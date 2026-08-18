//===----------------------------------------------------------------------===//
// Copyright © 2026 Apple Inc. and the Containerization project authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//===----------------------------------------------------------------------===//

import CArchive
import ContainerizationError
import ContainerizationOS
import Foundation
import SystemPackage

/// A protocol for reading data in chunks, compatible with both `InputStream` and zero-allocation archive readers.
public protocol ReadableStream {
    /// Reads up to `maxLength` bytes into the provided buffer.
    /// Returns the number of bytes actually read, 0 for EOF, or -1 for error.
    func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength: Int) -> Int
}

extension InputStream: ReadableStream {}

/// Small wrapper type to read data from an archive entry.
public struct ArchiveEntryReader: ReadableStream {
    private weak var reader: ArchiveReader?

    init(reader: ArchiveReader) {
        self.reader = reader
    }

    /// Reads up to `maxLength` bytes into the provided buffer.
    /// Returns the number of bytes actually read, 0 for EOF, or -1 for error.
    public func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength: Int) -> Int {
        guard let archive = reader?.underlying else { return -1 }
        let bytesRead = archive_read_data(archive, buffer, maxLength)
        return bytesRead < 0 ? -1 : bytesRead
    }
}

/// A class responsible for reading entries from an archive file.
public final class ArchiveReader {
    private static let chunkSize = 4 * 1024 * 1024

    /// A pointer to the underlying `archive` C structure.
    var underlying: OpaquePointer?
    /// The file handle associated with the archive file being read.
    let fileHandle: FileHandle?
    /// Temporary decompressed file URL if the input was zstd-compressed
    private var tempDecompressedFile: URL?

    /// The format the caller declared the archive to be in, or `nil` when this
    /// reader was asked to detect the format itself.
    public private(set) var declaredFormat: Format?
    /// The filter the caller declared the archive to be encoded with, or `nil`
    /// when this reader was asked to detect the filter itself.
    public private(set) var declaredFilter: Filter?

    /// The libarchive failure that ended the most recent iteration, if it ended
    /// in a failure rather than at the end of the archive.
    ///
    /// `IteratorProtocol.next()` cannot throw, so an iterator has exactly one way
    /// to stop and it means "no more entries" whether the archive ended or the
    /// read failed. Recording the failure here is what lets a consumer tell the
    /// two apart once its loop is over; it must check.
    public private(set) var iterationFailure: ArchiveError?

    /// The number of bytes the format handler has consumed, counted at the end of
    /// the filter chain and therefore *after* any decompression.
    ///
    /// A declared filter that cannot decode the source produces an empty stream
    /// rather than an error, which the format handler reports as a clean end of
    /// file. No archive of any format is zero bytes long, so a completed
    /// iteration leaving this at zero means the bytes are not what they were
    /// declared to be.
    public var decodedByteCount: Int64 {
        archive_filter_bytes(underlying, 0)
    }

    /// What the caller declared this archive to be, for naming both sides of a
    /// disagreement between a declaration and the bytes.
    public var declaration: String {
        guard let declaredFormat, let declaredFilter else {
            return "an archive of self-detected format and filter"
        }
        return "a \(declaredFormat.rawValue) archive with filter \(declaredFilter.rawValue)"
    }

    /// The error libarchive is reporting for a header read that failed, for the
    /// two callers that need it: one records it, one throws it.
    fileprivate func headerReadFailure(_ result: CInt) -> ArchiveError {
        let message = archive_error_string(underlying).map(String.init(cString:)) ?? "no error reported"
        return .failedToExtractArchive(
            "reading the next archive header failed with code \(result): \(message)")
    }

    fileprivate func recordIterationFailure(_ result: CInt) {
        iterationFailure = headerReadFailure(result)
    }

    fileprivate func clearIterationFailure() {
        iterationFailure = nil
    }

    /// Initializes an `ArchiveReader` to read from a specified file URL with an explicit `Format` and `Filter`.
    /// Note: This method must be used when it is known that the archive at the specified URL follows the specified
    /// `Format` and `Filter`.
    public convenience init(format: Format, filter: Filter, file: URL) throws {
        // If filter is zstd, decompress it and use filter .none
        let fileToRead: URL
        let tempFile: URL?
        let actualFilter: Filter

        if filter == .zstd {
            let decompressed = try Self.decompressZstd(file)
            tempFile = decompressed
            fileToRead = decompressed
            actualFilter = .none
        } else {
            tempFile = nil
            fileToRead = file
            actualFilter = filter
        }

        do {
            let fileHandle = try FileHandle(forReadingFrom: fileToRead)
            try self.init(format: format, filter: actualFilter, fileHandle: fileHandle)
        } catch {
            if let tempFile {
                try? FileManager.default.removeItem(at: tempFile.deletingLastPathComponent())
            }
            throw error
        }
        self.tempDecompressedFile = tempFile
        // The designated initializer saw the substituted filter, not the one the
        // caller declared; the declaration is what an error has to name.
        self.declaredFilter = filter
    }

    /// Initializes an `ArchiveReader` to read from the provided file descriptor with an explicit `Format` and `Filter`.
    /// Note: This method must be used when it is known that the archive pointed to by the file descriptor follows the specified
    /// `Format` and `Filter`.
    public init(format: Format, filter: Filter, fileHandle: FileHandle) throws {
        self.underlying = archive_read_new()
        self.fileHandle = fileHandle
        self.declaredFormat = format
        self.declaredFilter = filter

        try archive_read_set_format(underlying, format.code)
            .checkOk(elseThrow: .unableToSetFormat(format.code, format))
        try archive_read_append_filter(underlying, filter.code)
            .checkOk(elseThrow: .unableToAddFilter(filter.code, filter))

        let fd = fileHandle.fileDescriptor
        try archive_read_open_fd(underlying, fd, 4096)
            .checkOk(elseThrow: { .unableToOpenArchive($0) })
    }

    /// Initialize the `ArchiveReader` to read from a specified file URL
    /// by trying to auto determine the archives `Format` and `Filter`.
    public init(file: URL) throws {
        self.underlying = archive_read_new()

        // Try to decompress as zstd first, fall back to original if it fails
        let fileToRead: URL
        if let decompressed = try? Self.decompressZstd(file) {
            self.tempDecompressedFile = decompressed
            fileToRead = decompressed
        } else {
            fileToRead = file
        }

        let fileHandle = try FileHandle(forReadingFrom: fileToRead)
        self.fileHandle = fileHandle
        try archive_read_support_filter_all(underlying)
            .checkOk(elseThrow: .failedToDetectFilter)
        try archive_read_support_format_all(underlying)
            .checkOk(elseThrow: .failedToDetectFormat)
        let fd = fileHandle.fileDescriptor
        try archive_read_open_fd(underlying, fd, 4096)
            .checkOk(elseThrow: { .unableToOpenArchive($0) })
    }

    /// Decompress a zstd file to a temporary location
    public static func decompressZstd(_ source: URL) throws -> URL {
        guard let tempDir = createTemporaryDirectory(baseName: "zstd-decompress") else {
            throw ArchiveError.failedToDetectFormat
        }
        let tempFile = tempDir.appendingPathComponent(
            source.deletingPathExtension().lastPathComponent
        )

        do {
            let srcPath = source.path
            let srcFd = open(srcPath, O_RDONLY)
            guard srcFd >= 0 else { throw ArchiveError.failedToDetectFormat }
            defer { close(srcFd) }

            let dstFd = open(tempFile.path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
            guard dstFd >= 0 else { throw ArchiveError.failedToDetectFormat }
            defer { close(dstFd) }

            guard zstd_decompress_fd(srcFd, dstFd) == 0 else {
                throw ArchiveError.failedToDetectFormat
            }
        } catch {
            try? FileManager.default.removeItem(at: tempDir)
            throw error
        }
        return tempFile
    }

    /// Clean up the temporary directory created by `decompressZstd`.
    /// The decompressed file is placed inside a unique temporary directory,
    /// so removing that directory cleans up everything.
    public static func cleanUpDecompressedZstd(_ file: URL) {
        try? FileManager.default.removeItem(at: file.deletingLastPathComponent())
    }

    deinit {
        archive_read_free(underlying)
        try? fileHandle?.close()

        if let tempFile = tempDecompressedFile {
            Self.cleanUpDecompressedZstd(tempFile)
        }
    }
}

extension CInt {
    fileprivate func checkOk(elseThrow error: @autoclosure () -> ArchiveError) throws {
        guard self == ARCHIVE_OK else { throw error() }
    }
    fileprivate func checkOk(elseThrow error: (CInt) -> ArchiveError) throws {
        guard self == ARCHIVE_OK else { throw error(self) }
    }

    /// Whether a result from `archive_read_next_header2` left a usable entry
    /// behind. `ARCHIVE_WARN` does — libarchive uses it for problems it recovered
    /// from, such as a pax extended-attribute record it could not parse — so
    /// warnings must keep an otherwise sound archive readable. Everything below it
    /// does not. `ArchiveReaderMistypedBlobTests.aWarnedButUsableHeaderIsStillAnEntry`
    /// is the guard on the distinction.
    fileprivate var isReadableHeader: Bool {
        self == ARCHIVE_OK || self == ARCHIVE_WARN
    }
}

extension ArchiveReader: Sequence {
    public func makeIterator() -> Iterator {
        clearIterationFailure()
        return Iterator(reader: self)
    }

    public struct Iterator: IteratorProtocol {
        var reader: ArchiveReader

        public mutating func next() -> (WriteEntry, Data)? {
            let entry = WriteEntry()
            let result = archive_read_next_header2(reader.underlying, entry.underlying)
            if result == ARCHIVE_EOF {
                return nil
            }
            guard result.isReadableHeader else {
                reader.recordIterationFailure(result)
                return nil
            }
            let data = reader.readDataForEntry(entry)
            return (entry, data)
        }
    }

    /// Returns an iterator that yields archive entries.
    public func makeStreamingIterator() -> StreamingIterator {
        clearIterationFailure()
        return StreamingIterator(reader: self)
    }

    public struct StreamingIterator: Sequence, IteratorProtocol {
        var reader: ArchiveReader

        public func makeIterator() -> StreamingIterator {
            self
        }

        public mutating func next() -> (WriteEntry, ArchiveEntryReader)? {
            let entry = WriteEntry()
            let result = archive_read_next_header2(reader.underlying, entry.underlying)
            if result == ARCHIVE_EOF {
                return nil
            }
            guard result.isReadableHeader else {
                reader.recordIterationFailure(result)
                return nil
            }
            let streamReader = ArchiveEntryReader(reader: reader)
            return (entry, streamReader)
        }
    }

    internal func readDataForEntry(_ entry: WriteEntry) -> Data {
        let bufferSize = Int(Swift.min(entry.size ?? 4096, 4096))
        var entry = Data()
        var part = Data(count: bufferSize)
        while true {
            let c = part.withUnsafeMutableBytes { buffer in
                guard let baseAddress = buffer.baseAddress else {
                    return 0
                }
                return archive_read_data(self.underlying, baseAddress, buffer.count)
            }
            guard c > 0 else { break }
            part.count = c
            entry.append(part)
        }
        return entry
    }
}

extension ArchiveReader {
    public convenience init(name: String, bundle: Data, tempDirectoryBaseName: String? = nil) throws {
        let baseName = tempDirectoryBaseName ?? "Unarchiver"
        guard let tempDir = createTemporaryDirectory(baseName: baseName) else {
            throw ArchiveError.failedToExtractArchive("failed to create temporary directory")
        }
        let url = tempDir.appendingPathComponent(name)
        do {
            try bundle.write(to: url, options: .atomic)
            try self.init(format: .zip, filter: .none, file: url)
        } catch {
            try? FileManager.default.removeItem(at: tempDir)
            throw error
        }
        // Register for cleanup in deinit (only needed when the zstd path didn't already set it)
        if self.tempDecompressedFile == nil {
            self.tempDecompressedFile = url
        }
    }

    /// Extracts the contents of an archive to the provided directory.
    /// Rejects member paths that escape the root directory or traverse
    /// symbolic links, and uses a "last entry wins" replacement policy
    /// for an existing file at a path to be extracted.
    public func extractContents(to directory: URL) throws -> [String] {
        // Create the root directory with standard permissions
        // and create a FileDescriptor for secure path traversal.
        let fm = FileManager.default
        let rootFilePath = FilePath(directory.path)
        try fm.createDirectory(atPath: directory.path, withIntermediateDirectories: true)
        let rootFileDescriptor = try FileDescriptor.open(rootFilePath, .readOnly)
        defer { try? rootFileDescriptor.close() }

        // Iterate and extract archive entries, collecting rejected paths.
        var foundEntry = false
        var rejectedPaths = [String]()
        for (entry, dataReader) in self.makeStreamingIterator() {
            guard let memberPath = (entry.path.map { FilePath($0) }) else {
                continue
            }
            foundEntry = true

            // Try to extract the entry, catching path validation errors
            let extracted = try extractEntry(
                entry: entry,
                dataReader: dataReader,
                memberPath: memberPath,
                rootFileDescriptor: rootFileDescriptor
            )

            if !extracted {
                rejectedPaths.append(memberPath.string)
            }
        }
        if let iterationFailure {
            throw iterationFailure
        }
        guard foundEntry else {
            throw ArchiveError.failedToExtractArchive("no entries found in archive")
        }

        return rejectedPaths
    }

    /// This method extracts a given file from the archive.
    /// This operation modifies the underlying file descriptor's position within the archive,
    /// meaning subsequent reads will start from a new location.
    /// To reset the underlying file descriptor to the beginning of the archive, close and
    /// reopen the archive.
    ///
    /// A read that fails is thrown rather than searched past: `ARCHIVE_FATAL` does
    /// not advance the stream, so `while … != ARCHIVE_EOF` would never end, and a
    /// milder failure would end in "not found in archive" for a file the archive
    /// may well contain.
    public func extractFile(path: String) throws -> (WriteEntry, Data) {
        let entry = WriteEntry()
        while true {
            let result = archive_read_next_header2(self.underlying, entry.underlying)
            if result == ARCHIVE_EOF {
                break
            }
            guard result.isReadableHeader else {
                throw headerReadFailure(result)
            }
            guard let entryPath = entry.path else { continue }
            let trimCharSet = CharacterSet(charactersIn: "./")
            let trimmedEntry = entryPath.trimmingCharacters(in: trimCharSet)
            let trimmedRequired = path.trimmingCharacters(in: trimCharSet)
            guard trimmedEntry == trimmedRequired else { continue }
            let data = readDataForEntry(entry)
            return (entry, data)
        }
        throw ArchiveError.failedToExtractArchive(" \(path) not found in archive")
    }

    /// Extracts a single archive entry.
    /// Returns false if the entry was rejected due to path validation errors.
    /// Throws on system errors.
    private func extractEntry(
        entry: WriteEntry,
        dataReader: ArchiveEntryReader,
        memberPath: FilePath,
        rootFileDescriptor: FileDescriptor
    ) throws -> Bool {
        guard let lastComponent = memberPath.lastComponent else {
            return false
        }
        let relativePath = memberPath.removingLastComponent()
        let type = entry.fileType

        do {
            switch type {
            case .regular:
                try FileDescriptorOps.mkdir(rootFileDescriptor, relativePath, makeIntermediates: true) { fd in
                    // Remove existing entry if present (mimics containerd's "last entry wins" behavior)
                    try? FileDescriptorOps.unlinkRecursive(fd, filename: lastComponent)

                    // Open file for writing using openat with O_NOFOLLOW to prevent TOC-TOU attacks
                    let fileMode = entry.permissions & 0o777  // Mask to permission bits only
                    let fileFd = openat(fd.rawValue, lastComponent.string, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, fileMode)
                    guard fileFd >= 0 else {
                        throw ArchiveError.failedToExtractArchive("failed to create file: \(memberPath)")
                    }
                    defer { close(fileFd) }

                    try Self.copyDataReaderToFd(dataReader: dataReader, fileFd: fileFd, memberPath: memberPath)
                    setFileAttributes(fd: fileFd, entry: entry)
                }
            case .directory:
                try FileDescriptorOps.mkdir(rootFileDescriptor, memberPath, makeIntermediates: true) { fd in
                    setFileAttributes(fd: fd.rawValue, entry: entry)
                }
            case .symbolicLink:
                guard let targetPath = (entry.symlinkTarget.map { FilePath($0) }) else {
                    return false
                }
                var symlinkCreated = false
                try FileDescriptorOps.mkdir(rootFileDescriptor, relativePath, makeIntermediates: true) { fd in
                    // Remove existing entry if present (mimics containerd's "last entry wins" behavior)
                    try? FileDescriptorOps.unlinkRecursive(fd, filename: lastComponent)

                    guard symlinkat(targetPath.string, fd.rawValue, lastComponent.string) == 0 else {
                        throw ArchiveError.failedToExtractArchive("failed to create symlink: \(targetPath) <- \(memberPath)")
                    }
                    symlinkCreated = true
                }
                return symlinkCreated
            default:
                return false
            }

            return true
        } catch let error as FileDescriptorOps.Error {
            // Just reject path validation errors, don't fail the extraction
            switch error {
            case .systemError:
                // Fail for system errors
                throw error
            case .invalidRelativePath, .invalidPathComponent, .cannotFollowSymlink:
                return false
            }
        }
    }

    private func setFileAttributes(fd: Int32, entry: WriteEntry) {
        fchmod(fd, entry.permissions & 0o777)
        if let owner = entry.owner, let group = entry.group {
            fchown(fd, owner, group)
        }
    }

    private static func copyDataReaderToFd(dataReader: ArchiveEntryReader, fileFd: Int32, memberPath: FilePath) throws {
        var buffer = [UInt8](repeating: 0, count: ArchiveReader.chunkSize)
        while true {
            let bytesRead = buffer.withUnsafeMutableBufferPointer { bufferPtr in
                guard let baseAddress = bufferPtr.baseAddress else { return 0 }
                return dataReader.read(baseAddress, maxLength: bufferPtr.count)
            }

            if bytesRead < 0 {
                throw ArchiveError.failedToExtractArchive("failed to read data for: \(memberPath)")
            }
            if bytesRead == 0 {
                break  // EOF
            }

            let bytesWritten = write(fileFd, buffer, bytesRead)
            guard bytesWritten == bytesRead else {
                throw ArchiveError.failedToExtractArchive("failed to write data for: \(memberPath)")
            }
        }
    }
}
