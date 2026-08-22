//===----------------------------------------------------------------------===//
// ARCA PATCH. The ext4 volume label (`s_volume_name`), read and written.
//
// Upstream leaves the field zeroed and offers no way to set or inspect it. Arca needs it
// because the guest has to tell one virtio-blk device from another, and the only thing that
// travels with a block image is the image itself. The label is the identity. The role
// vocabulary that used to be written into it was removed with this fork's revert to an
// upstream single composed rootfs; what stays here is the encoding, which is format-level
// and names no vocabulary of its own.
//
// This file owns the 16-byte encoding so that the formatter and the reader cannot disagree
// about it.
//===----------------------------------------------------------------------===//

import Foundation
import SystemPackage

extension EXT4 {
    /// Byte width of the ext4 superblock's `s_volume_name` field.
    ///
    /// Fixed by the on-disk format: 16 bytes at offset 0x78 within the superblock, which
    /// itself begins at byte 1024. A label is NUL-padded, and a full 16-byte label is not
    /// NUL-terminated.
    public static let VolumeLabelLength = 16
}

extension EXT4.SuperBlock {
    /// The filesystem's volume label, or `nil` when the field is unset.
    ///
    /// An all-zero field reads as `nil` rather than as the empty string: "no label" and "a
    /// label that happens to be empty" are the same state on disk, and callers branch on the
    /// former.
    public var volumeLabel: String? {
        let bytes = withUnsafeBytes(of: self.volumeName) { Array($0) }
        let significant = Array(bytes.prefix { $0 != 0 })
        guard !significant.isEmpty else {
            return nil
        }
        return String(decoding: significant, as: UTF8.self)
    }

    /// Sets the filesystem's volume label.
    ///
    /// Throws rather than truncating: a silently shortened label is a label that no longer
    /// matches what the reader looks for, which is the failure this whole mechanism exists to
    /// prevent.
    public mutating func setVolumeLabel(_ label: String) throws {
        var bytes = Array(label.utf8)
        guard bytes.count <= EXT4.VolumeLabelLength else {
            throw EXT4.Error.volumeLabelTooLong(label, bytes.count)
        }
        bytes.append(contentsOf: repeatElement(0, count: EXT4.VolumeLabelLength - bytes.count))
        withUnsafeMutableBytes(of: &self.volumeName) { field in
            field.copyBytes(from: bytes)
        }
    }

    /// Reads the superblock, and only the superblock, from an already-open handle.
    ///
    /// Extracted from `EXT4Reader.init` so the two paths cannot disagree; `path` is carried
    /// purely so the error names the device.
    static func read(from handle: FileHandle, at path: String) throws -> EXT4.SuperBlock {
        try handle.seek(toOffset: EXT4.SuperBlockOffset)
        let superBlockSize = MemoryLayout<EXT4.SuperBlock>.size
        guard let data = try? handle.read(upToCount: superBlockSize), data.count == superBlockSize else {
            throw EXT4.Error.couldNotReadSuperBlock(path, EXT4.SuperBlockOffset, superBlockSize)
        }
        let superBlock = data.withUnsafeBytes { bytes in
            bytes.loadLittleEndian(as: EXT4.SuperBlock.self)
        }
        guard superBlock.magic == EXT4.SuperBlockMagic else {
            throw EXT4.Error.invalidSuperBlock
        }
        return superBlock
    }
}

extension EXT4 {
    /// The volume label of the ext4 filesystem on `blockDevice`, or `nil` when it carries none.
    ///
    /// Reads the superblock and stops -- deliberately not `EXT4Reader`, which walks the whole
    /// directory tree on `init` and would read a multi-gigabyte layer to answer a 16-byte
    /// question. Throws `EXT4.Error.invalidSuperBlock` when the device holds no ext4
    /// filesystem at all, which callers classifying a mixed set of devices must distinguish
    /// from an unlabelled one.
    public static func volumeLabel(ofBlockDevice blockDevice: FilePath) throws -> String? {
        guard let handle = FileHandle(forReadingAtPath: blockDevice) else {
            throw EXT4.Error.notFound(blockDevice.description)
        }
        defer { try? handle.close() }
        return try EXT4.SuperBlock.read(from: handle, at: blockDevice.description).volumeLabel
    }
}
