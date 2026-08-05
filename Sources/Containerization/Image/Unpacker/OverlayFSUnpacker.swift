//===----------------------------------------------------------------------===//
// Copyright © 2025 Apple Inc. and the Containerization project authors.
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

#if os(macOS)

import Foundation
import ContainerizationOCI
import ContainerizationEXT4
import ContainerizationArchive
import ContainerizationError
import ContainerizationExtras
import SystemPackage
import Logging

/// Protocol for recording cached layer information
/// Allows external systems (like Arca's StateStore) to track layer usage
public protocol LayerCacheRecorder: Sendable {
    func recordLayer(digest: String, path: String, size: Int64) async throws
    func incrementLayerRefCount(digest: String) async throws
}

/// Unpacker that creates OverlayFS-compatible layer cache
///
/// Instead of unpacking all layers sequentially into a single EXT4 filesystem,
/// this unpacker:
/// 1. Unpacks each layer to its own isolated EXT4 filesystem in parallel
/// 2. Caches layers at ~/.arca/layers/{digest}/layer.ext4 for reuse
/// 3. Returns configuration for OverlayFS stacking in guest VM
///
/// Performance:
/// - First container: ~80s (parallel unpacking, 3 concurrent)
/// - Subsequent containers: <2s (all layers cached)
/// - Shared layers between images (nginx + apache share base debian)
///
/// Note: Does not conform to Unpacker protocol (returns OverlayFSConfig instead of Mount)
public struct OverlayFSUnpacker: Sendable {
    public let layerCachePath: URL
    private let recorder: (any LayerCacheRecorder)?
    private let logger = Logger(label: "com.arca.OverlayFSUnpacker")

    public init(layerCachePath: URL, recorder: (any LayerCacheRecorder)? = nil) {
        self.layerCachePath = layerCachePath
        self.recorder = recorder
    }

    /// Unpack image layers in parallel to cache directory
    ///
    /// - Parameters:
    ///   - image: The OCI image to unpack
    ///   - platform: The target platform (e.g., linux/arm64)
    ///   - containerPath: Path where container upper/work dirs will be created
    ///   - progress: Optional progress callback
    /// - Returns: OverlayFS configuration with layer mounts + upper/work dirs
    public func unpack(
        _ image: Image,
        for platform: Platform,
        at containerPath: URL,
        progress: ProgressHandler? = nil
    ) async throws -> OverlayFSConfig {
        let manifest = try await image.manifest(for: platform)

        logger.info("Starting parallel layer unpacking", metadata: [
            "image": "\(image.reference)",
            "layers": "\(manifest.layers.count)",
            "concurrency": "3"
        ])

        let startTime = Date()

        // Parallel unpack with concurrency limit (3 concurrent)
        let layerPaths = try await withThrowingTaskGroup(of: (Int, URL).self) { group in
            var collected: [(Int, URL)] = []
            collected.reserveCapacity(manifest.layers.count)

            for (index, layer) in manifest.layers.enumerated() {
                // Limit active tasks to 3
                if collected.count >= 3 {
                    if let result = try await group.next() {
                        collected.append(result)
                    }
                }

                group.addTask {
                    let path = try await self.unpackLayerToCache(
                        image: image,
                        layer: layer,
                        index: index,
                        totalLayers: manifest.layers.count,
                        progress: progress
                    )
                    return (index, path)
                }
            }

            // Collect remaining results
            for try await result in group {
                collected.append(result)
            }

            // Sort by index to maintain layer order (bottom to top)
            return collected.sorted { $0.0 < $1.0 }.map { $0.1 }
        }

        let unpackDuration = Date().timeIntervalSince(startTime)
        logger.info("Parallel unpacking complete", metadata: [
            "duration_seconds": "\(String(format: "%.2f", unpackDuration))",
            "layers": "\(layerPaths.count)"
        ])

        // Increment reference counts for all layers used by this container
        if let recorder = recorder {
            for layer in manifest.layers {
                try await recorder.incrementLayerRefCount(digest: layer.digest)
            }
            logger.debug("Layer reference counts incremented", metadata: [
                "layers": "\(manifest.layers.count)"
            ])
        }

        // Create upper and work directories for this container
        let upperDir = containerPath.appendingPathComponent("upper")
        let workDir = containerPath.appendingPathComponent("work")

        try FileManager.default.createDirectory(
            at: upperDir,
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: workDir,
            withIntermediateDirectories: true
        )

        logger.debug("Created container directories", metadata: [
            "upper": "\(upperDir.path)",
            "work": "\(workDir.path)"
        ])

        return OverlayFSConfig(
            lowerLayers: layerPaths,
            upperDir: upperDir,
            workDir: workDir
        )
    }

    /// Unpack a single layer to cache directory
    ///
    /// Checks cache first, unpacks if missing. Layers are cached at:
    /// ~/.arca/layers/{digest}/layer.ext4
    ///
    /// - Parameters:
    ///   - image: The OCI image
    ///   - layer: Layer descriptor (contains digest)
    ///   - index: Layer index (for logging)
    ///   - totalLayers: Total number of layers (for logging)
    ///   - progress: Optional progress callback
    /// - Returns: Path to cached layer.ext4 file
    private func unpackLayerToCache(
        image: Image,
        layer: Descriptor,
        index: Int,
        totalLayers: Int,
        progress: ProgressHandler?
    ) async throws -> URL {
        let cacheKey = layer.digest
        let layerDir = layerCachePath.appendingPathComponent(cacheKey)
        let layerPath = layerDir.appendingPathComponent("layer.ext4")

        // Check cache
        if FileManager.default.fileExists(atPath: layerPath.path) {
            logger.debug("Layer cache HIT", metadata: [
                "layer": "\(index + 1)/\(totalLayers)",
                "digest": "\(cacheKey.prefix(19))...",
                "path": "\(layerPath.path)"
            ])
            return layerPath
        }

        logger.info("Layer cache MISS - unpacking", metadata: [
            "layer": "\(index + 1)/\(totalLayers)",
            "digest": "\(cacheKey.prefix(19))..."
        ])

        let unpackStart = Date()

        // Create layer directory
        try FileManager.default.createDirectory(
            at: layerDir,
            withIntermediateDirectories: true
        )

        // Get layer content (compressed tar.gz)
        let content = try await image.getContent(digest: layer.digest)

        // Determine compression from media type
        let compression: ContainerizationArchive.Filter
        switch layer.mediaType {
        case MediaTypes.imageLayer, MediaTypes.dockerImageLayer:
            compression = .none
        case MediaTypes.imageLayerGzip, MediaTypes.dockerImageLayerGzip:
            compression = .gzip
        default:
            throw ContainerizationError(
                .unsupported,
                message: "Media type \(layer.mediaType) not supported"
            )
        }

        // Unpack to isolated EXT4 filesystem
        // 2GB should be enough for most layers; will auto-expand if needed
        let filesystem = try EXT4.Formatter(
            FilePath(layerPath.path),
            minDiskSize: 2 * 1024 * 1024 * 1024  // 2 GB
        )
        defer { try? filesystem.close() }

        // EXT4.Formatter.unpack became async upstream in the 2026-08 merge.
        try await filesystem.unpack(
            source: content.path,
            format: .paxRestricted,
            compression: compression,
            progress: progress
        )

        let unpackDuration = Date().timeIntervalSince(unpackStart)
        let layerSize = try FileManager.default.attributesOfItem(
            atPath: layerPath.path
        )[.size] as? Int64 ?? 0

        logger.info("Layer cached", metadata: [
            "layer": "\(index + 1)/\(totalLayers)",
            "digest": "\(cacheKey.prefix(19))...",
            "size_mb": "\(layerSize / 1024 / 1024)",
            "duration_seconds": "\(String(format: "%.2f", unpackDuration))",
            "path": "\(layerPath.path)"
        ])

        // Record layer in cache tracker (if provided)
        if let recorder = recorder {
            try await recorder.recordLayer(
                digest: cacheKey,
                path: layerPath.path,
                size: layerSize
            )
        }

        return layerPath
    }
}

/// Configuration for OverlayFS mount
///
/// Represents the data needed to mount an OverlayFS filesystem in the guest VM:
/// - lowerLayers: Read-only layer filesystems (ordered bottom to top)
/// - upperDir: Writable directory for container changes
/// - workDir: OverlayFS work directory (metadata)
public struct OverlayFSConfig: Sendable {
    /// Paths to layer.ext4 files (ordered bottom to top)
    public let lowerLayers: [URL]

    /// Writable upper directory for container changes
    public let upperDir: URL

    /// OverlayFS work directory (required by overlay mount)
    public let workDir: URL

    public init(lowerLayers: [URL], upperDir: URL, workDir: URL) {
        self.lowerLayers = lowerLayers
        self.upperDir = upperDir
        self.workDir = workDir
    }
}

#endif
