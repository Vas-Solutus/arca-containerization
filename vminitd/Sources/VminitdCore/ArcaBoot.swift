//===----------------------------------------------------------------------===//
// Arca-specific vminitd boot steps.
//
// ARCA PATCH. Upstream restructured vminitd during the 2026-08 merge: the old
// Application.run() body moved into AgentCommand.bootstrap(), and Application.swift became
// a thin subcommand shell. The Arca additions that lived in that body are collected here
// rather than inlined into AgentCommand.swift, so the fork's delta against upstream stays a
// two-line call site instead of ~200 interleaved lines. Roadmap P8.2 wants exactly this
// shape when a modification cannot be upstreamed.
//
// Dropped during that move: `waitForVsockService(port:serviceName:timeout:log:)`, which had
// no call site in the fork. Readiness is handled host-side instead, by the daemon waiting on
// vsock port 51819 after container.start().
//===----------------------------------------------------------------------===//

#if os(Linux)

import ContainerizationOS
import Foundation
import Logging

#if canImport(Musl)
import Musl
#elseif canImport(Glibc)
import Glibc
#endif

/// OverlayFS mount options discovered at boot, consumed later over gRPC.
///
/// The layers are deliberately NOT mounted at `/` during boot. They are mounted directly at
/// `/run/container/{id}/rootfs` when requested, which avoids the read-only bind mount
/// problem. `Server+GRPC` reads `mountOptions` at that point.
///
/// Distinct from the `OverlayFSConfig` struct in the `Containerization` module, which is an
/// unrelated host-side type that happens to share the name.
actor OverlayFSConfig {
    static let shared = OverlayFSConfig()
    private(set) var mountOptions: String?

    func setMountOptions(_ options: String) {
        self.mountOptions = options
    }
}

enum ArcaBoot {
    /// Mounts the tmpfs that the OverlayFS layer mount points live under.
    static func mountScratch(log: Logger) {
        guard Musl.mount("tmpfs", "/mnt", "tmpfs", 0, "") == 0 else {
            log.error("failed to mount /mnt")
            exit(1)
        }
    }

    /// Starts the unified arca-services guest binary.
    ///
    /// Services listen on:
    ///   - vsock:51820 — WireGuard network API (with integrated DNS)
    ///   - vsock:51821 — Filesystem operations API
    ///   - vsock:51822 — Process control API
    ///   - vsock:51819 — Ready signal (opens ONLY after all services are fully ready)
    ///
    /// Deliberately does not wait: the host daemon waits for the ready signal after
    /// container.start(), so the vminitd API can come up immediately and the
    /// containerization framework does not time out.
    static func startServices(log: Logger) {
        let arcaServicesPath = "/sbin/arca-services"
        let arcaServicesExists = FileManager.default.fileExists(atPath: arcaServicesPath)
        log.info("arca-services binary exists: \(arcaServicesExists) at \(arcaServicesPath)")

        guard arcaServicesExists else {
            log.warning(
                "arca-services binary not found at \(arcaServicesPath), container networking/filesystem/process services will not be available"
            )
            return
        }

        log.info("starting arca-services (unified wireguard, filesystem, process services)...")
        var arcaServices = Command(arcaServicesPath)
        arcaServices.stdin = nil
        arcaServices.stdout = nil
        arcaServices.stderr = .standardError  // Log errors to vminitd stderr
        do {
            try arcaServices.start()
            log.info("arca-services started (daemon will wait for ready signal on port 51819)")
        } catch {
            log.error("failed to start arca-services: \(error)")
        }
    }

    /// Auto-detects OverlayFS layer block devices and prepares the mount options.
    ///
    /// Not hardcoded: this only runs if /dev/vdb exists, which indicates OverlayFS layers.
    static func prepareOverlayFS(log: Logger) async {
        guard FileManager.default.fileExists(atPath: "/dev/vdb") else {
            log.info("no OverlayFS block devices detected, using default rootfs")
            return
        }

        log.info("detected writable block device at /dev/vdb, checking for OverlayFS layers...")

        // Detect all layer block devices (vdc, vdd, vde, ...)
        var layers: [String] = []
        let deviceLetters = "cdefghijklmnopqrstuvwxyz"
        for letter in deviceLetters {
            let device = "/dev/vd\(letter)"
            if FileManager.default.fileExists(atPath: device) {
                layers.append(device)
            } else {
                break  // Stop at first missing device
            }
        }

        guard !layers.isEmpty else {
            log.info("no layer block devices detected (vdc exists but no vdd+), skipping OverlayFS")
            return
        }

        log.info("detected \(layers.count) OverlayFS layer block devices")

        // Create mount point and mount writable filesystem
        try? FileManager.default.createDirectory(atPath: "/mnt/writable", withIntermediateDirectories: true)
        guard Musl.mount("/dev/vdb", "/mnt/writable", "ext4", 0, "") == 0 else {
            log.error("failed to mount writable filesystem /dev/vdb to /mnt/writable (errno: \(errno))")
            exit(1)
        }

        // Mount each read-only layer
        var lowerDirs: [String] = []
        for (i, dev) in layers.enumerated() {
            let mnt = "/mnt/layer\(i)"
            try? FileManager.default.createDirectory(atPath: mnt, withIntermediateDirectories: true)
            guard Musl.mount(dev, mnt, "ext4", 1, "") == 0 else {  // 1 = MS_RDONLY
                log.error("failed to mount \(dev) to \(mnt)")
                exit(1)
            }
            lowerDirs.append(mnt)
        }

        // Create upper and work directories
        do {
            try FileManager.default.createDirectory(atPath: "/mnt/writable/upper", withIntermediateDirectories: true)
            try FileManager.default.createDirectory(atPath: "/mnt/writable/work", withIntermediateDirectories: true)
            log.info("created OverlayFS upper and work directories")
        } catch {
            log.error("failed to create OverlayFS directories: \(error)")
            exit(1)
        }

        // Save OverlayFS mount options for later use (mounted at the container rootfs path
        // via gRPC, not at / during boot).
        let opts =
            "lowerdir=\(lowerDirs.reversed().joined(separator: ":")),upperdir=/mnt/writable/upper,workdir=/mnt/writable/work"
        await OverlayFSConfig.shared.setMountOptions(opts)

        log.info("OverlayFS layers detected and prepared - will mount at container rootfs path (not at /)")
    }
}

#endif
