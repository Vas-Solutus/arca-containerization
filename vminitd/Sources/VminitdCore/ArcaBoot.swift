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

import Containerization
import ContainerizationEXT4
import ContainerizationOS
import Foundation
import Logging
import SystemPackage

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

    /// Every `/dev/vdX` node present, paired with the Arca role its ext4 volume label names.
    ///
    /// Devices carrying no role -- Apple's initfs, and every named-volume image, which vmexec
    /// mounts from the OCI spec at a destination the host chose -- are absent from the result.
    /// So is anything that is not an ext4 filesystem: a device with no ext4 superblock
    /// definitionally carries no ext4 volume label, and classifying it as "not ours" is
    /// reading the disk, not guessing about it. Any *other* failure to read a device is fatal,
    /// because a layer we cannot identify is a rootfs we would silently build wrong.
    private static func labelledBlockDevices(log: Logger) -> [(device: String, role: ArcaBlockDeviceRole)] {
        let entries: [String]
        do {
            entries = try FileManager.default.contentsOfDirectory(atPath: "/dev")
        } catch {
            log.error("failed to enumerate /dev: \(error)")
            exit(1)
        }

        // `vd` + exactly one letter of "a"..."z" is the whole of the virtio-blk namespace this
        // VM can produce: the host allocates tags from that alphabet and stops
        // (Character.blockDeviceTagAllocator). Excluding longer names also excludes partition
        // nodes such as vda1. Sorted, so single letters come back in the order the host
        // attached them.
        let devices =
            entries
            .filter { name in
                guard name.count == 3, name.hasPrefix("vd"), let letter = name.last else {
                    return false
                }
                return ("a"..."z").contains(letter)
            }
            .sorted()
            .map { "/dev/\($0)" }

        var classified: [(device: String, role: ArcaBlockDeviceRole)] = []
        for device in devices {
            let label: String?
            do {
                label = try EXT4.volumeLabel(ofBlockDevice: FilePath(device))
            } catch EXT4.Error.invalidSuperBlock {
                log.debug("\(device) holds no ext4 filesystem, not an Arca device")
                continue
            } catch {
                log.error("failed to read the ext4 superblock of \(device): \(error)")
                exit(1)
            }
            guard let label, let role = ArcaBlockDeviceRole(volumeLabel: label) else {
                log.info("\(device) label=\(label ?? "<none>") is not an Arca role, leaving it alone")
                continue
            }
            log.info("\(device) is \(role.rawValue)")
            classified.append((device, role))
        }
        return classified
    }

    /// Mounts the OverlayFS writable device and layer devices, and prepares the mount options.
    ///
    /// Devices are identified by the `ArcaBlockDeviceRole` in their ext4 volume label, never by
    /// position or count. The previous version scanned /dev/vdc upwards until a device was
    /// missing and called everything it found a layer, which silently swallowed the named
    /// volumes attached after the layers and mounted them read-only as lowerdirs.
    static func prepareOverlayFS(log: Logger) async {
        let classified = labelledBlockDevices(log: log)
        let writables = classified.filter { $0.role == .overlayWritable }.map(\.device)
        // Sorted by `labelledBlockDevices`, so this is the host's attach order, which is
        // bottom-to-top -- see OverlayFSMounter.buildMounts.
        let layers = classified.filter { $0.role == .overlayLayer }.map(\.device)

        guard !writables.isEmpty || !layers.isEmpty else {
            log.info("no OverlayFS block devices detected, using default rootfs")
            return
        }

        guard writables.count == 1 else {
            log.error("expected exactly one \(ArcaBlockDeviceRole.overlayWritable.rawValue) device, found \(writables)")
            exit(1)
        }
        let writable = writables[0]

        guard !layers.isEmpty else {
            log.info("\(writable) is present but no layer devices are, skipping OverlayFS")
            return
        }

        log.info("detected \(layers.count) OverlayFS layer block devices: \(layers.joined(separator: ", "))")

        // Create mount point and mount writable filesystem
        try? FileManager.default.createDirectory(atPath: "/mnt/writable", withIntermediateDirectories: true)
        guard Musl.mount(writable, "/mnt/writable", "ext4", 0, "") == 0 else {
            log.error("failed to mount writable filesystem \(writable) to /mnt/writable (errno: \(errno))")
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
