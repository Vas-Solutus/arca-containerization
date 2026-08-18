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

    /// The lowerdir a zero-layer image contributes: nothing, in a form overlayfs will take.
    ///
    /// An image with no layers still needs a lower level, because an overlay is not a valid
    /// mount without one. An empty directory on the scratch tmpfs is that image's contents
    /// exactly, and it keeps one mounting path for every container rather than a second,
    /// rarely-taken one whose first exercise would be in production.
    private static let emptyLayerMountPoint = "/mnt/emptyimage"

    /// Mounts the OverlayFS writable device and layer devices, and prepares the mount options.
    ///
    /// Devices are identified by the `ArcaBlockDeviceRole` in their ext4 volume label, never by
    /// position or count. The previous version scanned /dev/vdc upwards until a device was
    /// missing and called everything it found a layer, which silently swallowed the named
    /// volumes attached after the layers and mounted them read-only as lowerdirs.
    ///
    /// `attachedOverlayLayers` is how many layer devices the host says it attached, and it is
    /// a cross-check on that classification, never a replacement for it: nothing below picks a
    /// device by counting. It is `nil` when no host reported one, which is refused rather than
    /// read as zero -- see `ArcaLayerAttachment`.
    static func prepareOverlayFS(log: Logger, attachedOverlayLayers: Int?) async {
        let classified = labelledBlockDevices(log: log)
        let writables = classified.filter { $0.role == .overlayWritable }.map(\.device)
        // Sorted by `labelledBlockDevices`, so this is the host's attach order, which is
        // bottom-to-top -- see OverlayFSMounter.buildMounts.
        let layers = classified.filter { $0.role == .overlayLayer }.map(\.device)

        guard !writables.isEmpty || !layers.isEmpty else {
            // ARCA PATCH. **This early return is the one branch the count did not guard, and
            // it is the branch whose outcome is the silent wrong rootfs.** Booting on here
            // runs the container on vminitd's OWN initfs -- `Start` succeeds, the container
            // runs, and nothing it was built from is present -- so it is the same outcome the
            // refusal below exists to prevent, reached before the refusal is reached.
            //
            // A non-nil count is by construction a disagreement here: a host that reports one
            // has attached a writable and N layer devices, and this guest classified NONE of
            // them. `attached == 0` is included for that reason and not by oversight -- the
            // writable is still missing. A `writable.ext4` that predates the role label is the
            // known route: `ContainerManager` formats the writable only when the file is
            // absent, so an existing one is reused unlabelled and never self-heals, unlike a
            // layer cache entry, which `OverlayFSUnpacker.unpackLayerToCache` reformats.
            //
            // `nil` still returns, and must: it is the only honest "no Arca overlay at all".
            // Upstream's single-image boot reports nothing, and so does a pod VM (`LinuxPod`),
            // which attaches no Arca overlay devices either. Neither is affected by this.
            if let attachedOverlayLayers {
                log.error(
                    """
                    the host reported \(attachedOverlayLayers) attached OverlayFS layer \
                    device(s) and this guest classified no Arca block devices at all, not even \
                    a writable: booting here would run the container on vminitd's own initfs
                    """
                )
                exit(1)
            }
            log.info("no OverlayFS block devices detected, using default rootfs")
            return
        }

        guard writables.count == 1 else {
            log.error("expected exactly one \(ArcaBlockDeviceRole.overlayWritable.rawValue) device, found \(writables)")
            exit(1)
        }
        let writable = writables[0]

        // A writable overlay with nothing under it used to be two situations wearing one
        // observation, and this guard used to refuse both of them.
        //
        // An image that genuinely has no layers -- `FROM scratch`, an OCI artifact; nothing
        // refuses a zero-layer manifest -- produces exactly the same devices as an image whose
        // layers WERE attached and which this guest could not identify. The first deserves an
        // empty rootfs and the second must not boot at all, and no amount of looking at the
        // devices present can separate them, because what distinguishes them is a device that
        // is absent in one case and unrecognised in the other.
        //
        // The host now says how many it attached, so the two are different arithmetic:
        // `0 == 0` is the empty image and `N > identified` is the failure. The refusal names
        // both numbers, which is the diagnostic the single-number message could not produce.
        // Booting anyway would run the container on the bare initfs -- `Start` succeeds, the
        // container runs, and nothing it was built from is present.
        //
        // One known route to a disagreement remains, and it is not the one Task 6 closed at
        // unpack time: a layer cache written before the role label existed. The host validates
        // cache entries and reformats whatever carries no label
        // (`OverlayFSUnpacker.unpackLayerToCache`); this stands on its own regardless, because
        // the failure it catches is silent and a wrong rootfs is worse than a refusal to boot.
        //
        // A count that never arrived is `nil` and is refused too, rather than read as zero:
        // "the host attached none" and "no host said anything" are different claims, and only
        // the first describes an empty image. A pod VM (`LinuxPod`) reports no count because
        // one number cannot describe several containers' images -- it also attaches no Arca
        // overlay devices, so it returns above and never reaches here.
        let attachment = ArcaLayerAttachment.resolve(attached: attachedOverlayLayers, identified: layers.count)
        if let refusal = attachment.refusal {
            log.error("\(writable) is present but \(refusal)")
            exit(1)
        }

        // Past the refusal both numbers are equal, so one of them says everything.
        if layers.isEmpty {
            log.info("the host attached no OverlayFS layer devices and this guest identified none: an empty image")
        } else {
            log.info(
                """
                the host attached \(layers.count) OverlayFS layer block devices and this guest \
                identified all of them: \(layers.joined(separator: ", "))
                """
            )
        }

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

        // An image with no layers contributes an empty directory, because an overlay with no
        // lowerdir at all is not a mount the kernel accepts and `lowerdir=` would fail at the
        // rootfs mount RPC, long after the decision that produced it.
        if lowerDirs.isEmpty {
            do {
                try FileManager.default.createDirectory(
                    atPath: Self.emptyLayerMountPoint,
                    withIntermediateDirectories: true
                )
            } catch {
                log.error("failed to create \(Self.emptyLayerMountPoint) for an image with no layers: \(error)")
                exit(1)
            }
            lowerDirs.append(Self.emptyLayerMountPoint)
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
