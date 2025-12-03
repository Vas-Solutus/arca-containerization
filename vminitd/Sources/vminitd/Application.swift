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

import Cgroup
import Containerization
import ContainerizationError
import ContainerizationOS
import Foundation
import Logging
import NIOCore
import NIOPosix

#if os(Linux)
import Musl
import LCShim
#endif

// Global OverlayFS configuration for remounting at container rootfs paths
actor OverlayFSConfig {
    static let shared = OverlayFSConfig()
    private(set) var mountOptions: String?

    func setMountOptions(_ options: String) {
        self.mountOptions = options
    }
}

/// Wait for a vsock service to become ready by attempting connections
/// This prevents race conditions where container processes start before services are listening
private func waitForVsockService(
    port: UInt32,
    serviceName: String,
    timeout: TimeInterval = 5.0,
    log: Logger
) async throws {
    let startTime = Date()
    var lastError: Error?

    while Date().timeIntervalSince(startTime) < timeout {
        do {
            let type = VsockType(port: port, cid: VsockType.localCID)
            let socket = try Socket(type: type, closeOnDeinit: true)
            try socket.setTimeout(option: .send, seconds: 1)
            try socket.setTimeout(option: .receive, seconds: 1)
            try socket.connect()
            try socket.close()
            log.info("\(serviceName) is ready on vsock port \(port)")
            return
        } catch {
            lastError = error
            try? await Task.sleep(nanoseconds: 50_000_000) // 50ms
        }
    }

    log.error("\(serviceName) failed to become ready within \(timeout)s", metadata: [
        "port": "\(port)",
        "error": "\(lastError?.localizedDescription ?? "unknown")"
    ])
    throw ContainerizationError(
        .timeout,
        message: "\(serviceName) not ready on port \(port)"
    )
}

@main
struct Application {
    private static let foregroundEnvVar = "FOREGROUND"
    private static let vsockPort = 1024
    private static let standardErrorLock = NSLock()

    private static func runInForeground(_ log: Logger) throws {
        log.info("running vminitd under pid1")

        var command = Command("/sbin/vminitd")
        command.attrs = .init(setsid: true)
        command.stdin = .standardInput
        command.stdout = .standardOutput
        command.stderr = .standardError
        command.environment = ["\(foregroundEnvVar)=1"]

        try command.start()
        _ = try command.wait()
    }

    private static func adjustLimits() throws {
        var limits = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &limits) == 0 else {
            throw POSIXError(.init(rawValue: errno)!)
        }
        limits.rlim_cur = 65536
        limits.rlim_max = 65536
        guard setrlimit(RLIMIT_NOFILE, &limits) == 0 else {
            throw POSIXError(.init(rawValue: errno)!)
        }
    }

    @Sendable
    private static func standardError(label: String) -> StreamLogHandler {
        standardErrorLock.withLock {
            StreamLogHandler.standardError(label: label)
        }
    }

    static func main() async throws {
        LoggingSystem.bootstrap(standardError)
        var log = Logger(label: "vminitd")

        try adjustLimits()

        // when running under debug mode, launch vminitd as a sub process of pid1
        // so that we get a chance to collect better logs and errors before pid1 exists
        // and the kernel panics.
        #if DEBUG
        let environment = ProcessInfo.processInfo.environment
        let foreground = environment[Self.foregroundEnvVar]
        log.info("checking for shim var \(foregroundEnvVar)=\(String(describing: foreground))")

        if foreground == nil {
            try runInForeground(log)
            exit(0)
        }

        // since we are not running as pid1 in this mode we must set ourselves
        // as a subpreaper so that all child processes are reaped by us and not
        // passed onto our parent.
        CZ_set_sub_reaper()
        #endif

        log.logLevel = .debug

        signal(SIGPIPE, SIG_IGN)

        log.info("vminitd booting")

        // Set of mounts necessary to be mounted prior to taking any RPCs.
        // 1. /proc as the sysctl rpc wouldn't make sense if it wasn't there.
        // 2. /run as that is where we store container state.
        // 3. /sys as we need it for /sys/fs/cgroup
        // 4. /sys/fs/cgroup to add the agent to a cgroup, as well as containers later.
        let mounts = [
            ContainerizationOS.Mount(
                type: "proc",
                source: "proc",
                target: "/proc",
                options: []
            ),
            ContainerizationOS.Mount(
                type: "tmpfs",
                source: "tmpfs",
                target: "/run",
                options: []
            ),
            ContainerizationOS.Mount(
                type: "sysfs",
                source: "sysfs",
                target: "/sys",
                options: []
            ),
            ContainerizationOS.Mount(
                type: "cgroup2",
                source: "none",
                target: "/sys/fs/cgroup",
                options: []
            ),
        ]

        for mnt in mounts {
            log.info("mounting \(mnt.target)")

            try mnt.mount(createWithPerms: 0o755)
        }
        guard Musl.mount("tmpfs", "/mnt", "tmpfs", 0, "") == 0 else {
            log.error("failed to mount /mnt")
            exit(1)
        }
        try Binfmt.mount()

        let cgManager = Cgroup2Manager(
            group: URL(filePath: "/vminitd"),
            logger: log
        )
        try cgManager.create()
        try cgManager.toggleAllAvailableControllers(enable: true)

        // Set memory.high threshold to 75 MiB
        let threshold: UInt64 = 75 * 1024 * 1024
        try cgManager.setMemoryHigh(bytes: threshold)
        try cgManager.addProcess(pid: getpid())

        let memoryMonitor = try MemoryMonitor(
            cgroupManager: cgManager,
            threshold: threshold,
            logger: log
        ) { [log] (currentUsage, highMark) in
            log.warning(
                "vminitd memory threshold exceeded",
                metadata: [
                    "threshold_bytes": "\(threshold)",
                    "current_bytes": "\(currentUsage)",
                    "high_events_total": "\(highMark)",
                ])
        }

        let t = Thread { [log] in
            do {
                try memoryMonitor.run()
            } catch {
                log.error("memory monitor failed: \(error)")
            }
        }
        t.start()

        // Start unified arca-services binary
        // This starts all container extension services (wireguard, filesystem, process) as goroutines
        // Services listen on:
        //   - vsock:51820 - WireGuard network API (with integrated DNS)
        //   - vsock:51821 - Filesystem operations API
        //   - vsock:51822 - Process control API
        //   - vsock:51819 - Ready signal (opens ONLY after all services are fully ready)
        let arcaServicesPath = "/sbin/arca-services"
        let arcaServicesExists = FileManager.default.fileExists(atPath: arcaServicesPath)
        log.info("arca-services binary exists: \(arcaServicesExists) at \(arcaServicesPath)")

        if arcaServicesExists {
            log.info("starting arca-services (unified wireguard, filesystem, process services)...")
            var arcaServices = Command(arcaServicesPath)
            arcaServices.stdin = nil
            arcaServices.stdout = nil
            arcaServices.stderr = .standardError  // Log errors to vminitd stderr
            do {
                try arcaServices.start()
                // Don't wait here - the daemon waits for services via waitForServicesReady() after container.start()
                // This allows vminitd API to start immediately so the containerization framework doesn't timeout
                log.info("arca-services started (daemon will wait for ready signal on port 51819)")
            } catch {
                log.error("failed to start arca-services: \(error)")
            }
        } else {
            log.warning("arca-services binary not found at \(arcaServicesPath), container networking/filesystem/process services will not be available")
        }

        // Auto-detect and mount OverlayFS if layer block devices are present
        // This is NOT hardcoded - it only runs if vdb/vdc/vdd/etc exist (indicating OverlayFS layers)
        if FileManager.default.fileExists(atPath: "/dev/vdb") {
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

            if !layers.isEmpty {
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

                // Save OverlayFS mount options for later use (will be mounted at container rootfs path via gRPC)
                let opts = "lowerdir=\(lowerDirs.reversed().joined(separator: ":")),upperdir=/mnt/writable/upper,workdir=/mnt/writable/work"
                await OverlayFSConfig.shared.setMountOptions(opts)

                // DO NOT mount OverlayFS at / during boot
                // Instead, it will be mounted directly at /run/container/{id}/rootfs when requested via gRPC
                // This avoids the read-only bind mount issue
                log.info("OverlayFS layers detected and prepared - will mount at container rootfs path (not at /)")
            } else {
                log.info("no layer block devices detected (vdc exists but no vdd+), skipping OverlayFS")
            }
        } else {
            log.info("no OverlayFS block devices detected, using default rootfs")
        }

        let eg = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        let server = Initd(log: log, group: eg)

        do {
            log.info("serving vminitd API")
            try await server.serve(port: vsockPort)
            log.info("vminitd API returned, syncing filesystems")

            #if os(Linux)
            Musl.sync()
            #endif
        } catch {
            log.error("vminitd boot error \(error)")

            #if os(Linux)
            Musl.sync()
            #endif

            exit(1)
        }
    }
}
