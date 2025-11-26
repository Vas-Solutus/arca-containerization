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

        signal(SIGPIPE, SIG_IGN)

        // Because the sysctl rpc wouldn't make sense if this didn't always exist, we
        // ALWAYS mount /proc.
        guard Musl.mount("proc", "/proc", "proc", 0, "") == 0 else {
            log.error("failed to mount /proc")
            exit(1)
        }
        guard Musl.mount("tmpfs", "/run", "tmpfs", 0, "") == 0 else {
            log.error("failed to mount /run")
            exit(1)
        }
        guard Musl.mount("tmpfs", "/mnt", "tmpfs", 0, "") == 0 else {
            log.error("failed to mount /mnt")
            exit(1)
        }
        try Binfmt.mount()

        log.logLevel = .debug

        log.info("vminitd booting...")

        // Start arca-wireguard-service in background for WireGuard networking (with integrated DNS)
        // This service listens on vsock port 51820 (accessible from host via container.dialVsock())
        let wireGuardServicePath = "/sbin/arca-wireguard-service"
        let wireGuardServiceExists = FileManager.default.fileExists(atPath: wireGuardServicePath)
        log.info("arca-wireguard-service binary exists: \(wireGuardServiceExists) at \(wireGuardServicePath)")

        if wireGuardServiceExists {
            log.info("starting arca-wireguard-service...")
            var wireGuardService = Command(wireGuardServicePath)
            // Leave stdin/stdout/stderr as nil for detached background service
            wireGuardService.stdin = nil
            wireGuardService.stdout = nil
            wireGuardService.stderr = .standardError  // Log errors to vminitd stderr
            do {
                try wireGuardService.start()
                log.info("arca-wireguard-service started successfully on vsock port 51820")
            } catch {
                log.error("failed to start arca-wireguard-service: \(error)")
            }
        } else {
            log.warning("arca-wireguard-service binary not found at \(wireGuardServicePath), WireGuard networking will not be available")
        }

        // Start arca-filesystem-service in background for filesystem operations
        // This service listens on vsock port 51821 (accessible from host via container.dialVsock())
        // Provides: filesystem sync, upperdir enumeration (docker diff), bind mounts (file volumes), archive operations
        let filesystemServicePath = "/sbin/arca-filesystem-service"
        let filesystemServiceExists = FileManager.default.fileExists(atPath: filesystemServicePath)
        log.info("arca-filesystem-service binary exists: \(filesystemServiceExists) at \(filesystemServicePath)")

        if filesystemServiceExists {
            log.info("starting arca-filesystem-service...")
            var filesystemService = Command(filesystemServicePath)
            // Leave stdin/stdout/stderr as nil for detached background service
            filesystemService.stdin = nil
            filesystemService.stdout = nil
            filesystemService.stderr = .standardError  // Log errors to vminitd stderr
            do {
                try filesystemService.start()
                log.info("arca-filesystem-service started successfully on vsock port 51821")
            } catch {
                log.error("failed to start arca-filesystem-service: \(error)")
            }
        } else {
            log.warning("arca-filesystem-service binary not found at \(filesystemServicePath), filesystem operations will not be available")
        }

        // Start arca-process-service in background for process control
        // This service listens on vsock port 51822 (accessible from host via container.dialVsock())
        let processServicePath = "/sbin/arca-process-service"
        let processServiceExists = FileManager.default.fileExists(atPath: processServicePath)
        log.info("arca-process-service binary exists: \(processServiceExists) at \(processServicePath)")

        if processServiceExists {
            log.info("starting arca-process-service...")
            var processService = Command(processServicePath)
            // Leave stdin/stdout/stderr as nil for detached background service
            processService.stdin = nil
            processService.stdout = nil
            processService.stderr = .standardError  // Log errors to vminitd stderr
            do {
                try processService.start()
                log.info("arca-process-service started successfully on vsock port 51822")
            } catch {
                log.error("failed to start arca-process-service: \(error)")
            }
        } else {
            log.warning("arca-process-service binary not found at \(processServicePath), process listing via gRPC will not be available")
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
            log.info("serve vminitd api")
            try await server.serve(port: vsockPort)
            log.info("vminitd api returned...")
        } catch {
            log.error("vminitd boot error \(error)")
            exit(1)
        }
    }
}
