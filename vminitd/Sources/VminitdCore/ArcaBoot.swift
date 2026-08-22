//===----------------------------------------------------------------------===//
// Arca-specific vminitd boot steps.
//
// ARCA PATCH. Upstream restructured vminitd during the 2026-08 merge: the old
// Application.run() body moved into AgentCommand.bootstrap(), and Application.swift became
// a thin subcommand shell. The Arca additions that lived in that body are collected here
// rather than inlined into AgentCommand.swift, so the fork's delta against upstream stays a
// one-line call site instead of `startServices` interleaved into an upstream file. Roadmap
// P8.2 wants exactly this shape when a modification cannot be upstreamed.
//
// Dropped during that move: `waitForVsockService(port:serviceName:timeout:log:)`, which had
// no call site in the fork. Readiness is handled host-side instead, by the daemon waiting on
// vsock port 51819 after container.start().
//===----------------------------------------------------------------------===//

#if os(Linux)

import ContainerizationOS
import Foundation
import Logging

enum ArcaBoot {
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
}

#endif
