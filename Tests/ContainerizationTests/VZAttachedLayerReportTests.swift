//===----------------------------------------------------------------------===//
// ARCA PATCH. That the VZ backend's boot loader carries the layer count.
//===----------------------------------------------------------------------===//

#if os(macOS)

import Foundation
import Testing
import Virtualization

@testable import Containerization

/// That the count set on a VZ instance configuration reaches the command line the guest boots
/// with.
///
/// **`KernelTests` pins the string; this pins the hop that uses it.** A `linuxCommandline` that
/// formats the flag perfectly is worth nothing if the VZ backend never hands it the count, and
/// no test of `Kernel` alone can tell the difference.
///
/// **Why this drives `linuxBootLoader` and not `toVZ`.** `toVZ` ends in
/// `VZVirtualMachineConfiguration.validate()`, which needs the virtualization entitlement even
/// though no virtual machine is built anywhere in it -- MEASURED: a bare
/// `VZVirtualMachineConfiguration` carrying only a `VZLinuxBootLoader` throws `VZErrorDomain
/// Code=2 ... doesn't have the "com.apple.security.virtualization" entitlement` from
/// `validate()` alone, while reading `commandLine` back off the loader needs nothing. The
/// boot-loader construction was extracted for exactly that reason.
///
/// **What that extraction makes true is stronger than what these tests assert.**
/// `linuxBootLoader` reads `attachedOverlayLayers` from the configuration, so `toVZ` has no
/// count to pass and no way to pass a wrong one. The failure mode "the backend reports a number
/// that disagrees with the devices it attached" is gone by construction rather than watched for.
/// These tests pin the remaining thing a change could still get wrong: that the number on the
/// configuration is the number on the command line.
///
/// The two hops on either side remain unpinned and are not reachable from here:
/// `VZVirtualMachineManager.create` assigns the field inside the closure it hands to the
/// `VZVirtualMachineInstance` initialiser, which builds a real machine, and `LinuxContainer`
/// would need a fake `VirtualMachineManager` that this package does not have.
struct VZAttachedLayerReportTests {
    /// A configuration whose only interesting property is the reported count.
    private func configuration(attachedOverlayLayers: Int?) -> VZVirtualMachineInstance.Configuration {
        var config = VZVirtualMachineInstance.Configuration()
        config.attachedOverlayLayers = attachedOverlayLayers
        return config
    }

    private func commandLine(attachedOverlayLayers: Int?) -> String {
        let kernel = Kernel(
            path: URL(fileURLWithPath: "/vmlinux"),
            platform: .linuxArm,
            commandline: Kernel.CommandLine(kernelArgs: ["console=hvc0"], initArgs: [])
        )
        let initfs = Mount.block(format: "ext4", source: "/initfs.ext4", destination: "/", options: [])
        return configuration(attachedOverlayLayers: attachedOverlayLayers)
            .linuxBootLoader(kernel: kernel, initialFilesystem: initfs)
            .commandLine
    }

    @Test func theBootLoaderCarriesTheReportedCount() {
        #expect(commandLine(attachedOverlayLayers: 4).hasSuffix("-- --arca-attached-layers=4"))
    }

    /// Zero is a report and not silence, all the way through the assembly.
    @Test func zeroSurvivesTheAssembly() {
        #expect(commandLine(attachedOverlayLayers: 0).hasSuffix("-- --arca-attached-layers=0"))
    }

    /// A VM with no Arca overlay must reach the guest saying nothing, which the guest
    /// distinguishes from a report of zero.
    @Test func noOverlayReportsNothing() {
        #expect(!commandLine(attachedOverlayLayers: nil).contains("arca-attached-layers"))
    }
}

#endif
