//===----------------------------------------------------------------------===//
// Copyright © 2025-2026 Apple Inc. and the Containerization project authors.
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

//

import Foundation
import Logging
import Testing

@testable import Containerization

final class KernelTests {
    @Test func kernelArgs() {
        let commandLine = Kernel.CommandLine(debug: false, panic: 0)
        let kernel = Kernel(path: .init(fileURLWithPath: ""), platform: .linuxArm, commandline: commandLine)

        let expected = "console=hvc0 tsc=reliable panic=0"
        let cmdline = kernel.commandLine.kernelArgs.joined(separator: " ")
        #expect(cmdline == expected)
    }

    @Test func kernelDebugArgs() {
        let cmdLine = Kernel.CommandLine(debug: true, panic: 0)
        let kernel = Kernel(path: .init(fileURLWithPath: ""), platform: .linuxArm, commandline: cmdLine)

        let expected = "console=hvc0 tsc=reliable debug panic=0"
        let cmdline = kernel.commandLine.kernelArgs.joined(separator: " ")
        #expect(cmdline == expected)
    }

    @Test func kernelCommandLineInitWithDebugTrue() {
        let commandLine = Kernel.CommandLine(debug: true, panic: 5, initArgs: ["--verbose"])

        #expect(commandLine.kernelArgs == ["console=hvc0", "tsc=reliable", "debug", "panic=5"])
        #expect(commandLine.initArgs == ["--verbose"])
    }

    @Test func kernelCommandLineMutatingMethods() {
        var commandLine = Kernel.CommandLine(kernelArgs: ["console=hvc0"], initArgs: [])

        commandLine.addDebug()
        commandLine.addPanic(level: 10)

        #expect(commandLine.kernelArgs == ["console=hvc0", "debug", "panic=10"])
    }

    @Test func setAgentLogLevelAppendsFlagAndValue() {
        var commandLine = Kernel.CommandLine(initArgs: [])
        commandLine.setAgentLogLevel(level: .debug)
        #expect(commandLine.initArgs == ["--log-level", "debug"])
    }

    @Test(arguments: [
        (Logger.Level.trace, "trace"),
        (.debug, "debug"),
        (.info, "info"),
        (.notice, "notice"),
        (.warning, "warning"),
        (.error, "error"),
        (.critical, "critical"),
    ])
    func setAgentLogLevelForEachLevel(level: Logger.Level, expected: String) {
        var commandLine = Kernel.CommandLine(initArgs: [])
        commandLine.setAgentLogLevel(level: level)
        #expect(commandLine.initArgs == ["--log-level", expected])
    }

    @Test func setAgentLogLevelPreservesExistingInitArgs() {
        var commandLine = Kernel.CommandLine(initArgs: ["--verbose"])
        commandLine.setAgentLogLevel(level: .info)
        #expect(commandLine.initArgs == ["--verbose", "--log-level", "info"])
    }

    @Test func setAgentLogLevelDoesNotAffectKernelArgs() {
        var commandLine = Kernel.CommandLine(debug: true, panic: 0, initArgs: [])
        let kernelArgsBefore = commandLine.kernelArgs
        commandLine.setAgentLogLevel(level: .warning)
        #expect(commandLine.kernelArgs == kernelArgsBefore)
    }

    // MARK: - ARCA PATCH: the attached-layer count on the command line
    //
    // This is the channel the host tells the guest how many OverlayFS layer devices it
    // attached over. `linuxCommandline` is the single function both VMM backends build a
    // command line through, which is why the count goes here rather than into either backend:
    // one of them reporting and the other not would leave the guest's check working on one
    // VMM and refusing every boot on the other.

    private func kernel(initArgs: [String] = []) -> Kernel {
        Kernel(
            path: .init(fileURLWithPath: "/vmlinux"),
            platform: .linuxArm,
            commandline: Kernel.CommandLine(kernelArgs: [], initArgs: initArgs)
        )
    }

    private var ext4Rootfs: Mount {
        .block(format: "ext4", source: "/initfs.ext4", destination: "/", options: [])
    }

    @Test func theAttachedLayerCountReachesTheGuestAsAnInitArgument() {
        let cmdline = kernel().linuxCommandline(initialFilesystem: ext4Rootfs, attachedOverlayLayers: 4)

        // After `--`, which is what the kernel hands to init as its argv. Before it, the
        // kernel would parse it as one of its own parameters and vminitd would never see it.
        #expect(cmdline.hasSuffix("-- --arca-attached-layers=4"))
    }

    /// Zero is a claim the guest acts on -- it is what an image with no layers looks like --
    /// so it must be sent, not elided as "nothing to say".
    @Test func zeroAttachedLayersIsReportedAndIsNotSilence() {
        let cmdline = kernel().linuxCommandline(initialFilesystem: ext4Rootfs, attachedOverlayLayers: 0)

        #expect(cmdline.contains("-- --arca-attached-layers=0"))
    }

    /// A VM with no Arca overlay says nothing, which the guest distinguishes from `0`.
    @Test func aVMWithNoOverlayReportsNoCountAtAll() {
        let cmdline = kernel().linuxCommandline(initialFilesystem: ext4Rootfs, attachedOverlayLayers: nil)

        #expect(!cmdline.contains("arca-attached-layers"))
        #expect(!cmdline.contains("--"))
    }

    /// The count is appended to whatever init arguments were already configured rather than
    /// replacing them: `setAgentLogLevel` puts `--log-level` in the same list.
    @Test func theCountJoinsExistingInitArgsWithoutDisplacingThem() {
        let cmdline = kernel(initArgs: ["--log-level", "debug"])
            .linuxCommandline(initialFilesystem: ext4Rootfs, attachedOverlayLayers: 2)

        #expect(cmdline.hasSuffix("-- --log-level debug --arca-attached-layers=2"))
    }

    /// Reporting the count must not disturb the kernel's own parameters, which decide how the
    /// guest boots at all.
    @Test func reportingTheCountLeavesTheKernelArgumentsAlone() {
        let boot = kernel().linuxCommandline(initialFilesystem: ext4Rootfs, attachedOverlayLayers: nil)
        let reported = kernel().linuxCommandline(initialFilesystem: ext4Rootfs, attachedOverlayLayers: 3)

        #expect(reported == boot + " -- --arca-attached-layers=3")
        #expect(boot == "init=/sbin/vminitd ro rootfstype=ext4 root=/dev/vda")
    }
}
