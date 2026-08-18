//===----------------------------------------------------------------------===//
// Copyright © 2026 Apple Inc. and the Containerization project authors.
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

extension Kernel {
    /// Build the `init=/sbin/vminitd` Linux kernel command line for the given
    /// rootfs type. Used by both the VZ and cloud-hypervisor backends since
    /// the guest's vminitd init contract is identical across VMMs.
    ///
    /// ARCA PATCH: `attachedOverlayLayers` is how many OverlayFS layer block devices this VM
    /// is being given, reported to vminitd as an init argument. It has NO default value on
    /// purpose: this function is the single point both backends build a command line through
    /// (`VZVirtualMachineInstance.toVZ`, `CHVirtualMachineInstance.buildVmConfig`), and a
    /// required parameter makes a **call site** that omits the value fail to compile.
    ///
    /// **That is all it secures, and the difference matters.** The value reaches those two call
    /// sites through three plain assignments -- `LinuxContainer.create` into `VMConfiguration`,
    /// and each manager's `create` into its instance configuration. Dropping one produces
    /// exactly the "one backend reports and the other does not" this parameter cannot prevent,
    /// and it is invisible: MEASURED at submodule `cc2ea7d` / Arca `a3e812d` with the
    /// `LinuxContainer.create` assignment deleted, the submodule reported `613 tests passed`
    /// -- its whole count at that commit -- and Arca reported `Executed 247 tests, with 0
    /// failures`. The guest would then be told nothing, resolve `.unreported`, and refuse every
    /// boot on that backend, with the only trace a line in `bootlog.log`. Those three lines are
    /// load bearing and pinned by nothing.
    ///
    /// The hop after them -- an instance configuration to this command line -- **is** pinned,
    /// by `VZAttachedLayerReportTests` driving
    /// `VZVirtualMachineInstance.Configuration.linuxBootLoader(kernel:initialFilesystem:)`,
    /// which was extracted for that purpose. What is still unreachable from a test is `toVZ`
    /// itself, which ends in `VZVirtualMachineConfiguration.validate()`, which needs the
    /// virtualization entitlement (MEASURED: a bare `VZVirtualMachineConfiguration` carrying
    /// only a `VZLinuxBootLoader` throws `VZErrorDomain Code=2 ... doesn't have the
    /// "com.apple.security.virtualization" entitlement` from `validate()` alone).
    ///
    /// `nil` means this VM has no Arca overlay at all -- upstream's own
    /// rootfs-in-a-single-image boot -- and is not the same claim as `0`.
    /// See `ArcaLayerAttachment`.
    func linuxCommandline(initialFilesystem: Mount, attachedOverlayLayers: Int?) -> String {
        var args = self.commandLine.kernelArgs

        args.append("init=/sbin/vminitd")
        // rootfs is always mounted read-only.
        args.append("ro")

        switch initialFilesystem.type {
        case "virtiofs":
            args.append(contentsOf: [
                "rootfstype=virtiofs",
                "root=rootfs",
            ])
        case "ext4":
            args.append(contentsOf: [
                "rootfstype=ext4",
                "root=/dev/vda",
            ])
        default:
            fatalError("unsupported initfs filesystem \(initialFilesystem.type)")
        }

        // ARCA PATCH: the layer count is an init argument and never a kernel argument. The
        // kernel would parse it, fail to recognise it, and hand it to init as an environment
        // entry instead; everything after `--` is init's argv by contract.
        var initArgs = self.commandLine.initArgs
        if let attachedOverlayLayers {
            initArgs.append(ArcaLayerAttachment.initArgument(attached: attachedOverlayLayers))
        }

        if initArgs.count > 0 {
            args.append("--")
            args.append(contentsOf: initArgs)
        }

        return args.joined(separator: " ")
    }
}
