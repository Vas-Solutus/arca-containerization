//===----------------------------------------------------------------------===//
// ARCA PATCH. What a virtio-blk device attached to an Arca sandbox *is*.
//
// The host knows: it formats each image and decides what the guest should do with it. The
// guest used to have to guess, by counting device letters from /dev/vdc upwards and calling
// everything it found an OverlayFS layer. That inference is wrong the moment a device of any
// other class is attached -- which is exactly what a named volume is -- and it failed
// silently, mounting three named volumes read-only as overlay lowerdirs.
//
// So the identity travels with the artifact instead: the host writes the role into the ext4
// superblock's volume label when it formats the image, and the guest reads it back. Count and
// order stop mattering.
//
// This file is deliberately free of an `#if os(...)` guard: the macOS host writes these labels
// and the Linux guest reads them, and a vocabulary that only one side could compile would be
// no vocabulary at all. A new device class is a new case here and nothing else -- no second
// positional rule anywhere.
//===----------------------------------------------------------------------===//

/// The role an Arca-formatted ext4 block image plays in the guest, as carried by its volume
/// label.
///
/// Raw values are the on-disk labels and are a compatibility surface between a host build and
/// a vminit build. They must fit `EXT4.VolumeLabelLength` (16) bytes.
public enum ArcaBlockDeviceRole: String, Sendable, CaseIterable, Equatable {
    /// The writable image holding the OverlayFS `upper` and `work` directories.
    case overlayWritable = "arca.writable"

    /// A read-only image layer, one per OCI layer digest, stacked as an OverlayFS lowerdir.
    case overlayLayer = "arca.layer"

    /// The label to write into `s_volume_name` when formatting an image for this role.
    public var volumeLabel: String { rawValue }

    /// The role a volume label names, or `nil` when the label is not one of Arca's.
    ///
    /// `nil` covers every device Arca did not format for a role of its own: Apple's initfs on
    /// `/dev/vda`, and any named-volume image, whose destination reaches the guest in the OCI
    /// spec and which the boot sequence must therefore leave alone.
    public init?(volumeLabel: String) {
        self.init(rawValue: volumeLabel)
    }
}

#if os(macOS)

import ContainerizationEXT4
import SystemPackage

extension ArcaBlockDeviceRole {
    /// The role the ext4 image at `path` was formatted for, or `nil` for anything else.
    ///
    /// `nil` covers three different situations on purpose, because no caller can act on the
    /// difference: the path holds no ext4 filesystem, it holds one with no volume label, or it
    /// holds one whose label is not a role of Arca's. All three mean "this is not an image
    /// Arca formatted for a role", and the host's answer has to match the guest's, which
    /// treats them the same way.
    ///
    /// **This exists because an image formatted before roles existed is a perfectly VALID
    /// ext4 filesystem.** Nothing refuses it; it is simply unlabelled, so a guest classifying
    /// by label leaves it alone and a rootfs gets built without it. Checking is therefore a
    /// positive test for the role and never a test for corruption.
    ///
    /// Host-only: it reads a superblock through `ContainerizationEXT4`, which the guest build
    /// does not link. The enum above stays unguarded because it is the shared vocabulary.
    public static func role(ofImageAt path: FilePath) -> ArcaBlockDeviceRole? {
        (try? EXT4.volumeLabel(ofBlockDevice: path))
            .flatMap { $0 }
            .flatMap(ArcaBlockDeviceRole.init(volumeLabel:))
    }
}

#endif
