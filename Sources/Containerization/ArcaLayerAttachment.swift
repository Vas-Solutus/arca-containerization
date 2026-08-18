//===----------------------------------------------------------------------===//
// ARCA PATCH. How many OverlayFS layer devices the host attached, and what a guest does when
// its own count of them disagrees.
//
// `ArcaBlockDeviceRole` made each device say what it IS. It cannot make the set of devices say
// how many there were meant to be: a layer whose label is missing is indistinguishable from a
// layer that was never attached, so "this image has no layers" and "I could not identify the
// layers this image has" arrive at the guest as the same observation -- an overlay writable
// with nothing under it. The guest's only options were to boot a container on a rootfs that is
// not its image, or to refuse every `FROM scratch` image and OCI artifact along with the
// broken case.
//
// The count is the missing half. It is the host's INTENT -- how many layer images it decided
// to attach -- and deliberately not a re-reading of the labels it wrote. A count derived from
// the labels would agree with the guest's classification exactly when the classification is
// wrong, which is the one case worth catching.
//
// Unguarded by `#if os(...)` for the reason `ArcaBlockDeviceRole` is: the macOS host writes
// this number onto the kernel command line and the Linux guest reads it back off its own argv,
// and a vocabulary only one side could compile would be no vocabulary at all. The flag spelling
// lives here once so the two sides cannot drift: the host formats `initArgument(attached:)` and
// the guest declares its option as `.customLong(commandLineFlag)`.
//===----------------------------------------------------------------------===//

/// What the host said it attached, checked against what the guest identified.
public enum ArcaLayerAttachment: Sendable, Equatable {
    /// The host attached no layers and the guest identified none: a zero-layer image
    /// (`FROM scratch`, an OCI artifact). Its rootfs is legitimately empty.
    case emptyImage

    /// The host attached `count` layers and the guest identified all of them.
    case complete(count: Int)

    /// The host did not say how many it attached.
    case unreported(identified: Int)

    /// The two numbers disagree.
    case disagreement(attached: Int, identified: Int)

    /// The long-option name the count travels under, without its leading dashes.
    ///
    /// Both sides read it from here. The host writes the argument with
    /// ``initArgument(attached:)``; the guest names its `ArgumentParser` option
    /// `.customLong(ArcaLayerAttachment.commandLineFlag)`.
    public static let commandLineFlag = "arca-attached-layers"

    /// The single init argument that reports `attached` to the guest.
    ///
    /// One token rather than a flag and a value, so nothing between here and the guest's argv
    /// can separate them.
    public static func initArgument(attached: Int) -> String {
        "--\(commandLineFlag)=\(attached)"
    }

    /// Which of the four situations a boot is in.
    ///
    /// `attached` is `nil` when no count reached the guest at all, which is a fifth thing and
    /// not a zero: a host that reported nothing and a host that reported zero are different
    /// claims and only one of them is an empty image.
    public static func resolve(attached: Int?, identified: Int) -> Self {
        guard let attached else {
            return .unreported(identified: identified)
        }
        guard attached == identified else {
            return .disagreement(attached: attached, identified: identified)
        }
        return attached == 0 ? .emptyImage : .complete(count: attached)
    }

    /// `nil` when the boot may proceed, otherwise why it must not.
    ///
    /// Both refusals name both numbers. "expected 4, identified 2" is the diagnostic the
    /// single-number message this replaces could not produce, and it is the difference between
    /// a report that says which layers went missing and one that says only that some did.
    public var refusal: String? {
        switch self {
        case .emptyImage, .complete:
            return nil
        case .unreported(let identified):
            return """
                the host did not report how many OverlayFS layer devices it attached, so the \
                \(identified) this guest identified cannot be checked against anything: a \
                rootfs built from a subset of its own image would be indistinguishable from a \
                correct one
                """
        case .disagreement(let attached, let identified):
            return """
                the host attached \(attached) OverlayFS layer device(s) and this guest \
                identified \(identified): the layers this container was built from could not \
                all be identified, and booting without them would run it on a rootfs that is \
                not its image
                """
        }
    }
}
