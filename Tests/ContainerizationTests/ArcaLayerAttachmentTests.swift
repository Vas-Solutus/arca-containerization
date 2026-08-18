//===----------------------------------------------------------------------===//
// ARCA PATCH. The three cases that used to be two observations.
//===----------------------------------------------------------------------===//

import Foundation
import Testing

@testable import Containerization

/// That the host's count and the guest's count, together, separate an image with no layers
/// from layers the guest could not identify.
///
/// **Both used to arrive as the same thing.** A container's writable overlay device is created
/// and attached unconditionally, and its layer devices come from `manifest.layers`, so a
/// writable with nothing under it is what a `FROM scratch` image produces AND what a guest that
/// failed to classify every layer sees. `ArcaBoot` refused both, which killed a legitimate
/// zero-layer container, and its own comment recorded that as wrong and unfixable from the
/// guest side alone.
///
/// These run on macOS against the same type the Linux guest calls, which is why
/// `ArcaLayerAttachment` carries no `#if os(...)`: the decision is arithmetic and testable, the
/// `exit(1)` around it is not.
struct ArcaLayerAttachmentTests {
    @Test func anImageWithNoLayersIsNotAFailure() {
        let attachment = ArcaLayerAttachment.resolve(attached: 0, identified: 0)

        #expect(attachment == .emptyImage)
        #expect(attachment.refusal == nil)
    }

    @Test func everyAttachedLayerIdentifiedProceeds() {
        let attachment = ArcaLayerAttachment.resolve(attached: 4, identified: 4)

        #expect(attachment == .complete(count: 4))
        #expect(attachment.refusal == nil)
    }

    /// The case the whole change exists for, and the one a zero-layer image is NOT.
    @Test func layersAttachedButNotIdentifiedIsARefusal() throws {
        let attachment = ArcaLayerAttachment.resolve(attached: 4, identified: 2)

        #expect(attachment == .disagreement(attached: 4, identified: 2))
        let refusal = try #require(attachment.refusal)
        // Both numbers, because "expected 4, identified 2" is the diagnostic the message this
        // replaces could not produce: it knew only that the layer list was empty.
        #expect(refusal.contains("4"))
        #expect(refusal.contains("2"))
    }

    /// Every layer missing is the shape the old single-number guard caught, and it must stay
    /// caught now that zero identified layers is sometimes legitimate.
    @Test func layersAttachedAndNoneIdentifiedIsARefusal() {
        let attachment = ArcaLayerAttachment.resolve(attached: 3, identified: 0)

        #expect(attachment == .disagreement(attached: 3, identified: 0))
        #expect(attachment.refusal != nil)
    }

    /// More identified than attached is a disagreement too. Nothing known produces it, and
    /// that is the reason: a guest that has found a layer device its host did not attach has
    /// found something no one can explain, and building a rootfs out of it is the worst of the
    /// available answers.
    @Test func moreIdentifiedThanAttachedIsARefusal() {
        let attachment = ArcaLayerAttachment.resolve(attached: 1, identified: 2)

        #expect(attachment == .disagreement(attached: 1, identified: 2))
        #expect(attachment.refusal != nil)
    }

    /// **A host that said nothing is not a host that said zero.** Reading `nil` as `0` would
    /// make every unreported boot look like an empty image, which is exactly the silent wrong
    /// rootfs this guard exists to prevent -- and it would do it to ordinary images.
    @Test func anUnreportedCountIsRefusedAndIsNotAnEmptyImage() {
        let attachment = ArcaLayerAttachment.resolve(attached: nil, identified: 0)

        #expect(attachment != .emptyImage)
        #expect(attachment == .unreported(identified: 0))
        #expect(attachment.refusal != nil)
    }

    @Test func anUnreportedCountIsRefusedEvenWithLayersIdentified() {
        let attachment = ArcaLayerAttachment.resolve(attached: nil, identified: 3)

        #expect(attachment == .unreported(identified: 3))
        #expect(attachment.refusal != nil)
    }

    /// The wire format is one token. A flag and its value as two arguments could be separated
    /// by anything between here and the guest's argv; this cannot be.
    @Test func theCountTravelsAsASingleArgument() {
        #expect(ArcaLayerAttachment.initArgument(attached: 7) == "--arca-attached-layers=7")
        #expect(ArcaLayerAttachment.initArgument(attached: 0) == "--arca-attached-layers=0")
    }
}
