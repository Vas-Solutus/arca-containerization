//===----------------------------------------------------------------------===//
// ARCA PATCH. Which layer of an image refused to unpack.
//
// `EXT4.Formatter.unpack` throws `UnpackError.sourceIsNotDeclaredArchive` naming the
// DECLARATION it refused against -- "a paxRestricted archive with filter none" -- and nothing
// that identifies the blob that carried it. An image has many layers and `EXT4Unpacker` walks
// all of them into one filesystem, so neither the throw nor the destination it refused against
// says which one it was. The operator's next question is always
// which layer, and their remedy -- refetch that blob, rebuild that layout -- needs the digest
// to act on. The media type is the other half: it says whether the blob or the declaration is
// the wrong one.
//
// The spelling lives here rather than inline at the throw, so that a second unpacker cannot
// drift into naming the layer differently.
//===----------------------------------------------------------------------===//

import ContainerizationError
import Foundation

/// The identity an unpack failure is missing, attached by the frame that knows it.
enum LayerUnpackFailure {
    /// `cause`, wrapped so that it names the layer that produced it.
    ///
    /// The original is the `cause` rather than folded into the message:
    /// `ContainerizationError` renders it either way, and a caller that wants to
    /// inspect the refusal itself still can.
    ///
    /// `index` is zero-based and reported one-based, because the manifest's layer
    /// order is what an operator counts through and they count from one.
    static func naming(
        layer index: Int,
        of total: Int,
        digest: String,
        mediaType: String,
        destination: String,
        cause: any Error
    ) -> ContainerizationError {
        ContainerizationError(
            .internalError,
            message: "layer \(index + 1) of \(total), \(digest) (\(mediaType)), "
                + "could not be unpacked into \(destination)",
            cause: cause
        )
    }
}
