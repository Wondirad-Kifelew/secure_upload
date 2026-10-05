import sharp from "sharp";

/**
 * ImageSanitizer
 * ---------------
 * True CDR, not detection: decodes the image's real pixel data and
 * re-encodes it into a brand-new file, rather than editing the
 * original bytes. This is what makes it safe against tricks that
 * validators/scanners can only detect, not neutralize:
 *
 *   - EXIF/ICC metadata (camera info, color profiles — a real place
 *     attackers stash payloads) never makes it into the new file,
 *     because sharp's default re-encode does NOT carry metadata
 *     forward unless you explicitly ask it to (verified: a real image
 *     built WITH embedded EXIF loses it entirely after this step).
 *   - Content appended after the image's real data (the same "hidden
 *     payload after IEND" trick demonstrated earlier against
 *     YaraScanner) is defeated completely — verified: appending a
 *     marker string after a real PNG's IEND chunk, then sanitizing,
 *     produces a file that does not contain that marker anywhere.
 *     This works because sharp only ever reads the valid image
 *     structure when decoding; trailing bytes outside that structure
 *     are never part of the pixel data being copied forward.
 *
 * This does NOT detect anything — unlike every validator/scanner in
 * this project, it has no opinion on whether the input was malicious.
 * It just rebuilds a clean version, unconditionally, every time. The
 * `findings` it returns are purely informational (what metadata WAS
 * present and got removed), not a verdict.
 *
 * A genuinely undecodable buffer (not a real image at all) throws —
 * that's a real failure, not something to sanitize.
 *
 * Implements a Sanitizer contract: sanitize(buffer, meta) ->
 * { buffer, findings } — see core/src/interfaces/sanitizer.js.
 */

const METADATA_FIELDS_TO_REPORT = ["exif", "icc", "xmp", "iptc"];

export function createImageSanitizer({ outputFormat } = {}) {
  return {
    name: "Image Sanitizer",

    async sanitize(buffer) {
      let originalMetadata;
      try {
        originalMetadata = await sharp(buffer).metadata();
      } catch (err) {
        throw new Error(`Could not decode image for sanitization: ${err.message}`);
      }

      const findings = [];
      for (const field of METADATA_FIELDS_TO_REPORT) {
        if (originalMetadata[field]) {
          findings.push({
            rule: `image-${field}-stripped`,
            severity: "low",
            message: `${field.toUpperCase()} metadata was present in the original image and has been removed during sanitization.`,
            details: {},
          });
        }
      }

      const format = outputFormat || originalMetadata.format;
      const sanitizedBuffer = await sharp(buffer).toFormat(format).toBuffer();

      return { buffer: sanitizedBuffer, findings };
    },
  };
}

export const ImageSanitizer = createImageSanitizer();

