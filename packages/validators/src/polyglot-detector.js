import { fileTypeFromBuffer } from "file-type";

/**
 * PolyglotDetectorValidator
 * ---------------------------
 * A polyglot is a file that's simultaneously valid under two unrelated
 * format interpretations — e.g. a file that's a genuinely valid GIF
 * AND, read as text, also valid, runnable JavaScript. Every other
 * validator in this package only ever asks "is this ONE claimed type
 * consistent" — none of them ask "does this ALSO validate as something
 * completely different." That's this validator's whole job.
 *
 * SCOPE, DELIBERATELY NARROW: this only checks the GIF/PNG/JPEG-style
 * "binary media that's also valid JS" combination, proven to work
 * reliably with low false positives (see the test file). It does NOT
 * attempt a PDF/ZIP-style "valid archive appended after a fake header"
 * check — that requires an offset-correcting zip parser (most strict
 * zip readers, including the yauzl library used elsewhere in this
 * project, don't auto-adjust for prepended bytes the way some more
 * permissive tools do), which is a genuinely harder, unverified
 * problem left for a future iteration rather than shipped untested.
 *
 * Why gate on "has a concrete detected type" first: JS's grammar is
 * very permissive — plain text files (CSV, config files, etc.) can
 * easily happen to ALSO parse as syntactically valid JS by pure
 * coincidence, which would make this validator noisy if run against
 * everything. Restricting it to files that file-type already
 * confidently identified as a concrete BINARY format (image, PDF,
 * etc.) makes a coincidental JS-parse essentially impossible — real
 * compressed pixel/binary data does not by chance form valid JS
 * syntax. See the sandbox verification: a genuine, non-crafted PNG's
 * real pixel data reliably throws a SyntaxError when parsed as JS.
 *
 * SAFETY NOTE: this only ever CONSTRUCTS a Function from the buffer's
 * text — it never CALLS it. Constructing parses/compiles the code but
 * does not execute the function body, so no attacker-controlled code
 * ever actually runs during detection.
 *
 * Implements the Validator contract from core/src/interfaces/validator.js.
 */

const DEFAULT_MAX_BUFFER_SIZE_TO_CHECK = 5 * 1024 * 1024; // 5MB — bound worst-case parse cost
const MIN_NON_WHITESPACE_LENGTH = 10; // avoid flagging trivially-empty "valid" parses

export function createPolyglotDetectorValidator({
  maxBufferSizeToCheck = DEFAULT_MAX_BUFFER_SIZE_TO_CHECK,
} = {}) {
  return {
    name: "Polyglot Detector",

    /**
     * @param {Buffer} buffer
     * @returns {Promise<import('@secureupload/core').ValidationFinding[]>}
     */
    async validate(buffer) {
      console.log("Running polyglot detector validator...");
      const findings = [];

      if (buffer.length > maxBufferSizeToCheck) {
        return findings;
      }

      const detected = await fileTypeFromBuffer(buffer);
      if (!detected) {
        // No concrete type established — nothing to compare a second
        // interpretation against, and the noise risk described above
        // applies here.
        return findings;
      }

      const text = buffer.toString("utf8");
      if (text.trim().length < MIN_NON_WHITESPACE_LENGTH) {
        return findings;
      }

      try {
        // eslint-disable-next-line no-new-func -- parse-only, never called
        new Function(text);
      } catch {
        // Not valid JS — the normal, expected case for real media files.
        return findings;
      }

      findings.push({
        rule: "polyglot-dual-format",
        severity: "extreme",
        message:
          `File is detected as "${detected.mime}" but the same content also parses as ` +
          `syntactically valid JavaScript — a dual-format polyglot, a known technique for ` +
          `smuggling executable content past checks that only look at the declared/sniffed type.`,
        details: { detectedMimeType: detected.mime },
      });

      return findings;
    },
  };
}

/** The default instance, with real-world limits — what other packages import. */
export const PolyglotDetectorValidator = createPolyglotDetectorValidator();