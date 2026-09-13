import { fileTypeFromBuffer } from "file-type";

/**
 * MagicByteValidator
 * -------------------
 * Sniffs the file's true type from its content (magic bytes / file
 * signature) rather than trusting the declared MIME type — this is
 * the "never trust declared MIME type or extension alone" rule from
 * Phase 1.
 *
 * Scope, on purpose: this validator ONLY compares declared-vs-sniffed
 * MIME type. It does NOT look at the file extension — that three-way
 * comparison (declared MIME vs sniffed content vs extension) belongs
 * to a separate "mismatch detection" validator later, so each file
 * stays small and independently testable.
 *
 * A note on limits: many legitimate formats (plain text, JSON, CSV,
 * SVG, etc.) have no distinguishing magic bytes at all, so detection
 * returning "unknown" does not by itself mean the file is malicious.
 * We only raise a finding when we DID detect a type and it disagrees
 * with what was declared, or when a declared type was one we'd expect
 * to be detectable but wasn't.
 *
 * Implements the Validator contract from core/src/interfaces/validator.js.
 */
export const MagicByteValidator = {
  name: "Magic Byte Sniffer",

  /**
   * @param {Buffer} buffer
   * @param {{ filename?: string, declaredMimeType?: string }} meta
   * @returns {Promise<import('@secureupload/core').ValidationFinding[]>}
   */
  async validate(buffer, meta = {}) {
    console.log("Running magic-byte sniffing validator...");
    const findings = [];
    const { declaredMimeType } = meta;

    // Nothing to compare against — this validator has nothing useful to say.
    if (!declaredMimeType) {
      return findings;
    }

    const detected = await fileTypeFromBuffer(buffer);

    if (!detected) {
      findings.push({
        rule: "magic-byte-undetected",
        severity: "low",
        message:
          `Declared type "${declaredMimeType}" could not be verified — ` +
          `no recognizable file signature was found in the content.`,
        details: { declaredMimeType },
      });
      return findings;
    }

    if (detected.mime !== declaredMimeType) {
      findings.push({
        rule: "magic-byte-mismatch",
        severity: "high",
        message:
          `Declared type "${declaredMimeType}" does not match the content's ` +
          `actual signature, which is "${detected.mime}".`,
        details: { declaredMimeType, detectedMimeType: detected.mime, detectedExtension: detected.ext },
      });
    }

    return findings;
  },
};
