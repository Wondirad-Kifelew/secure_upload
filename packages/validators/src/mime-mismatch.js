import { fileTypeFromBuffer } from "file-type";

/**
 * MimeMismatchValidator
 * -----------------------
 * magic-byte.js compares declared-vs-sniffed content only — it never
 * looks at the filename's extension. This validator fills that gap by
 * checking the EXTENSION against both the declared type and the
 * sniffed content:
 *
 *   extension-declared-mismatch  — the extension disagrees with what
 *     the upload claimed (e.g. "photo.jpg" declared as "application/pdf")
 *
 *   extension-content-mismatch   — the extension disagrees with what
 *     the file's content actually is (e.g. "invoice.pdf" that is
 *     really a PNG under the hood — a classic renamed-extension trick,
 *     including the "resume.php.jpg" doubsssssle-extension case, since only
 *     the LAST extension is checked here, same as most real servers do)
 *
 * Deliberately NOT re-checking declared-vs-sniffed here — that's
 * magic-byte.js's job already. This file only ever involves the
 * extension as one of the two things being compared.
 *
 * Implements the Validator contract from core/src/interfaces/validator.js.
 */

// Extensions can legitimately map to more than one real-world MIME type
// (browsers/tools aren't fully consistent), so each maps to a LIST of
// acceptable types, not just one.
const EXTENSION_TO_MIME = {
  ".png": ["image/png"],
  ".jpg": ["image/jpeg"],
  ".jpeg": ["image/jpeg"],
  ".gif": ["image/gif"],
  ".pdf": ["application/pdf"],
  ".zip": ["application/zip"],
  ".docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
  ".xlsx": ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
  ".pptx": ["application/vnd.openxmlformats-officedocument.presentationml.presentation"],
  // Legacy Office files sniff as generic CFB, not a Word/Excel-specific
  // mime — see the .doc vs .docx discussion. Include both so a real
  // legacy .doc doesn't false-positive against itself.
  ".doc": ["application/msword", "application/x-cfb"],
  ".xls": ["application/vnd.ms-excel", "application/x-cfb"],
  ".ppt": ["application/vnd.ms-powerpoint", "application/x-cfb"],
  ".mp3": ["audio/mpeg"],
  ".mp4": ["video/mp4"],
};

function getExtension(filename) {
  const match = /\.[^./\\]+$/.exec(filename ?? "");
  return match ? match[0].toLowerCase() : null;
}

export const MimeMismatchValidator = {
  name: "MIME Mismatch Detector",

  /**
   * @param {Buffer} buffer
   * @param {{ filename?: string, declaredMimeType?: string }} meta
   * @returns {Promise<import('@secureupload/core').ValidationFinding[]>}
   */
  async validate(buffer, meta = {}) {
    console.log("Running MIME mismatch validator...");
    const findings = [];
    const { filename, declaredMimeType } = meta;

    if (!filename) {
      return findings;
    }

    const ext = getExtension(filename);

    // Unrecognized/unlisted extension — nothing to compare against.
    // (Not itself suspicious; plenty of legitimate extensions aren't
    // in this table yet.)
    if (!ext || !(ext in EXTENSION_TO_MIME)) {
      return findings;
    }

    const expectedMimes = EXTENSION_TO_MIME[ext];

    if (declaredMimeType && !expectedMimes.includes(declaredMimeType)) {
      findings.push({
        rule: "extension-declared-mismatch",
        severity: "medium",
        message:
          `The file extension "${ext}" does not match the declared type "${declaredMimeType}".`,
        details: { extension: ext, declaredMimeType, expectedMimeTypes: expectedMimes },
      });
    }

    const detected = await fileTypeFromBuffer(buffer);
    if (detected && !expectedMimes.includes(detected.mime)) {
      findings.push({
        rule: "extension-content-mismatch",
        severity: "high",
        message:
          `The file extension "${ext}" does not match the file's actual content, ` +
          `which is "${detected.mime}".`,
        details: { extension: ext, detectedMimeType: detected.mime, expectedMimeTypes: expectedMimes },
      });
    }

    return findings;
  },
};