import yauzl from "yauzl";

/**
 * UnicodeControlGuardValidator
 * -----------------------------
 * Inspects entry filenames in ZIP archives BEFORE unzipping to detect:
 *  1. Right-to-Left Override (RLO / RTLO) characters (\u202E, \u202D, \u202C, \u2066-\u2069)
 *     used to flip file extensions visually (e.g. turning "report[RLO]fdp.exe" into "reportexe.pdf").
 *  2. Null bytes (\u0000) used for poison-null-byte path truncation.
 *  3. Non-printable control characters (\u0001-\u001F and \u007F-\u009F) that can
 *     break filesystem parsers and logging.
 */

// Matches RTLO, LTR/RTL embedding, directional isolates, and null/control characters
const DANGEROUS_UNICODE_PATTERN = /[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/;

export const UnicodeControlGuardValidator = {
  name: "Unicode Control & Spoof Guard",

  /**
   * @param {Buffer} buffer
   * @returns {Promise<import('@secureupload/core').ValidationFinding[]>}
   */
  async validate(buffer) {
    console.log("Running unicode-control guard validator...");
    const findings = [];

    let entries;
    try {
      entries = await readZipEntryNames(buffer);
    } catch {
      // Not a valid/readable zip archive — nothing to check.
      return findings;
    }

    for (const fileName of entries) {
      if (DANGEROUS_UNICODE_PATTERN.test(fileName)) {
        const hasRtlo = /[\u202A-\u202E\u2066-\u2069]/.test(fileName);
        const hasNullByte = fileName.includes("\0");

        let threatDesc = "hidden control characters";
        if (hasRtlo) {
          threatDesc = "a Right-to-Left Override (RTLO) spoofing character designed to disguise executable extensions";
        } else if (hasNullByte) {
          threatDesc = "a null-byte (\\0) poison sequence designed to truncate file extensions";
        }

        findings.push({
          rule: "zip-entry-unicode-spoof",
          severity: "high",
          message:
            `Archive entry contains ${threatDesc}. Extracting this file could trick ` +
            `users or bypass file extension security checks.`,
          details: { fileName, hasRtlo, hasNullByte },
        });
      }
    }

    return findings;
  },
};

/** Reads only entry filenames via yauzl — never decompresses content. */
function readZipEntryNames(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(
      buffer,
      { lazyEntries: true, decodeStrings: false, validateEntrySizes: false },
      (err, zipfile) => {
        if (err) return reject(err);

        const names = [];
        zipfile.on("entry", (entry) => {
          names.push(entry.fileName.toString("utf8"));
          zipfile.readEntry();
        });

        zipfile.on("end", () => resolve(names));
        zipfile.on("error", reject);

        zipfile.readEntry();
      }
    );
  });
}
