import yauzl from "yauzl";

/**
 * TrailingCharacterGuardValidator
 * --------------------------------
 * Checks entry names in ZIP archives BEFORE unzipping to detect filenames
 * or directory segments ending with trailing spaces (" ") or dots (".").
 *
 * Why this matters:
 * Windows filesystems silently strip trailing dots and spaces from filenames
 * upon creation. An attacker can name a payload "virus.exe." or "payload.exe "
 * to bypass naive file-extension checks (thinking it is not an executable).
 * Once unzipped on Windows, the OS truncates the trailing character, turning
 * the file into an executable "virus.exe".
 */

// Matches path segments ending in a dot or whitespace
const TRAILING_DOT_OR_SPACE_PATTERN = /[. ]$/;

export const TrailingCharacterGuardValidator = {
  name: "Trailing Character Guard",

  /**
   * @param {Buffer} buffer
   * @returns {Promise<import('@secureupload/core').ValidationFinding[]>}
   */
  async validate(buffer) {
    console.log("Running trailing-character guard validator...");
    const findings = [];

    let entries;
    try {
      entries = await readZipEntryNames(buffer);
    } catch {
      // Not a valid/readable zip archive — nothing to check.
      return findings;
    }

    for (const fileName of entries) {
      // Split path into segments so we check both directories and files
      // Ignore trailing slash for legitimate directories before splitting
      const normalizedPath = fileName.replace(/\\/g, "/").replace(/\/+$/, "");
      const segments = normalizedPath.split("/");

      for (const segment of segments) {
        if (!segment || segment === "." || segment === "..") {
          continue;
        }

        if (TRAILING_DOT_OR_SPACE_PATTERN.test(segment)) {
          const isDot = segment.endsWith(".");
          const charType = isDot ? "dot ('.')" : "whitespace (' ')";

          findings.push({
            rule: "zip-entry-trailing-character",
            severity: "high",
            message:
              `Archive entry "${fileName}" contains a segment ("${segment}") ending with a trailing ` +
              `${charType}. On Windows, trailing dots and spaces are stripped during extraction, ` +
              `which attackers use to bypass extension security filters.`,
            details: { fileName, suspiciousSegment: segment },
          });
          // One finding per entry is sufficient
          break;
        }
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
