import yauzl from "yauzl";

/**
 * DeviceNameGuardValidator
 * ------------------------
 * Checks a ZIP archive's internal entry names BEFORE unzipping to detect
 * forbidden Windows DOS device names:
 *   CON, PRN, AUX, NUL, COM1-COM9, LPT1-LPT9 (with or without an extension,
 *   e.g. "CON.txt", "aux.png", "folder/nul.dat").
 *
 * Why this matters:
 * Windows reserves these legacy device names. Attempting to extract or create
 * any file with these names can hang the server process, cause an unhandled
 * filesystem error, or corrupt disk handles.
 */

// Matches Windows reserved device basenames (case-insensitive)
const DOS_DEVICE_PATTERN = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$/i;

export const DeviceNameGuardValidator = {
  name: "Windows Device Name Guard",

  /**
   * @param {Buffer} buffer
   * @returns {Promise<import('@secureupload/core').ValidationFinding[]>}
   */
  async validate(buffer) {
    console.log("Running device-name guard validator...");
    const findings = [];

    let entries;
    try {
      entries = await readZipEntryNames(buffer);
    } catch {
      // Not a valid/readable zip archive — nothing to check.
      return findings;
    }

    for (const fileName of entries) {
      // Split into path segments to inspect each folder and the filename itself
      const segments = fileName.replace(/\\/g, "/").split("/");

      for (const segment of segments) {
        const trimmed = segment.trim();
        if (DOS_DEVICE_PATTERN.test(trimmed)) {
          findings.push({
            rule: "zip-forbidden-device-name",
            severity: "high",
            message:
              `Archive entry "${fileName}" contains a reserved Windows DOS device name ` +
              `("${trimmed}"). Extracting this file on Windows can crash the server ` +
              `filesystem or lock up background workers.`,
            details: { fileName, forbiddenSegment: trimmed },
          });
          // One finding per entry is enough
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
