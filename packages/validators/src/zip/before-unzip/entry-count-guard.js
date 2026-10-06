
import yauzl from "yauzl";
 
/**
 * EntryCountGuardValidator
 * -------------------------
 * Reads a zip archive's internal directory — just the COUNT of entries —
 * without extracting or decompressing anything. Flags archives with an
 * absurd number of packed entries, a known resource-exhaustion attack:
 * extracting millions of tiny (even empty) files can exhaust a
 * filesystem's inode limit or simply take the server down for minutes,
 * regardless of how small each individual entry is.
 *
 * Same safe, metadata-only read as zip-bomb-guard.js and
 * zip-slip-guard.js — this one just counts entries instead of checking
 * their sizes or names.
 */
 
const MAX_ENTRY_COUNT = 10_000;
 
export const EntryCountGuardValidator = {
  name: "Entry Count Guard",
 
  async validate(buffer) {
    console.log("Running entry-count guard validator...");
    const findings = [];
 
    let entryCount;
    try {
      entryCount = await countZipEntries(buffer);
    } catch {
      // Not a valid/readable zip archive at all — nothing to check.
      return findings;
    }
 
    if (entryCount > MAX_ENTRY_COUNT) {
      findings.push({
        rule: "zip-entry-count-excessive",
        severity: "high",
        message:
          `Archive contains ${entryCount} entries, exceeding the safe limit of ` +
          `${MAX_ENTRY_COUNT}. Extracting an archive with an excessive entry count ` +
          `can exhaust filesystem inodes or server resources, even if each entry ` +
          `is tiny.`,
        details: { entryCount, maxAllowed: MAX_ENTRY_COUNT },
      });
    }
 
    return findings;
  },
};
 
/** Reads only the entry count via yauzl — never decompresses content. */
function countZipEntries(buffer) {
  return new Promise((resolve, reject) => {
      yauzl.fromBuffer(buffer, { lazyEntries: true, decodeStrings: false }, (err, zipfile) => {
      if (err) return reject(err);
 
      let count = 0;
      zipfile.on("entry", () => {
        count += 1;
        zipfile.readEntry();
      });
      zipfile.on("end", () => resolve(count));
      zipfile.on("error", reject);
 
      zipfile.readEntry();
    });
  });
}
 
