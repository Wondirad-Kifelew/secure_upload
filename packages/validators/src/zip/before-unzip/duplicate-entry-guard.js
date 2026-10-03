

import yauzl from "yauzl";
 
/**
 * DuplicateEntryGuardValidator
 * -----------------------------
 * Reads a zip archive's internal directory — just the entry NAMES —
 * without extracting or decompressing anything. Flags archives where
 * two or more entries resolve to the same path once case-folded and
 * slash-normalized. This matters because different unzip tools and
 * operating systems resolve near-identical names differently: on a
 * case-insensitive filesystem, "config.json" and "Config.json" land
 * on the same file, so whichever entry is written LAST silently wins.
 * An attacker can exploit this to smuggle a malicious file in under a
 * name that looks like a harmless duplicate, overwriting what a human
 * reviewer or scanner saw first.
 *
 * Same safe, metadata-only read as zip-bomb-guard.js, zip-slip-guard.js
 * and entry-count-guard.js — this one just compares normalized names.
 */
 
export const DuplicateEntryGuardValidator = {
  name: "Duplicate Entry Guard",
 
  async validate(buffer) {
    console.log("Running duplicate-entry guard validator...");
    const findings = [];
 
    let entries;
    try {
      entries = await readZipEntryNames(buffer);
    } catch {
      // Not a valid/readable zip archive at all — nothing to check.
      return findings;
    }
 
    const seen = new Map(); // normalizedName -> [originalNames]
    for (const fileName of entries) {
      const normalized = normalize(fileName);
      if (!seen.has(normalized)) {
        seen.set(normalized, []);
      }
      seen.get(normalized).push(fileName);
    }
 
    for (const [normalized, originalNames] of seen) {
      if (originalNames.length > 1) {
        findings.push({
          rule: "zip-duplicate-entry-name",
          severity: "medium",
          message:
            `Archive contains ${originalNames.length} entries that resolve to the ` +
            `same path once case and separators are normalized: ` +
            `${originalNames.map((n) => `"${n}"`).join(", ")}. Different extraction ` +
            `tools may resolve these differently, letting a later entry silently ` +
            `overwrite an earlier one.`,
          details: { normalized, originalNames },
        });
      }
    }
 
    return findings;
  },
};
 
function normalize(fileName) {
  return fileName.toLowerCase().replace(/\\/g, "/");
}
 
/** Reads only entry filenames via yauzl — never decompresses content. */
function readZipEntryNames(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
      if (err) return reject(err);
 
      const names = [];
      zipfile.on("entry", (entry) => {
        names.push(entry.fileName);
        zipfile.readEntry();
      });
      zipfile.on("end", () => resolve(names));
      zipfile.on("error", reject);
 
      zipfile.readEntry();
    });
  });
}
 
