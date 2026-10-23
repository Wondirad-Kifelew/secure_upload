import yauzl from "yauzl";

/**
 * ArchiveIntegrityGuardValidator
 * ------------------------------
 * Before-unzip guard that verifies any file claiming to be a ZIP archive
 * (based on magic signature PK\x03\x04 or empty PK\x05\x06) can actually
 * be opened and has readable central directory / entry records.
 *
 * Catches truncated, incomplete, or corrupted ZIP uploads before subsequent
 * validators or processing stages fail silently or skip inspection.
 */

function hasZipSignature(buffer) {
  if (!buffer || buffer.length < 4) return false;
  return (
    buffer[0] === 0x50 &&
    buffer[1] === 0x4b &&
    ((buffer[2] === 0x03 && buffer[3] === 0x04) || (buffer[2] === 0x05 && buffer[3] === 0x06))
  );
}

function readAllEntries(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(
      buffer,
      { lazyEntries: true, decodeStrings: false, validateEntrySizes: false },
      (err, zipfile) => {
        if (err) return reject(err);
        zipfile.readEntry();
        zipfile.on("entry", () => {
          zipfile.readEntry();
        });
        zipfile.on("end", () => resolve());
        zipfile.on("error", (e) => reject(e));
      }
    );
  });
}

export const ArchiveIntegrityGuardValidator = {
  name: "Archive Integrity Guard",
  async validate(buffer) {
    console.log("Running archive-integrity guard validator...");
    const findings = [];
    if (!hasZipSignature(buffer)) {
      return findings;
    }

    try {
      await readAllEntries(buffer);
    } catch (err) {
      findings.push({
        rule: "archive-unreadable",
        severity: "high",
        message:
          `The file claims to be a ZIP archive but cannot be read or is corrupted ` +
          `(${err?.message || err}), so its contents were not inspected.`,
        details: { reason: err?.message || String(err) },
      });
    }

    return findings;
  },
};
