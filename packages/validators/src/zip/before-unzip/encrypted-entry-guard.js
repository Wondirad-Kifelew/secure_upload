import yauzl from "yauzl";

/**
 * EncryptedEntryGuardValidator
 * -----------------------------
 * Reads a zip archive's internal directory — just each entry's general
 * purpose bit flags — without extracting or decompressing anything.
 * Flags any entry that is encrypted (password-protected).
 *
 * Why this matters: every other guard in this folder reads a zip's
 * entry list or limited metadata to decide if something looks unsafe.
 * An encrypted entry can't be inspected by ANY of them — not by this
 * pipeline's scanners, not by a human reviewer — until someone supplies
 * the correct password. An attacker can hide a zip bomb, malware, or
 * anything else inside a password-protected entry and it will sail
 * through every other check in this folder untouched, because nothing
 * here can see inside it. Flagging it doesn't prove it's malicious —
 * legitimate encrypted archives exist — but it means "we could not
 * verify this entry is safe," which this pipeline should never pass
 * through silently.
 *
 * Detected via bit 0 of the entry's general purpose bit flag, which
 * the zip format reserves to mean "this entry is encrypted."
 */

export const EncryptedEntryGuardValidator = {
  name: "Encrypted Entry Guard",

  async validate(buffer) {
    console.log("Running encrypted-entry guard validator...");
    const findings = [];

    let entries;
    try {
      entries = await readZipEntryMetadata(buffer);
    } catch {
      return findings;
    }

    for (const entry of entries) {
      const isEncrypted = (entry.generalPurposeBitFlag & 0x0001) !== 0;

      if (isEncrypted) {
        findings.push({
          rule: "zip-encrypted-entry",
          severity: "high",
          message:
            `Archive entry "${entry.fileName}" is encrypted/password-protected. ` +
            `None of this pipeline's checks or scanners can inspect its real ` +
            `content without the password, so it cannot be verified safe.`,
          details: { fileName: entry.fileName },
        });
      }
    }

    return findings;
  },
};

function readZipEntryMetadata(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true, decodeStrings: false, validateEntrySizes: false }, (err, zipfile) => {
      if (err) return reject(err);

      const entries = [];
      zipfile.on("entry", (entry) => {
        entries.push({
          fileName: entry.fileName.toString("utf8"),
          generalPurposeBitFlag: entry.generalPurposeBitFlag,
        });
        zipfile.readEntry();
      });
      zipfile.on("end", () => resolve(entries));
      zipfile.on("error", reject);

      zipfile.readEntry();
    });
  });
}