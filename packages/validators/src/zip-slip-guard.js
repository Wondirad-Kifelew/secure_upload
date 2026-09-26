import yauzl from "yauzl";

/**
 * ZipSlipGuardValidator
 * ----------------------
 * Reads a zip archive's internal directory — the list of entry NAMES —
 * without extracting or decompressing any content. Checks whether any
 * entry's name would escape the intended extraction folder if the
 * archive were ever unpacked (the "Zip Slip" vulnerability).
 */

const PATH_TRAVERSAL_PATTERN = /\.\.[\\/]/;
const WINDOWS_DRIVE_PATTERN = /^[a-zA-Z]:\\/;

export const ZipSlipGuardValidator = {
  name: "Zip Slip Guard",

  async validate(buffer) {
    console.log("Running zip-slip guard validator...");
    const findings = [];

    let entries;
    try {
      entries = await readZipEntryNames(buffer);
    } catch {
      return findings;
    }

    for (const fileName of entries) {
      const isTraversal = PATH_TRAVERSAL_PATTERN.test(fileName);
      const isAbsolute = fileName.startsWith("/") || WINDOWS_DRIVE_PATTERN.test(fileName);

      if (isTraversal || isAbsolute) {
        findings.push({
          rule: "zip-slip-path-traversal",
          severity: "extreme",
          message:
            `Archive entry "${fileName}" contains a path traversal sequence or an ` +
            `absolute path. Extracting this archive naively could write this file ` +
            `outside the intended upload directory (Zip Slip).`,
          details: { fileName },
        });
      }
    }

    return findings;
  },
};

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