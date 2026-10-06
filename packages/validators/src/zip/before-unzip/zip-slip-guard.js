import yauzl from "yauzl";

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
          message: `Archive entry "${fileName}" contains a path traversal sequence or an absolute path. Extracting this archive naively could write this file outside the intended upload directory (Zip Slip).`,
          details: { fileName },
        });
      }
    }
    return findings;
  },
};

function readZipEntryNames(buffer) {
  return new Promise((resolve, reject) => {
    // decodeStrings: false — read raw names ourselves so yauzl's own
    // path-safety check doesn't abort reading before WE get to inspect them.
    yauzl.fromBuffer(buffer, { lazyEntries: true, decodeStrings: false }, (err, zipfile) => {
      if (err) return reject(err);
      const names = [];
      zipfile.readEntry();
      zipfile.on("entry", (entry) => {
        names.push(entry.fileName.toString("utf8"));
        zipfile.readEntry();
      });
      zipfile.on("end", () => resolve(names));
      zipfile.on("error", (e) => reject(e));
    });
  });
}