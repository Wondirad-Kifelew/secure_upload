import yauzl from "yauzl";

/**
 * NestedArchiveGuardValidator
 * ----------------------------
 * Reads a zip archive's internal directory — just the entry NAMES —
 * and flags any entry that is ITSELF an archive-format file (another
 * zip, a jar, an Office document, an apk, etc). This is a name-based
 * heuristic, not true recursive decompression: actually walking into
 * a nested zip to measure real depth would require decompressing that
 * entry's content, which breaks the metadata-only safety rule this
 * whole before-unzip/ folder follows. True recursive depth checking
 * belongs to a later stage (CDR), where content is already being
 * decompressed under controlled conditions — see
 * PipelineContext.enterNested()/exitNested() in core, built for
 * exactly that future use.
 *
 * Still useful on its own: a zip containing another zip is a classic
 * first step in nested-archive attacks (a bomb or slip hidden one
 * level deeper than scanners expect to look).
 */

const ARCHIVE_EXTENSIONS = [
  ".zip", ".jar", ".war", ".ear", ".apk",
  ".docx", ".xlsx", ".pptx", // OOXML files are zips internally
  ".tar", ".gz", ".7z", ".rar",
];

export const NestedArchiveGuardValidator = {
  name: "Nested Archive Guard",

  async validate(buffer) {
    console.log("Running nested-archive guard validator...");
    const findings = [];

    let entries;
    try {
      entries = await readZipEntryNames(buffer);
    } catch {
      return findings;
    }

    for (const fileName of entries) {
      const lower = fileName.toLowerCase();
      const matchedExt = ARCHIVE_EXTENSIONS.find((ext) => lower.endsWith(ext));

      if (matchedExt) {
        findings.push({
          rule: "zip-nested-archive",
          severity: "medium",
          message:
            `Archive entry "${fileName}" is itself an archive-format file ` +
            `(${matchedExt}). Nested archives are a common technique to hide a ` +
            `zip bomb or Zip Slip payload one level deeper than a scanner expects ` +
            `to check — this entry's own contents have not been inspected.`,
          details: { fileName, matchedExtension: matchedExt },
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