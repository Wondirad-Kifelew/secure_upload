import yauzl from "yauzl";

/**
 * SymlinkEntryGuardValidator
 * ---------------------------
 * Reads a zip archive's internal directory — just each entry's stored
 * Unix file-mode bits — without extracting or decompressing anything.
 * Flags any entry that is a symlink rather than a real file.
 *
 * Why this matters: a zip entry can be a symlink pointing anywhere on
 * the filesystem (e.g. a entry named "config.json" that is actually a
 * symlink to "/etc/shadow"). If something later reads "config.json"
 * expecting file content, it may actually follow the link and read a
 * completely different, unintended file. This is a different attack
 * from Zip Slip: Zip Slip is about where an entry's OWN name writes
 * to; this is about an entry being a POINTER rather than real content.
 *
 * Unix zip tools store file permissions in the upper 16 bits of each
 * entry's "external file attributes" field. A symlink's mode has the
 * S_IFLNK bit pattern (0xA000) in that field. Windows-created zips
 * don't set this at all, so this check only fires for entries that
 * explicitly declare themselves as symlinks.
 */

const S_IFLNK = 0xa000;
const S_IFMT = 0xf000;

export const SymlinkEntryGuardValidator = {
  name: "Symlink Entry Guard",

  async validate(buffer) {
    console.log("Running symlink-entry guard validator...");
    const findings = [];

    let entries;
    try {
      entries = await readZipEntryMetadata(buffer);
    } catch {
      return findings;
    }

    for (const entry of entries) {
      const unixMode = entry.externalFileAttributes >>> 16;
      const isSymlink = (unixMode & S_IFMT) === S_IFLNK;

      if (isSymlink) {
        findings.push({
          rule: "zip-symlink-entry",
          severity: "extreme",
          message:
            `Archive entry "${entry.fileName}" is a symlink, not a real file. ` +
            `Extracting it naively could create a link pointing anywhere on the ` +
            `filesystem, so reading this "file" later may actually read a ` +
            `completely different, attacker-chosen target.`,
          details: { fileName: entry.fileName },
        });
      }
    }

    return findings;
  },
};

function readZipEntryMetadata(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
      if (err) return reject(err);

      const entries = [];
      zipfile.on("entry", (entry) => {
        entries.push({
          fileName: entry.fileName,
          externalFileAttributes: entry.externalFileAttributes,
        });
        zipfile.readEntry();
      });
      zipfile.on("end", () => resolve(entries));
      zipfile.on("error", reject);

      zipfile.readEntry();
    });
  });
}