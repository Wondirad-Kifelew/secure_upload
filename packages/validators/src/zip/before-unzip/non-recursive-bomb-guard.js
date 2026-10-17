import yauzl from "yauzl";

/**
 * NonRecursiveBombGuardValidator
 * --------------------------------
 * Detects "non-recursive" zip bombs (David Fifield / BAMSoftware technique).
 *
 * Traditional zip bombs use nested archives (zips inside zips) or extreme
 * individual compression ratios. In contrast, non-recursive zip bombs contain
 * hundreds or thousands of distinct entries whose local header/data offsets
 * overlap or point to the EXACT SAME compressed byte payload.
 *
 * This validator inspects Central Directory metadata WITHOUT decompressing
 * payload data:
 *   1. Identical local header offsets across different entries (offset reuse).
 *   2. Overlapping entry byte ranges [offset, offset + headerSize + compressedSize].
 *
 * Scope:
 *   - Runs before extraction in the `before-unzip` pipeline.
 *   - Safe metadata-only read via yauzl (lazyEntries, no decompression).
 */

export const NonRecursiveBombGuardValidator = {
  name: "Non-Recursive Zip Bomb Guard",

  /**
   * @param {Buffer} buffer
   * @returns {Promise<import('@secureupload/core').ValidationFinding[]>}
   */
  async validate(buffer) {
    console.log("Running non-recursive-bomb guard validator...");
    const findings = [];

    let entries;
    try {
      entries = await readZipEntriesWithOffsets(buffer);
    } catch {
      // Not a valid/readable zip archive — nothing to check.
      return findings;
    }

    if (!entries || entries.length < 2) {
      return findings;
    }

    // Map each offset to entries that start at that exact local header offset
    const offsetMap = new Map();
    for (const entry of entries) {
      const offset = entry.relativeOffsetOfLocalHeader;
      if (!offsetMap.has(offset)) {
        offsetMap.set(offset, []);
      }
      offsetMap.get(offset).push(entry);
    }

    // 1. Check for identical local header offsets (direct offset reuse)
    for (const [offset, matchingEntries] of offsetMap.entries()) {
      if (matchingEntries.length > 1) {
        findings.push({
          rule: "zip-non-recursive-bomb-shared-offset",
          severity: "extreme",
          message:
            `Multiple archive entries (${matchingEntries.length}) share the identical local ` +
            `header byte offset (${offset}). This is a signature of a non-recursive decompression ` +
            `bomb designed to inflate overlapping data streams into massive output.`,
          details: {
            offset,
            entriesCount: matchingEntries.length,
            fileNames: matchingEntries.slice(0, 5).map((e) => e.fileName),
          },
        });
        // If we found identical offsets, that is already a confirmed signature
        return findings;
      }
    }

    // 2. Check for overlapping byte ranges [offset, offset + compressedSize]
    // Sort entries by local header offset to detect range collisions
    const sorted = [...entries].sort(
      (a, b) => a.relativeOffsetOfLocalHeader - b.relativeOffsetOfLocalHeader
    );

    for (let i = 0; i < sorted.length - 1; i++) {
      const current = sorted[i];
      const next = sorted[i + 1];

      // If current entry has compressed data that extends into the next entry's offset
      if (current.compressedSize > 0) {
        const currentDataStart = current.relativeOffsetOfLocalHeader;
        const currentDataEnd = currentDataStart + current.compressedSize;

        if (currentDataEnd > next.relativeOffsetOfLocalHeader) {
          findings.push({
            rule: "zip-non-recursive-bomb-overlapping-range",
            severity: "extreme",
            message:
              `Archive entry "${current.fileName}" byte range overlaps with "${next.fileName}". ` +
              `Overlapping entry payloads are abnormal and indicative of a non-recursive zip bomb.`,
            details: {
              currentEntry: current.fileName,
              nextEntry: next.fileName,
              currentOffset: current.relativeOffsetOfLocalHeader,
              nextOffset: next.relativeOffsetOfLocalHeader,
            },
          });
          break;
        }
      }
    }

    return findings;
  },
};

/**
 * Reads entries along with their local header offset and compressed size.
 * Safe, lazy metadata read only.
 */
function readZipEntriesWithOffsets(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(
      buffer,
      { lazyEntries: true, decodeStrings: false, validateEntrySizes: false },
      (err, zipfile) => {
        if (err) return reject(err);

        const entries = [];
        zipfile.on("entry", (entry) => {
          entries.push({
            fileName: entry.fileName.toString("utf8"),
            relativeOffsetOfLocalHeader: entry.relativeOffsetOfLocalHeader,
            compressedSize: entry.compressedSize,
            uncompressedSize: entry.uncompressedSize,
          });
          zipfile.readEntry();
        });

        zipfile.on("end", () => resolve(entries));
        zipfile.on("error", reject);

        zipfile.readEntry();
      }
    );
  });
}
