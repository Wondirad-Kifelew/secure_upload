import yauzl from "yauzl";

/**
 * ZipBombGuardValidator
 * -----------------------
 * Reads a zip/OOXML archive's internal directory — the list of entries
 * and their claimed compressed/uncompressed sizes — WITHOUT extracting
 * or decompressing any actual content. This is what makes it safe to
 * run against a file that might genuinely be a decompression bomb: we
 * only ever read small header metadata, never inflate the payload.
 *
 * Flags two things:
 *   1. Any single entry with an absurd compression ratio (a few KB of
 *      compressed data claiming to expand to megabytes/gigabytes) —
 *      the classic zip-bomb signature.
 *   2. The archive's total claimed uncompressed size, across all
 *      entries, exceeding a hard cap.
 *
 * Scope, on purpose: this only inspects the TOP-LEVEL archive's own
 * entries. If one of those entries is itself another zip (a bomb
 * nested inside a zip inside a zip), catching THAT is the job of the
 * recursion-depth guard already built into PipelineContext
 * (enterNested/exitNested) — that guard applies once something
 * actually starts descending into nested content (e.g. future CDR
 * code), which this validator deliberately does not do.
 *
 * Non-archive files (or corrupt/unreadable ones) simply produce no
 * findings — this validator has nothing to say about them.
 *
 * Exposed as a factory (createZipBombGuardValidator) so limits are
 * configurable — useful for tests, which use tiny buffers and would
 * never trigger the real-world default of 1GB.
 */

const DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES = 1 * 1024 * 1024 * 1024; // 1 GB
const DEFAULT_MAX_COMPRESSION_RATIO = 100; // 100:1 — real-world files rarely exceed this

export function createZipBombGuardValidator({
  maxTotalUncompressedBytes = DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES,
  maxCompressionRatio = DEFAULT_MAX_COMPRESSION_RATIO,
} = {}) {
  return {
    name: "Zip Bomb Guard",

    /**
     * @param {Buffer} buffer
     * @returns {Promise<import('@secureupload/core').ValidationFinding[]>}
     */
    async validate(buffer) {
        console.log("Running zip-bomb guard validator...");
      const findings = [];

      let entries;
      try {
        entries = await readZipEntryMetadata(buffer);
        console.log(`Zip archive has ${entries.length} entries; checking for zip-bomb signatures...`);
    
      } catch {
        // Not a valid/readable zip archive at all — nothing to check.
        return findings;
      }

      let totalUncompressed = 0;

      for (const entry of entries) {
        totalUncompressed += entry.uncompressedSize;

        if (entry.compressedSize > 0) {
          const ratio = entry.uncompressedSize / entry.compressedSize;
          if (ratio > maxCompressionRatio) {
            findings.push({
              rule: "zip-bomb-compression-ratio",
              severity: "extreme",
              message:
                `Archive entry "${entry.fileName}" compresses at ${ratio.toFixed(1)}:1, ` +
                `far beyond what real-world files achieve — a classic decompression-bomb signature.`,
              details: {
                fileName: entry.fileName,
                compressedSize: entry.compressedSize,
                uncompressedSize: entry.uncompressedSize,
                ratio,
              },
            });
          }
        }
      }

      if (totalUncompressed > maxTotalUncompressedBytes) {
        findings.push({
          rule: "zip-bomb-total-size",
          severity: "extreme",
          message:
            `Archive claims a total uncompressed size of ${totalUncompressed} bytes, ` +
            `exceeding the configured limit of ${maxTotalUncompressedBytes} bytes.`,
          details: { totalUncompressedBytes: totalUncompressed, limit: maxTotalUncompressedBytes },
        });
      }

      return findings;
    },
  };
}

/** The default instance, with real-world limits — what other packages import. */
export const ZipBombGuardValidator = createZipBombGuardValidator();

/**
 * Reads only the zip's directory metadata (filenames + sizes) via
 * yauzl. Deliberately never calls anything that would decompress an
 * entry's actual content.
 */
function readZipEntryMetadata(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
      if (err) return reject(err);

      const entries = [];
      zipfile.on("entry", (entry) => {
        entries.push({
          fileName: entry.fileName,
          compressedSize: entry.compressedSize,
          uncompressedSize: entry.uncompressedSize,
        });
        zipfile.readEntry();
      });
      zipfile.on("end", () => resolve(entries));
      zipfile.on("error", reject);

      zipfile.readEntry();
    });
  });
}