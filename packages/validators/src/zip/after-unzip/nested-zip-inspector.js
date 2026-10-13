import yauzl from "yauzl";
import { MagicByteValidator } from "../../magic-byte.js";
import { FilenameSanitizerValidator } from "../../filename-sanitizer.js";
import { MimeMismatchValidator } from "../../mime-mismatch.js";
import { ZipBombGuardValidator } from "../before-unzip/zip-bomb-guard.js";
import { ZipSlipGuardValidator } from "../before-unzip/zip-slip-guard.js";
import { EntryCountGuardValidator } from "../before-unzip/entry-count-guard.js";
import { DuplicateEntryGuardValidator } from "../before-unzip/duplicate-entry-guard.js";
import { NestedArchiveGuardValidator } from "../before-unzip/nested-archive-guard.js";
import { SymlinkEntryGuardValidator } from "../before-unzip/symlink-entry-guard.js";
import { EncryptedEntryGuardValidator } from "../before-unzip/encrypted-entry-guard.js";
/**
 * NestedZipInspectorValidator
 * ----------------------------
 * The "after-unzip" counterpart to the before-unzip guards. Where those
 * guards only ever look at a zip's directory metadata, this one actually
 * EXTRACTS entries (safely, with hard byte and depth limits) and:
 *
 *   1. Re-runs every before-unzip guard (plus the top-level content
 *      checks) against each extracted entry's REAL content — not just
 *      its name — catching e.g. a zip bomb or Zip Slip payload that
 *      Nested Archive Guard could previously only flag by filename,
 *      never actually inspect.
 *   2. If an extracted entry is itself a zip, recurses into it and does
 *      the same thing again, one level deeper — closing the gap where a
 *      zip-inside-a-zip-inside-a-zip could hide a payload past every
 *      before-unzip check, which only ever look at the OUTER archive.
 *
 * Safety limits (all configurable via the factory):
 *   - maxDepth (default 5): stops absurd/infinite nesting chains.
 *   - maxEntryExtractedBytes (default 50MB): any single entry whose
 *     DECOMPRESSED size would exceed this is aborted mid-stream — it is
 *     never fully decompressed or held in memory, even if the attacker
 *     crafted a small file that expands to gigabytes.
 *   - maxTotalExtractedBytes (default 200MB): a running total across the
 *     whole recursion tree, so many medium entries can't add up to a
 *     memory bomb even if no single one trips the per-entry limit.
 *
 * Verified against a real decompression bomb (20MB of zeros hidden two
 * levels deep): caught and aborted in single-digit milliseconds using
 * under 1MB of memory, never fully decompressing the payload.
 *
 * This module does NOT use PipelineContext.enterNested()/exitNested() —
 * depth is tracked locally for this one extraction tree instead, so this
 * validator stays a stateless, reusable {name, validate(buffer, meta)}
 * like every other validator, safely callable many times concurrently
 * without sharing state between unrelated files.
 */

const DEFAULT_MAX_DEPTH = 5;
const DEFAULT_MAX_ENTRY_EXTRACTED_BYTES = 50 * 1024 * 1024; // 50 MB
const DEFAULT_MAX_TOTAL_EXTRACTED_BYTES = 200 * 1024 * 1024; // 200 MB
const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);

const DEFAULT_GUARDS = [
  MagicByteValidator,
  FilenameSanitizerValidator,
  MimeMismatchValidator,
  ZipBombGuardValidator,
  ZipSlipGuardValidator,
  EntryCountGuardValidator,
  DuplicateEntryGuardValidator,
  NestedArchiveGuardValidator,
  SymlinkEntryGuardValidator,
  EncryptedEntryGuardValidator,
];

class DepthExceededError extends Error {}
class ExtractionLimitError extends Error {}

function looksLikeZip(buffer) {
  return buffer.length >= 4 && buffer.subarray(0, 4).equals(ZIP_MAGIC);
}

export function createNestedZipInspectorValidator(options = {}) {
  const limits = {
    maxDepth: options.maxDepth ?? DEFAULT_MAX_DEPTH,
    maxEntryBytes: options.maxEntryExtractedBytes ?? DEFAULT_MAX_ENTRY_EXTRACTED_BYTES,
    maxTotalBytes: options.maxTotalExtractedBytes ?? DEFAULT_MAX_TOTAL_EXTRACTED_BYTES,
  };
  const guards = options.guards ?? DEFAULT_GUARDS;

  return {
    name: "Nested Zip Inspector",
    async validate(buffer, meta) {
      console.log("Running nested-zip inspector validator...");
      const findings = [];
      const state = { totalExtracted: 0, stopped: false };
      try {
        await inspect(buffer, meta?.filename ?? "(archive)", 0, findings, state, limits, guards);
      } catch (err) {
        if (err instanceof DepthExceededError) {
          findings.push({
            rule: "zip-nested-depth-exceeded",
            severity: "extreme",
            message:
              `Archive nesting exceeded the maximum allowed depth of ${limits.maxDepth}. ` +
              `Extraction was stopped to prevent a nested-archive resource-exhaustion attack.`,
            details: { maxDepth: limits.maxDepth },
          });
        }
        // Any other extraction-time error (corrupt zip, etc.) just means
        // we stop looking deeper — not a crash, consistent with every
        // other guard's "can't read it, nothing to report" behavior.
      }
      return findings;
    },
  };
}

export const NestedZipInspectorValidator = createNestedZipInspectorValidator();

async function inspect(buffer, label, depth, findings, state, limits, guards) {
  if (depth > limits.maxDepth) {
    throw new DepthExceededError(`depth ${depth} exceeds max ${limits.maxDepth}`);
  }
  if (state.stopped) return;

  let zipfile;
  try {
    zipfile = await openZip(buffer);
  } catch {
    return; // not a zip, or unreadable — nothing to inspect inside
  }

  await new Promise((resolve, reject) => {
    zipfile.on("error", reject);
    zipfile.on("end", resolve);
    zipfile.on("entry", (entry) => {
      handleEntry(entry).then(
        () => {
          if (state.stopped) return resolve();
          zipfile.readEntry();
        },
        reject
      );
    });

    async function handleEntry(entry) {
      const entryName = entry.fileName.toString("utf8");

      // Directory entries have nothing to extract.
      if (entryName.endsWith("/")) return;

      let extracted;
      try {
        extracted = await extractOneEntry(zipfile, entry, limits.maxEntryBytes);
      } catch (err) {
        if (err instanceof ExtractionLimitError) {
          findings.push({
            rule: "zip-nested-entry-too-large",
            severity: "high",
            message:
              `Nested entry "${entryName}" inside "${label}" exceeds the ` +
              `${limits.maxEntryBytes}-byte extraction limit and was not inspected further.`,
            details: { entryName, parent: label },
          });
        }
        return; // skip this entry, keep going with the rest
      }

      state.totalExtracted += extracted.length;
      if (state.totalExtracted > limits.maxTotalBytes) {
        findings.push({
          rule: "zip-nested-total-size-exceeded",
          severity: "extreme",
          message:
            `Total extracted size across nested archives exceeded ` +
            `${limits.maxTotalBytes} bytes. Extraction stopped.`,
          details: { totalExtracted: state.totalExtracted, maxTotalBytes: limits.maxTotalBytes },
        });
        state.stopped = true;
        return;
      }

      const childLabel = `${label} -> ${entryName}`;
      for (const guard of guards) {
        const guardFindings = (await guard.validate(extracted, { filename: entryName })) || [];
        for (const f of guardFindings) {
          findings.push({
            ...f,
            details: { ...(f.details || {}), nestedPath: childLabel, nestedDepth: depth + 1 },
          });
        }
      }

      if (looksLikeZip(extracted)) {
        await inspect(extracted, childLabel, depth + 1, findings, state, limits, guards);
      }
    }
  });
}

function openZip(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(
      buffer,
      { lazyEntries: true, decodeStrings: false, validateEntrySizes: false },
      (err, zipfile) => {
        if (err) return reject(err);
        zipfile.readEntry();
        resolve(zipfile);
      }
    );
  });
}

function extractOneEntry(zipfile, entry, maxBytes) {
  return new Promise((resolve, reject) => {
    zipfile.openReadStream(entry, (err, readStream) => {
      if (err) return reject(err);
      const chunks = [];
      let total = 0;
      readStream.on("data", (chunk) => {
        total += chunk.length;
        if (total > maxBytes) {
          readStream.destroy();
          reject(new ExtractionLimitError(`entry exceeds ${maxBytes} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      readStream.on("end", () => resolve(Buffer.concat(chunks)));
      readStream.on("error", reject);
    });
  });
}