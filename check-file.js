/**
 * Runs a file through the WHOLE pipeline at once: all 5 validators,
 * then both real scanners (ClamAV, YARA) 
 *
 * Usage:
 *   node check-file.js <path-to-file> <declared-mime-type>
 *
 * Example:
 *   node check-file.js uploads/sample-real.png image/png
 */
import fs from "node:fs";
import { PipelineContext, ValidationPipeline } from "@secureupload/core";
import {
  MagicByteValidator,
  FilenameSanitizerValidator,
  MimeMismatchValidator,
  ZipBombGuardValidator,
  PolyglotDetectorValidator,
  ZipSlipGuardValidator,
} from "@secureupload/validators";
import { ScanPipeline, createClamAVScanner, createYaraScanner } from "@secureupload/scanners";

const CLAMD_SOCKET_PATH = "/var/run/clamav/clamd.ctl";
const YARA_RULES_PATH = "packages/scanners/test/fixtures/test-rules.yar";

const [, , filePath, declaredMimeType] = process.argv;

if (!filePath || !declaredMimeType) {
  console.error("Usage: node check-file.js <path-to-file> <declared-mime-type>");
  process.exit(1);
}

const buffer = fs.readFileSync(filePath);
const context = new PipelineContext({ filename: filePath, declaredMimeType });

// Stage 1: validation — same as check-uploads.js
const validationPipeline = new ValidationPipeline([
  MagicByteValidator,
  FilenameSanitizerValidator,
  MimeMismatchValidator,
  ZipBombGuardValidator,
  PolyglotDetectorValidator,
  ZipSlipGuardValidator,
]);
await validationPipeline.run(buffer, context);

// Stage 2: scanning — each scanner run in its OWN ScanPipeline, wrapped
// in its own try/catch, so if clamd isn't running, YARA still gets a
// chance to run instead of the whole script dying early.
const scanners = [
  createClamAVScanner({ socketPath: CLAMD_SOCKET_PATH }),
  createYaraScanner({ rulesPath: YARA_RULES_PATH }),
];

for (const scanner of scanners) {
  try {
    await new ScanPipeline([scanner]).run(buffer, context);
  } catch (err) {
    console.warn(`  [warning] ${scanner.name} could not run: ${err.message}`);
  }
}

// One combined report — the whole point of merging these scripts
console.log(`\n${filePath}  (claiming to be: ${declaredMimeType})`);
if (context.hasFindings) {
  for (const f of context.findings) {
    console.log(`  [${f.severity}] ${f.rule} (${f.source}) — ${f.message}`);
  }
} else {
  console.log("  clean — nothing flagged by any validator or scanner");
}