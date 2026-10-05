/**
 * Runs a file through the WHOLE pipeline at once: all 6 validators,
 * both real scanners (ClamAV, YARA), a CDR, and finally quarantine.
 *
 * Usage:
 *   node check-file.js <path-to-file> <declared-mime-type>
 *
 * Example:
 *   node check-file.js uploads/sample-real.png image/png
 */
import fs from "node:fs";
import path from "node:path";
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
import { ImageSanitizer, PdfSanitizer } from "@secureupload/cdr";
import { evaluateQuarantine, QuarantineStore } from "@secureupload/quarantine";

const CLAMD_SOCKET_PATH = "/var/run/clamav/clamd.ctl";
const YARA_RULES_PATH = "packages/scanners/test/fixtures/test-rules.yar";

const [, , filePath, declaredMimeType] = process.argv;

if (!filePath || !declaredMimeType) {
  console.error("Usage: node check-file.js <path-to-file> <declared-mime-type>");
  process.exit(1);
}

const buffer = fs.readFileSync(filePath);
const context = new PipelineContext({ filename: filePath, declaredMimeType });

// Stage 1: validation — the full validator set
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

// Stage 3: CDR — rebuild a clean copy (images)
let sanitizedInfo = null;
if (declaredMimeType.startsWith("image/")) {
  try {
    const result = await ImageSanitizer.sanitize(buffer);
    for (const finding of result.findings) {
      context.addFinding({ ...finding, stage: "cdr", source: ImageSanitizer.name });
    }
    const { dir, name, ext } = path.parse(filePath);
    const outPath = path.join(dir, `${name}.sanitized${ext}`);
    fs.writeFileSync(outPath, result.buffer);
    sanitizedInfo = `${outPath} (${buffer.length} → ${result.buffer.length} bytes)`;
  } catch (err) {
    console.warn(`  [warning] ${ImageSanitizer.name} could not run: ${err.message}`);
  }
}

// Stage 4: CDR — PDF
if (declaredMimeType === "application/pdf") {
  try {
    const result = await PdfSanitizer.sanitize(buffer);
    for (const finding of result.findings) {
      context.addFinding({ ...finding, stage: "cdr", source: PdfSanitizer.name });
    }
    const { dir, name, ext } = path.parse(filePath);
    const outPath = path.join(dir, `${name}.sanitized${ext}`);
    fs.writeFileSync(outPath, result.buffer);
    sanitizedInfo = sanitizedInfo
      ? `${sanitizedInfo}\n  sanitized copy written to: ${outPath}`
      : `${outPath} (${buffer.length} → ${result.buffer.length} bytes)`;
  } catch (err) {
    console.warn(`  [warning] ${PdfSanitizer.name} could not run: ${err.message}`);
  }
}

// Stage 5: quarantine — the file is stored in the quarantine store and
// scored by policy against every finding collected above. This calls
// evaluateQuarantine + QuarantineStore directly rather than going
// through QuarantinePipeline, because that pipeline would re-run the
// validation stage and duplicate every finding in the report and the
// score.
let quarantineInfo = null;
try {
  const decision = evaluateQuarantine(context.findings);
  const record = await new QuarantineStore().put(
    buffer,
    {
      filename: context.filename,
      declaredMimeType: context.declaredMimeType,
    },
    decision
  );
  quarantineInfo = {
    id: record.id,
    suspicionScore: decision.suspicionScore,
  };
} catch (err) {
  console.warn(`  [warning] quarantine could not run: ${err.message}`);
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

if (sanitizedInfo) {
  console.log(`\n  sanitized copy written to: ${sanitizedInfo}`);
}

if (quarantineInfo) {
  console.log(`  quarantined as: ${quarantineInfo.id}`);
  console.log(`  suspicion score: ${quarantineInfo.suspicionScore}`);
}
