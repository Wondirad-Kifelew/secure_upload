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
  EntryCountGuardValidator,
  DuplicateEntryGuardValidator,
  NestedArchiveGuardValidator,
  SymlinkEntryGuardValidator,
  EncryptedEntryGuardValidator,
  NonRecursiveBombGuardValidator,
  DeviceNameGuardValidator,
  UnicodeControlGuardValidator,
  TrailingCharacterGuardValidator,
  DangerousExtensionGuardValidator,
  NestedZipInspectorValidator
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
  EntryCountGuardValidator,
  DuplicateEntryGuardValidator,
  NestedArchiveGuardValidator,
  SymlinkEntryGuardValidator,
  EncryptedEntryGuardValidator,
  NonRecursiveBombGuardValidator,
  DeviceNameGuardValidator,
  UnicodeControlGuardValidator,
  TrailingCharacterGuardValidator,
  DangerousExtensionGuardValidator,
]);
await validationPipeline.run(buffer, context);

// Stage 1b: nested-zip inspection — only dig into nested archives if the
// outer zip isn't already being rejected. If it already has a high/extreme
// finding, the file is rejected regardless, so deeper inspection adds
// nothing. If it only has low/medium findings, the outcome isn't decided
// yet, so we still want to know if something worse is hiding inside.
const HIGH_SEVERITY = ["high", "extreme"];
const hasHighOrExtremeFinding = context.findings.some((f) =>
  HIGH_SEVERITY.includes(f.severity)
);

if (hasHighOrExtremeFinding) {
  context.addFinding({
    rule: "zip-nested-inspection-skipped",
    severity: "low",
    stage: "validation",
    source: "Nested Zip Inspector",
    message:
      "Nested zip inspection was skipped because the archive already has a " +
      "high/extreme finding. The file is being rejected regardless, so deeper " +
      "inspection was not performed.",
    details: { reason: "high-or-extreme-finding-present" },
  });
} else {
  const nestedFindings = await NestedZipInspectorValidator.validate(buffer, {
    filename: context.filename,
  });
  for (const finding of nestedFindings) {
    context.addFinding(finding);
  }
}

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

// One combined report — the whole point of merging these scripts.
// Findings are sorted worst-to-least-bad (extreme -> high -> medium -> low)
// so the scariest problems are always at the top, and any finding that
// came from inside a nested archive shows exactly where it was found.
console.log(`\n${filePath}  (claiming to be: ${declaredMimeType})`);
if (context.hasFindings) {
  const SEVERITY_ORDER = ["extreme", "high", "medium", "low"];
  const sortedFindings = [...context.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  for (const f of sortedFindings) {
    const location = f.details?.nestedPath
      ? `\n      location: ${f.details.nestedPath}`
      : "";
    console.log(`  [${f.severity}] ${f.rule} (${f.source}) — ${f.message}${location}`);
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