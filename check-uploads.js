/**
 * Point this at any one file and tell it what the "browser" is
 * claiming the file's type is. Simulates the two things a real upload
 * gives your server: the file's bytes (read here from disk instead of
 * over a network — a Buffer looks identical either way) and the
 * declared type (which you supply by hand here, standing in for
 * whatever a browser would send — and which is exactly the thing an
 * attacker can lie about).
 *
 * Usage:
 *   node check-uploads.js <path-to-file> <declared-mime-type>
 *
 * Example:
 *   node check-uploads.js uploads/sample-real.png image/png
 */
import fs from "node:fs";
import { PipelineContext, ValidationPipeline } from "@secureupload/core";
import { MagicByteValidator, FilenameSanitizerValidator, MimeMismatchValidator } from "@secureupload/validators";

const [, , filePath, declaredMimeType] = process.argv;

if (!filePath || !declaredMimeType) {
  console.error("Usage: node check-uploads.js <path-to-file> <declared-mime-type>");
  process.exit(1);
}

const buffer = fs.readFileSync(filePath);

const context = new PipelineContext({ filename: filePath, declaredMimeType });
const pipeline = new ValidationPipeline([
  MagicByteValidator, 
  FilenameSanitizerValidator, 
  MimeMismatchValidator]);

await pipeline.run(buffer, context);

console.log(`\n${filePath}  (claiming to be: ${declaredMimeType})`);
if (context.hasFindings) {
  for (const f of context.findings) {
    console.log(`  [${f.severity}] ${f.rule} — ${f.message}`);
  }
} else {
  console.log("  clean — nothing flagged");
}
