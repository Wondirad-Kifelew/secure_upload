import fs from "node:fs";
import { createYaraScanner } from "@secureupload/scanners";

const scanner = createYaraScanner({
  rulesPath: "packages/scanners/test/fixtures/test-rules.yar",
});

const [, , filePath] = process.argv;
if (!filePath) {
  console.error("Usage: node check-yara.js <path-to-file>");
  process.exit(1);
}

const buffer = fs.readFileSync(filePath);

try {
  const result = await scanner.scan(buffer);
  console.log(JSON.stringify(result, null, 2));
} catch (err) {
  console.error("Scan failed:", err.message);
  process.exit(1);
}