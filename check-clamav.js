import fs from "node:fs";
import { createClamAVScanner } from "@secureupload/scanners";

const scanner = createClamAVScanner({ socketPath: "/var/run/clamav/clamd.ctl" });

const [, , filePath] = process.argv;
if (!filePath) {
  console.error("Usage: node check-clamav.js <path-to-file>");
  process.exit(1);
}

const buffer = fs.readFileSync(filePath);

const result = await scanner.scan(buffer);

console.log(result);