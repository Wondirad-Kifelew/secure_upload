import fs from "node:fs";
import { createClamAVScanner } from "@secureupload/scanners";

const scanner = createClamAVScanner({ socketPath: "/var/run/clamav/clamd.ctl" });

const [, , filePath] = process.argv;
if (!filePath) {
  console.error("Usage: node check-clamav.js <path-to-file>");
  process.exit(1);
}

const buffer = fs.readFileSync(filePath);

try {
  const result = await scanner.scan(buffer);
  console.log(JSON.stringify(result, null, 2));
} catch (err) {
  console.error("Scan failed:", err.message);
  console.error("(Is clamd actually running? Try: sudo systemctl status clamav-daemon)");
  process.exit(1);
}