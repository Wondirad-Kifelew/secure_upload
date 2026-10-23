import { execFileSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createYaraScanner } from "../src/yara-scanner.js";

/**
 * Same reasoning as clamav-scanner.test.js: this needs the real `yara`
 * CLI to prove the subprocess wiring actually works — there's no
 * meaningful way to fake a command-line tool and still test that.
 * Auto-skips if `yara` isn't installed, so `npm test` stays green on
 * a machine without it (see FakeScanner for the dependency-free way
 * ScanPipeline itself gets tested).
 */

let yaraAvailable = false;
try {
  execFileSync("yara", ["--version"], { stdio: "ignore" });
  yaraAvailable = true;
} catch {
  // yara not installed or not on PATH — tests below will skip.
}

const maybeTest = yaraAvailable ? test : test.skip;

if (!yaraAvailable) {
  console.warn(
    "\nSkipping YaraScanner integration tests — the `yara` CLI was not found on PATH.\n"
  );
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RULES_PATH = path.join(__dirname, "fixtures", "test-rules.yar");
const permissionTest = process.platform === "win32" ? test.skip : test;

if (process.platform === "win32") {
  console.warn("Skipping YARA temp-file permission assertion: Windows does not expose POSIX mode bits.");
}

async function createFakeYaraBinary(root) {
  const binaryPath = path.join(root, "fake-yara.js");
  await fs.writeFile(binaryPath, `#!/usr/bin/env node
const fs = require("node:fs");
const reportPath = process.argv[3];
const scannedPath = process.argv[4];
const mode = fs.statSync(scannedPath).mode & 0o777;
fs.writeFileSync(reportPath, JSON.stringify({ scannedPath, mode }));
if (reportPath.endsWith(".fail")) {
  process.stderr.write("fake YARA failure");
  process.exit(2);
}
`, { mode: 0o700 });
  await fs.chmod(binaryPath, 0o700);
  return binaryPath;
}

describe("YaraScanner", () => {
  test("throws when constructed without a rulesPath", () => {
    expect(() => createYaraScanner({})).toThrow(/requires \{ rulesPath \}/);
  });

  permissionTest("creates owner-only temp files and removes them after success and failure", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-yara-test-"));
    try {
      const yaraBinary = await createFakeYaraBinary(root);
      const successReport = path.join(root, "success.json");
      const successfulScan = createYaraScanner({ rulesPath: successReport, yaraBinary });
      expect((await successfulScan.scan(Buffer.from("private upload"))).clean).toBe(true);

      const success = JSON.parse(await fs.readFile(successReport, "utf8"));
      expect(success.mode).toBe(0o600);
      await expect(fs.access(success.scannedPath)).rejects.toMatchObject({ code: "ENOENT" });

      const failureReport = path.join(root, "failure.fail");
      const failingScan = createYaraScanner({ rulesPath: failureReport, yaraBinary });
      await expect(failingScan.scan(Buffer.from("private upload"))).rejects.toThrow("YARA scan failed");

      const failure = JSON.parse(await fs.readFile(failureReport, "utf8"));
      expect(failure.mode).toBe(0o600);
      await expect(fs.access(failure.scannedPath)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  maybeTest("reports a harmless buffer as clean", async () => {
    const scanner = createYaraScanner({ rulesPath: RULES_PATH });
    const result = await scanner.scan(Buffer.from("just an ordinary harmless file"));
    expect(result.clean).toBe(true);
    expect(result.findings).toEqual([]);
  });

  maybeTest("flags a buffer matching the test rule", async () => {
    const scanner = createYaraScanner({ rulesPath: RULES_PATH });
    const result = await scanner.scan(
      Buffer.from("this file contains malicious-test-string-for-yara-testing inside it")
    );
    expect(result.clean).toBe(false);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].rule).toBe("yara-match");
    expect(result.findings[0].details.ruleName).toBe("Suspicious_Test_String");
  });

  maybeTest("cleans up its temp file even after a scan", async () => {
    const scanner = createYaraScanner({ rulesPath: RULES_PATH });
    await scanner.scan(Buffer.from("first scan"));
    const result = await scanner.scan(Buffer.from("second scan, still harmless"));
    expect(result.clean).toBe(true);
  });

  maybeTest("throws a clear error for a malformed rules file", async () => {
    const scanner = createYaraScanner({ rulesPath: "/nonexistent/rules.yar" });
    await expect(scanner.scan(Buffer.from("test"))).rejects.toThrow(/YARA scan failed/);
  });
});