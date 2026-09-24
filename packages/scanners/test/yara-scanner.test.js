import { execFileSync } from "node:child_process";
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

describe("YaraScanner", () => {
  test("throws when constructed without a rulesPath", () => {
    expect(() => createYaraScanner({})).toThrow(/requires \{ rulesPath \}/);
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