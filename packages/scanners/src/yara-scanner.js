import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

const execFileAsync = promisify(execFile);

/**
 * YaraScanner
 * ------------
 * Runs YARA rules — pattern/structural rules you write yourself,
 * rather than exact-hash signatures like ClamAV — against a file.
 * This catches whole families/behaviors ("any Office doc combining
 * Auto_Open with Shell(...)") even for content nobody's cataloged
 * before, complementing ClamAV rather than duplicating it.
 *
 * IMPLEMENTATION NOTE, IMPORTANT: this wraps the `yara` CLI binary as
 * a subprocess, rather than a native Node binding. A native binding
 * would need to compile against libyara's dev headers (libyara-dev),
 * which in turn need libssl-dev — and that specific package failed to
 * install in verification (a broken upstream mirror, unrelated to this
 * project). Rather than build on an unverifiable foundation, this uses
 * the CLI directly, the same way many production tools do. One real
 * consequence: unlike ClamAV's clamd (which streams a buffer directly
 * over a socket, touching disk never), YARA's CLI has no stdin/stream
 * option — it only accepts a real file path. So this scanner writes
 * the buffer to a throwaway temp file for the duration of the scan,
 * and always deletes it afterward (even on error, via `finally`).
 *
 * Unlike clamd, there's no long-running daemon to connect to here —
 * every scan spawns a fresh `yara` process. Slower per-call than
 * ClamAV's persistent-daemon approach, but YARA rule sets are
 * typically much smaller than ClamAV's full malware database, so
 * process-startup cost is the dominant factor, not database reloading.
 *
 * Implements the Scanner contract from core/src/interfaces/scanner.js.
 */

export function createYaraScanner({ rulesPath, yaraBinary = "yara" } = {}) {
  if (!rulesPath) {
    throw new Error("createYaraScanner requires { rulesPath } — a path to a .yar rules file.");
  }

  return {
    name: "YARA Scanner",

    /**
     * @param {Buffer} buffer
     * @returns {Promise<import('@secureupload/core').ScanResult>}
     */
    async scan(buffer) {
      // Deliberately never derived from the original filename — always
      // a fresh random name, so nothing attacker-controlled ever
      // touches the temp file path.
      const tempFilePath = path.join(os.tmpdir(), `secureupload-yara-${crypto.randomUUID()}`);
      await fs.writeFile(tempFilePath, buffer);

      try {
        const { stdout } = await execFileAsync(yaraBinary, ["-m", rulesPath, tempFilePath]);
        return interpretOutput(stdout);
      } catch (err) {
        if (err.code === "ENOENT") {
          throw new Error(`Could not run YARA: "${yaraBinary}" was not found. Is YARA installed?`);
        }
        // Non-zero exit (e.g. a malformed rules file) — a genuine
        // failure, not a normal "unclean" verdict.
        throw new Error(`YARA scan failed: ${err.stderr || err.message}`);
      } finally {
        await fs.rm(tempFilePath, { force: true });
      }
    },
  };
}

/**
 * With the -m flag, each matching rule prints one line:
 *   RuleName [key="value",...] /path/to/scanned/file
 * No output at all means no rules matched — a clean result.
 */
function interpretOutput(stdout) {
  const lines = stdout
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  if (lines.length === 0) {
    return { clean: true, findings: [] };
  }

  const findings = lines.map((line) => {
    const match = line.match(/^(\S+)/);
    const ruleName = match ? match[1] : line;
    return {
      rule: "yara-match",
      severity: "high",
      message: `YARA rule "${ruleName}" matched this file.`,
      details: { ruleName, raw: line },
    };
  });

  return { clean: false, findings };
}