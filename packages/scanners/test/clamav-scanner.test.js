import fs from "node:fs";
import { createClamAVScanner } from "../src/clamav-scanner.js";

/**
 * Unlike every other test file in this project, these tests need a
 * REAL running clamd daemon — there's no meaningful way to "fake" the
 * wire protocol and still prove the integration actually works. That's
 * exactly why FakeScanner exists separately: for testing the
 * orchestration logic (ScanPipeline) without needing ClamAV installed.
 * These tests below are specifically for proving THIS file's protocol
 * implementation against the real thing.
 *
 * If no clamd socket is found, these tests skip themselves (rather
 * than failing) so `npm test` still passes cleanly on a machine
 * without ClamAV set up — same reasoning as the project guide's
 * FakeScanner note about CI machines not having ClamAV installed.
 */

const SOCKET_PATH = process.env.CLAMD_SOCKET_PATH || "/var/run/clamav/clamd.ctl";
const clamdAvailable = fs.existsSync(SOCKET_PATH);
const maybeTest = clamdAvailable ? test : test.skip;

if (!clamdAvailable) {
  console.warn(
    `\nSkipping ClamAVScanner integration tests — no clamd socket found at ${SOCKET_PATH}.\n` +
      `Set CLAMD_SOCKET_PATH or run with a real clamd to exercise these.\n`
  );
}

describe("ClamAVScanner", () => {
  test("throws when constructed without any connection info", () => {
    expect(() => createClamAVScanner({})).toThrow(/requires either/);
  });

  maybeTest("reports a harmless buffer as clean", async () => {
    const scanner = createClamAVScanner({ socketPath: SOCKET_PATH });
    const result = await scanner.scan(Buffer.from("just an ordinary harmless file"));
    expect(result.clean).toBe(true);
    expect(result.findings).toEqual([]);
  });

  maybeTest("flags the real EICAR test string as infected", async () => {
    const scanner = createClamAVScanner({ socketPath: SOCKET_PATH });
    const eicar = Buffer.from(
      "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    );
    const result = await scanner.scan(eicar);
    expect(result.clean).toBe(false);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].rule).toBe("clamav-match");
    expect(result.findings[0].details.virusName).toMatch(/Eicar/i);
  });

  maybeTest("throws a real error when clamd is unreachable at a given path", async () => {
    const scanner = createClamAVScanner({ socketPath: "/tmp/nonexistent-clamd-socket.ctl" });
    await expect(scanner.scan(Buffer.from("test"))).rejects.toThrow(/Could not reach clamd/);
  });
});