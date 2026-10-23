import fs from "node:fs";
import net from "node:net";
import { createClamAVScanner } from "../src/clamav-scanner.js";

async function scanWithMockResponse(response) {
  const server = net.createServer((socket) => {
    socket.once("data", () => socket.end(`${response}\0`));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  try {
    return await createClamAVScanner({ host: "127.0.0.1", port: server.address().port })
      .scan(Buffer.from("sample upload"));
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

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

  test("accepts the exact clean response", async () => {
    await expect(scanWithMockResponse("stream: OK")).resolves.toEqual({ clean: true, findings: [] });
  });

  test("preserves valid infected response handling", async () => {
    const result = await scanWithMockResponse("stream: Eicar-Test-Signature FOUND");
    expect(result.clean).toBe(false);
    expect(result.findings[0]).toMatchObject({
      rule: "clamav-match",
      severity: "extreme",
      details: { virusName: "Eicar-Test-Signature" },
    });
  });

  test.each([
    "stream: ERROR: scanner unavailable OK",
    "stream: ERROR: scanner unavailable",
    "stream: ERROR signature FOUND",
    "stream: OK trailing data",
    "unexpected stream: OK",
    "stream: signature FOUND trailing data",
    "",
  ])("rejects malformed response %p", async (response) => {
    await expect(scanWithMockResponse(response)).rejects.toThrow(/Unexpected response from clamd/);
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