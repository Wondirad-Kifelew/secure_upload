import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { QuarantineStore } from "@secureupload/quarantine";

const settings = ["MAX_UPLOAD_MB", "MAX_CONCURRENT_SCANS"];
const originalSettings = Object.fromEntries(settings.map((name) => [name, process.env[name]]));

async function importHttpServer(env = {}) {
  for (const name of settings) {
    delete process.env[name];
  }
  Object.assign(process.env, env);
  return import(`../src/http-server.js?settings=${Math.random()}`);
}

async function withHttpServer(status, run, env = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-http-"));
  const quarantineStore = new QuarantineStore({ rootDirectory: root });
  let record = await quarantineStore.put(Buffer.from("clean sample"), {
    filename: "sample.txt",
    declaredMimeType: "text/plain",
  });
  if (status === "manual-review") {
    await quarantineStore.transition(record.id, "sandboxing");
    record = await quarantineStore.transition(record.id, "manual-review");
  }

  const service = {
    quarantineStore,
    async analyze() {
      return { quarantine: record, context: { findings: [] } };
    },
  };
  const originalApiKey = process.env.API_KEY;
  process.env.API_KEY = "";
  const { createServer } = await importHttpServer(env);
  const server = createServer(service);

  try {
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    await run(baseUrl, record, quarantineStore);
  } finally {
    if (server.listening) {
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
    await fs.rm(root, { recursive: true, force: true });
    if (originalApiKey === undefined) delete process.env.API_KEY;
    else process.env.API_KEY = originalApiKey;
  }
}

describe("HTTP server", () => {
  afterEach(() => {
    for (const name of settings) {
      if (originalSettings[name] === undefined) delete process.env[name];
      else process.env[name] = originalSettings[name];
    }
  });

  test.each(settings.flatMap((name) => [
    [name, "not-a-number"],
    [name, "Infinity"],
    [name, "0"],
    [name, "-1"],
  ]).concat([
    ["MAX_CONCURRENT_SCANS", "NaN"],
    ["MAX_CONCURRENT_SCANS", "-Infinity"],
    ["MAX_CONCURRENT_SCANS", "1.5"],
  ]))("rejects %s=%s at startup", async (name, value) => {
    const expected = name === "MAX_CONCURRENT_SCANS"
      ? `${name} must be a positive integer.`
      : `${name} must be a finite number greater than 0.`;
    await expect(importHttpServer({ [name]: value })).rejects.toThrow(
      expected
    );
  });

  test("accepts positive configured values and the existing defaults", async () => {
    const configured = await importHttpServer({ MAX_UPLOAD_MB: "1.5", MAX_CONCURRENT_SCANS: "2" });
    const server = configured.createServer({});
    expect(server.requestTimeout).toBe(60_000);
    server.close();

    const defaults = await importHttpServer();
    const defaultServer = defaults.createServer({});
    expect(defaultServer.requestTimeout).toBe(60_000);
    defaultServer.close();
  });

  test("keeps a failed sandbox manual-review record out of clean and download responses", async () => {
    await withHttpServer("manual-review", async (baseUrl, record, quarantineStore) => {
      const clean = await fetch(`${baseUrl}/clean`, {
        method: "POST",
        headers: { "X-Filename": "sample.txt", "Content-Type": "text/plain" },
        body: "sample",
      });
      expect(clean.status).toBe(422);
      expect(await clean.json()).toMatchObject({ verdict: "review" });

      // Even a stale allow verdict must not release content held for review.
      await quarantineStore.annotate(record.id, { verdict: "allow" });
      const download = await fetch(`${baseUrl}/files/${record.id}`);
      expect(download.status).toBe(403);
    });
  });

  test("serves clean output for an allow verdict in a releasable quarantine state", async () => {
    await withHttpServer("quarantined", async (baseUrl, record) => {
      const clean = await fetch(`${baseUrl}/clean`, {
        method: "POST",
        headers: { "X-Filename": "sample.txt", "Content-Type": "text/plain" },
        body: "sample",
      });
      expect(clean.status).toBe(200);
      expect(await clean.text()).toBe("clean sample");

      const download = await fetch(`${baseUrl}/files/${record.id}`);
      expect(download.status).toBe(200);
      expect(await download.text()).toBe("clean sample");
    });
  });

  test("returns 413 for a body over the configured upload limit", async () => {
    await withHttpServer("quarantined", async (baseUrl) => {
      const response = await fetch(`${baseUrl}/clean`, {
        method: "POST",
        headers: { "X-Filename": "large.txt", "Content-Type": "text/plain" },
        body: "oversized",
      });
      expect(response.status).toBe(413);
      expect(await response.json()).toMatchObject({ error: "Upload exceeds maximum allowed size." });
    }, { MAX_UPLOAD_MB: "0.000001" });
  });
});
