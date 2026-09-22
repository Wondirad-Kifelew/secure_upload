import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { QuarantineStore, evaluateQuarantine } from "../src/index.js";

describe("Quarantine", () => {
  let root;
  let store;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-quarantine-"));
    store = new QuarantineStore({ rootDirectory: root });
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  test("evaluates high-severity evidence as requiring sandboxing", () => {
    const decision = evaluateQuarantine([
      {
        rule: "magic-byte-mismatch",
        severity: "high",
        message: "Content does not match declared type",
      },
    ]);

    expect(decision.storageState).toBe("quarantined");
    expect(decision.suspicious).toBe(true);
    expect(decision.requiresSandbox).toBe(true);
  });

  test("stores sample bytes under a generated ID with a manifest", async () => {
    const record = await store.put(Buffer.from("hello"), {
      filename: "hello.txt",
      declaredMimeType: "text/plain",
    });

    expect(record.status).toBe("quarantined");
    expect(record.originalName).toBe("hello.txt");
    expect(record.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(await fs.readFile(record.samplePath, "utf8")).toBe("hello");

    const loaded = await store.get(record.id);
    expect(loaded.sha256).toBe(record.sha256);
  });

  test("rejects unsafe object IDs instead of treating them as filesystem paths", async () => {
    await expect(store.get("../outside"))
      .rejects.toThrow("Invalid quarantine object ID");
  });

  test("allows quarantine to sandboxing but rejects invalid transitions", async () => {
    const record = await store.put(Buffer.from("sample"));
    const sandboxing = await store.transition(record.id, "sandboxing");
    expect(sandboxing.status).toBe("sandboxing");

    await expect(store.transition(record.id, "released")).rejects.toThrow(
      "Invalid quarantine transition"
    );
  });
});
