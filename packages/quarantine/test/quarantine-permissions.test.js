import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { QuarantineStore } from "../src/index.js";

describe("Quarantine permissions", () => {
  test("creates private quarantine directories and sample files", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-perm-"));
    try {
      const store = new QuarantineStore({ rootDirectory: root });
      const record = await store.put(Buffer.from("secret"));

      const rootMode = (await fs.stat(root)).mode & 0o777;
      const objectDir = path.dirname(record.samplePath);
      const dirMode = (await fs.stat(objectDir)).mode & 0o777;
      const fileMode = (await fs.stat(record.samplePath)).mode & 0o777;

      expect(rootMode).toBe(0o700);
      expect(dirMode).toBe(0o700);
      expect(fileMode).toBe(0o600);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
