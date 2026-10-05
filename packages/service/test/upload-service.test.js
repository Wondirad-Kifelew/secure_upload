import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { MagicByteValidator } from "@secureupload/validators";
import { QuarantineStore } from "@secureupload/quarantine";
import { DryRunSandboxAdapter, SandboxManager } from "@secureupload/sandbox";
import { UploadSecurityService } from "../src/index.js";

describe("UploadSecurityService", () => {
  test("quarantines every upload and sandboxes high-risk evidence", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-service-"));
    try {
      const quarantineStore = new QuarantineStore({ rootDirectory: root });
      const sandboxManager = new SandboxManager({
        adapter: new DryRunSandboxAdapter(),
        threshold: 60,
      });
      const service = new UploadSecurityService({
        validators: [MagicByteValidator],
        quarantineStore,
        sandboxManager,
      });

      const result = await service.analyze({
        buffer: Buffer.from("not really a png"),
        filename: "report.png",
        declaredMimeType: "image/png",
        riskScore: 80,
      });

      expect(result.quarantine.status).toBe("sandboxed");
      expect(result.quarantine.originalName).toBe("report.png");
      expect(result.quarantine.sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(result.sandbox.triggered).toBe(true);
      expect(result.sandbox.result.executed).toBe(false);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  test("does not trigger sandbox for a low-risk clean upload", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-service-"));
    try {
      const quarantineStore = new QuarantineStore({ rootDirectory: root });
      const sandboxManager = new SandboxManager({ adapter: new DryRunSandboxAdapter() });
      const service = new UploadSecurityService({
        validators: [MagicByteValidator],
        quarantineStore,
        sandboxManager,
      });

      const png = Buffer.concat([
        Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
        Buffer.from([0, 0, 0, 13]),
        Buffer.from("IHDR"),
        Buffer.alloc(13),
        Buffer.alloc(4),
        Buffer.alloc(20)
      ]);
      const result = await service.analyze({
        buffer: png,
        filename: "photo.png",
        declaredMimeType: "image/png",
        riskScore: 10,
      });

      expect(result.quarantine.status).toBe("quarantined");
      expect(result.sandbox.triggered).toBe(false);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
