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

      const png = Buffer.from([
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8,
        2, 0, 0, 0, 144, 119, 83, 222, 0, 0, 0, 9, 112, 72, 89, 115, 0, 0, 3, 232, 0, 0, 3, 232, 1,
        181, 123, 82, 107, 0, 0, 0, 12, 73, 68, 65, 84, 8, 153, 99, 248, 207, 192, 0, 0, 3, 1, 1,
        0, 156, 227, 191, 89, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
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

  test("moves a failed sandbox run to manual review", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-service-"));
    try {
      const quarantineStore = new QuarantineStore({ rootDirectory: root });
      const sandboxManager = new SandboxManager({
        adapter: { async analyze() { throw new Error("sandbox unavailable"); } },
        threshold: 60,
      });
      const service = new UploadSecurityService({
        quarantineStore,
        sandboxManager,
        anomalyDetector: null,
        aiProvider: null,
      });

      const result = await service.analyze({
        buffer: Buffer.from("sample"),
        filename: "sample.txt",
        declaredMimeType: "text/plain",
        riskScore: 80,
      });

      expect(result.sandbox.status).toBe("failed");
      expect(result.quarantine.status).toBe("manual-review");
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  test("handles a throwing scanner on clean upload without failing analysis", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-service-"));
    try {
      const quarantineStore = new QuarantineStore({ rootDirectory: root });
      const sandboxManager = new SandboxManager({ adapter: new DryRunSandboxAdapter() });
      const throwingScanner = {
        name: "Broken Scanner",
        async scan() {
          throw new Error("ClamAV socket timeout");
        },
      };
      const service = new UploadSecurityService({
        scanners: [throwingScanner],
        quarantineStore,
        sandboxManager,
      });

      const result = await service.analyze({
        buffer: Buffer.from("clean document"),
        filename: "notes.txt",
        declaredMimeType: "text/plain",
      });

      expect(result.context.findings.some((f) => f.rule === "scanner-failed")).toBe(true);
      const scannerFinding = result.context.findings.find((f) => f.rule === "scanner-failed");
      expect(scannerFinding.severity).toBe("medium");
      expect(scannerFinding.details.reason).toBe("ClamAV socket timeout");
      expect(result.quarantine.status).not.toBe("allow");
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  test("retains validator findings when scanner throws on non-blocking file", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-service-"));
    try {
      const quarantineStore = new QuarantineStore({ rootDirectory: root });
      const sandboxManager = new SandboxManager({ adapter: new DryRunSandboxAdapter() });
      const mediumValidator = {
        name: "Medium Validator",
        async validate() {
          return [
            {
              rule: "extension-declared-mismatch",
              severity: "medium",
              stage: "validation",
              source: "Medium Validator",
              message: "Extension does not match declared MIME type.",
            },
          ];
        },
      };
      const throwingScanner = {
        name: "Broken Scanner",
        async scan() {
          throw new Error("scanner error");
        },
      };
      const service = new UploadSecurityService({
        validators: [mediumValidator],
        scanners: [throwingScanner],
        quarantineStore,
        sandboxManager,
      });

      const result = await service.analyze({
        buffer: Buffer.from("sample content"),
        filename: "test.txt",
        declaredMimeType: "text/plain",
      });

      expect(result.context.findings.some((f) => f.rule === "extension-declared-mismatch")).toBe(true);
      expect(result.context.findings.some((f) => f.rule === "scanner-failed")).toBe(true);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  test("skips scanner when validator returns an extreme finding", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-service-"));
    try {
      const quarantineStore = new QuarantineStore({ rootDirectory: root });
      const sandboxManager = new SandboxManager({ adapter: new DryRunSandboxAdapter() });
      let scannerCalled = false;
      const recordingScanner = {
        name: "Recording Scanner",
        async scan() {
          scannerCalled = true;
          return { clean: true };
        },
      };
      const extremeValidator = {
        name: "Extreme Validator",
        async validate() {
          return [
            {
              rule: "zip-slip-path-traversal",
              severity: "extreme",
              stage: "validation",
              source: "Extreme Validator",
              message: "Archive entry points outside target directory.",
            },
          ];
        },
      };
      const service = new UploadSecurityService({
        validators: [extremeValidator],
        scanners: [recordingScanner],
        quarantineStore,
        sandboxManager,
      });

      const result = await service.analyze({
        buffer: Buffer.from("payload"),
        filename: "test.zip",
        declaredMimeType: "application/zip",
      });

      expect(scannerCalled).toBe(false);
      expect(result.context.findings.some((f) => f.rule === "zip-slip-path-traversal")).toBe(true);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  test("calls scanner when validator returns only a medium finding", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-service-"));
    try {
      const quarantineStore = new QuarantineStore({ rootDirectory: root });
      const sandboxManager = new SandboxManager({ adapter: new DryRunSandboxAdapter() });
      let scannerCalled = false;
      const recordingScanner = {
        name: "Recording Scanner",
        async scan() {
          scannerCalled = true;
          return { clean: true };
        },
      };
      const mediumValidator = {
        name: "Medium Validator",
        async validate() {
          return [
            {
              rule: "extension-declared-mismatch",
              severity: "medium",
              stage: "validation",
              source: "Medium Validator",
              message: "Extension does not match declared MIME type.",
            },
          ];
        },
      };
      const service = new UploadSecurityService({
        validators: [mediumValidator],
        scanners: [recordingScanner],
        quarantineStore,
        sandboxManager,
      });

      const result = await service.analyze({
        buffer: Buffer.from("payload"),
        filename: "test.bin",
        declaredMimeType: "application/octet-stream",
      });

      expect(scannerCalled).toBe(true);
      expect(result.context.findings.some((f) => f.rule === "extension-declared-mismatch")).toBe(true);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  test("calls scanner when validators produce no findings", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-service-"));
    try {
      const quarantineStore = new QuarantineStore({ rootDirectory: root });
      const sandboxManager = new SandboxManager({ adapter: new DryRunSandboxAdapter() });
      let scannerCalled = false;
      const recordingScanner = {
        name: "Recording Scanner",
        async scan() {
          scannerCalled = true;
          return { clean: true };
        },
      };
      const service = new UploadSecurityService({
        validators: [],
        scanners: [recordingScanner],
        quarantineStore,
        sandboxManager,
      });

      const result = await service.analyze({
        buffer: Buffer.from("clean document"),
        filename: "notes.txt",
        declaredMimeType: "text/plain",
      });

      expect(scannerCalled).toBe(true);
      expect(result.context.findings.length).toBe(0);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
