import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { MagicByteValidator, ZipSlipGuardValidator } from "@secureupload/validators";
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

function crc32(buf) {
  let table = crc32.table;
  if (!table) {
    table = crc32.table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) {
        c = c & 1 ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[n] = c;
    }
  }
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function buildZip(files) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const [name, content] of Object.entries(files)) {
    const nameBuf = Buffer.from(name, "utf8");
    const crc = crc32(content);
    const size = content.length;

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(size, 18);
    localHeader.writeUInt32LE(size, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);

    const localEntry = Buffer.concat([localHeader, nameBuf, content]);
    localParts.push(localEntry);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0, 8);
    centralHeader.writeUInt16LE(0, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(size, 20);
    centralHeader.writeUInt32LE(size, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);

    const centralEntry = Buffer.concat([centralHeader, nameBuf]);
    centralParts.push(centralEntry);

    offset += localEntry.length;
  }

  const localSection = Buffer.concat(localParts);
  const centralSection = Buffer.concat(centralParts);

  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(centralParts.length, 8);
  end.writeUInt16LE(centralParts.length, 10);
  end.writeUInt32LE(centralSection.length, 12);
  end.writeUInt32LE(localSection.length, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([localSection, centralSection, end]);
}

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

  test("retains validator findings when scanner throws on malicious file", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-service-"));
    try {
      const quarantineStore = new QuarantineStore({ rootDirectory: root });
      const sandboxManager = new SandboxManager({ adapter: new DryRunSandboxAdapter() });
      const throwingScanner = {
        name: "Broken Scanner",
        async scan() {
          throw new Error("scanner error");
        },
      };
      const service = new UploadSecurityService({
        validators: [ZipSlipGuardValidator],
        scanners: [throwingScanner],
        quarantineStore,
        sandboxManager,
      });

      const evilZip = buildZip({ "../../evil.txt": Buffer.from("payload") });
      const result = await service.analyze({
        buffer: evilZip,
        filename: "test.zip",
        declaredMimeType: "application/zip",
      });

      expect(result.context.findings.some((f) => f.rule === "zip-slip-path-traversal")).toBe(true);
      expect(result.context.findings.some((f) => f.rule === "scanner-failed")).toBe(true);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
