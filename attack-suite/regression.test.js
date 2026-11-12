// attack-suite/regression.test.js
import { describe, test, expect, beforeAll, afterAll } from "@jest/globals";
import fs, { readFile, readdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { UploadSecurityService } from "@secureupload/service";
import { MagicByteValidator, FilenameSanitizerValidator, MimeMismatchValidator,
  PolyglotDetectorValidator, ZipBombGuardValidator, ZipSlipGuardValidator,
  EntryCountGuardValidator, DuplicateEntryGuardValidator, NestedArchiveGuardValidator,
  SymlinkEntryGuardValidator, EncryptedEntryGuardValidator, NonRecursiveBombGuardValidator,
  DeviceNameGuardValidator, UnicodeControlGuardValidator, TrailingCharacterGuardValidator,
  ArchiveIntegrityGuardValidator, DangerousExtensionGuardValidator, NestedZipInspectorValidator } from "@secureupload/validators";
import { FakeScanner, createClamAVScanner } from "@secureupload/scanners";
import { QuarantineStore } from "@secureupload/quarantine";
import { SandboxManager, DryRunSandboxAdapter } from "@secureupload/sandbox";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SAMPLES_ROOT = path.join(__dirname, "samples");

// Declared MIME type per sample filename — without this, CDR's sanitizer
// selection (which keys off declaredMimeType) never runs, and PDF/image
// samples pass straight through unexamined. Add an entry here for every
// new sample you drop into samples/.
const SAMPLE_META = {
  "eicar.txt": "text/plain",
  "malicious-invoice.pdf": "application/pdf",
  "malicious-invoice.sanitized.pdf": "application/pdf",
  "polyglot.gif": "image/gif",
  "zip-bomb-sample.zip": "application/zip",
  "%2e%2e%2fetc%2fpasswd.png": "image/png",
  "..∕etc∕passwd.png": "image/png",
};

// Use real ClamAV when CLAMD_HOST/CLAMD_PORT are set (CI with a clamd
// sidecar, or local run against `docker compose up`'s clamav container),
// fall back to FakeScanner otherwise so this suite still runs without
// Docker — detection-specific assertions below are skipped in that case,
// since FakeScanner can't actually detect anything.
const usingRealClamAV = Boolean(process.env.CLAMD_HOST && process.env.CLAMD_PORT);
const scanners = usingRealClamAV
  ? [createClamAVScanner({ host: process.env.CLAMD_HOST, port: Number(process.env.CLAMD_PORT) })]
  : [FakeScanner];

let quarantineRoot;
let service;

beforeAll(async () => {
  // Use a fresh temp directory rather than a fixed path inside the repo.
  // A leftover .test-quarantine directory can be owned by another user
  // (e.g. root after a containerized test run), making chmod fail with EPERM.
  quarantineRoot = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-attack-suite-"));
  service = new UploadSecurityService({
    validators: [
      MagicByteValidator, FilenameSanitizerValidator, MimeMismatchValidator,
      PolyglotDetectorValidator, ZipBombGuardValidator, ZipSlipGuardValidator,
      EntryCountGuardValidator, DuplicateEntryGuardValidator, NestedArchiveGuardValidator,
      SymlinkEntryGuardValidator, EncryptedEntryGuardValidator, NonRecursiveBombGuardValidator,
      DeviceNameGuardValidator, UnicodeControlGuardValidator, TrailingCharacterGuardValidator,
      ArchiveIntegrityGuardValidator, DangerousExtensionGuardValidator, NestedZipInspectorValidator,
    ],
    scanners,
    quarantineStore: new QuarantineStore({ rootDirectory: quarantineRoot }),
    sandboxManager: new SandboxManager({ adapter: new DryRunSandboxAdapter(), threshold: 60 }),
  });
});

afterAll(async () => {
  if (quarantineRoot) {
    await fs.rm(quarantineRoot, { recursive: true, force: true });
  }
});

async function listSamplesRecursive(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...(await listSamplesRecursive(full)));
    else if (entry.isFile()) files.push(full);
  }
  return files;
}

async function analyzeSample(filePath) {
  const buffer = await readFile(filePath);
  const filename = path.basename(filePath);
  const declaredMimeType = SAMPLE_META[filename] ?? null;
  return service.analyze({ buffer, filename, declaredMimeType });
}

describe("attack-suite regression", () => {
  test("every sample runs through the pipeline without throwing", async () => {
    const files = await listSamplesRecursive(SAMPLES_ROOT);
    expect(files.length).toBeGreaterThan(0); // catches an empty/misconfigured suite

    for (const filePath of files) {
      let result;
      try {
        result = await analyzeSample(filePath);
      } catch (error) {
        throw new Error(`Pipeline threw on ${filePath}: ${error.message}`);
      }
      console.log(
        `${path.relative(SAMPLES_ROOT, filePath)}: status=${result.quarantine.status} ` +
        `risk=${result.risk.score} findings=[${result.context.findings.map((f) => f.rule).join(", ")}]`
      );
    }
  }, 30000);

  test("polyglot.gif triggers polyglot-dual-format and gets sandboxed", async () => {
    const result = await analyzeSample(path.join(SAMPLES_ROOT, "polyglots", "polyglot.gif"));
    expect(result.context.findings.some((f) => f.rule === "polyglot-dual-format")).toBe(true);
    expect(result.quarantine.status).toBe("sandboxed");
  });

  test("zip-bomb-sample.zip triggers zip-bomb-compression-ratio and gets sandboxed", async () => {
    const result = await analyzeSample(path.join(SAMPLES_ROOT, "zip-bombs", "zip-bomb-sample.zip"));
    expect(result.context.findings.some((f) => f.rule === "zip-bomb-compression-ratio")).toBe(true);
    expect(result.quarantine.status).toBe("sandboxed");
  }, 60000);

    test("malicious-invoice.pdf triggers CDR findings on sanitization", async () => {
    const result = await analyzeSample(path.join(SAMPLES_ROOT, "macro-office", "malicious-invoice.pdf"));
    expect(result.context.findings.some((f) => f.rule === "pdf-content-stripped")).toBe(true);
    expect(result.quarantine.status).toBe("quarantined");
  });

  test.each([
    ["%2e%2e%2fetc%2fpasswd.png"],
    ["..∕etc∕passwd.png"],
  ])("%s triggers filename-path-traversal and gets sandboxed", async (filename) => {
    const result = await analyzeSample(path.join(SAMPLES_ROOT, "null-byte-unicode", filename));
    expect(result.context.findings.some((f) => f.rule === "filename-path-traversal")).toBe(true);
    expect(result.quarantine.status).toBe("sandboxed");
  });

  (usingRealClamAV ? test : test.skip)(
    "eicar.txt is flagged by ClamAV and sandboxed",
    async () => {
      const result = await analyzeSample(path.join(SAMPLES_ROOT, "eicar", "eicar.txt"));
      expect(result.context.findings.some((f) => f.rule === "clamav-match")).toBe(true);
      expect(result.quarantine.status).toBe("sandboxed");
    }
  );


});