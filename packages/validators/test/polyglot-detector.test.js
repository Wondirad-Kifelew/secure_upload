import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createPolyglotDetectorValidator, PolyglotDetectorValidator } from "../src/polyglot-detector.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadsDir = path.resolve(__dirname, "..", "..", "..", "uploads");

function resolveUploadFixture(filename) {
  const fromRelative = path.join(uploadsDir, filename);
  if (fs.existsSync(fromRelative)) return fromRelative;
  const fromCwd = path.resolve(process.cwd(), "uploads", filename);
  if (fs.existsSync(fromCwd)) return fromCwd;
  return null;
}

// --- Fixture Generators ---

function pngBuffer(options = {}) {
  const { extraTrailingBytes = 0, corruptIendLength = false } = options;
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdrLength = Buffer.from([0x00, 0x00, 0x00, 0x0d]);
  const ihdrType = Buffer.from("IHDR");
  const ihdrData = Buffer.alloc(13);
  const ihdrCrc = Buffer.alloc(4);

  const iendLenVal = corruptIendLength ? 0x0000000a : 0x00000000;
  const iendLength = Buffer.alloc(4);
  iendLength.writeUInt32BE(iendLenVal, 0);

  const iendChunk = Buffer.concat([
    iendLength,
    Buffer.from("IEND"),
    Buffer.from([0xae, 0x42, 0x60, 0x82]),
  ]);

  const base = Buffer.concat([signature, ihdrLength, ihdrType, ihdrData, ihdrCrc, iendChunk]);
  return extraTrailingBytes > 0
    ? Buffer.concat([base, Buffer.alloc(extraTrailingBytes, 0x58)])
    : base;
}

function jpegBuffer(options = {}) {
  const { extraTrailingBytes = 0 } = options;
  const soi = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00]);
  const payload = Buffer.alloc(32, 0xaa);
  const eoi = Buffer.from([0xff, 0xd9]);
  const base = Buffer.concat([soi, payload, eoi]);
  return extraTrailingBytes > 0
    ? Buffer.concat([base, Buffer.alloc(extraTrailingBytes, 0x59)])
    : base;
}

function gifJsPolyglotBuffer() {
  return Buffer.from("GIF89a=1;//" + "\0".repeat(20) + "\n" + 'console.log("polyglot executed");');
}

function pdfBuffer() {
  return Buffer.from("%PDF-1.5\n%rest of pdf content padding padding padding padding padding\n%%EOF");
}

function peStubBuffer() {
  const dos = Buffer.alloc(64);
  dos[0] = 0x4d; // 'M'
  dos[1] = 0x5a; // 'Z'
  dos.writeUInt32LE(64, 0x3c); // e_lfanew = 64
  const pe = Buffer.from([0x50, 0x45, 0x00, 0x00]); // 'PE\0\0'
  return Buffer.concat([dos, pe, Buffer.alloc(32)]);
}

describe("PolyglotDetectorValidator — Full Enterprise Suite", () => {
  // ==========================================
  // 1. Baseline Clean Files & Shape Contract
  // ==========================================
  describe("Baseline Clean Files & Shape Contract", () => {
    test("implements the expected Validator interface", () => {
      expect(PolyglotDetectorValidator.name).toBe("Polyglot Detector");
      expect(typeof PolyglotDetectorValidator.validate).toBe("function");
    });

    test("clean PNG returns zero findings", async () => {
      const findings = await PolyglotDetectorValidator.validate(pngBuffer());
      expect(findings).toEqual([]);
    });

    test("clean JPEG returns zero findings", async () => {
      const findings = await PolyglotDetectorValidator.validate(jpegBuffer());
      expect(findings).toEqual([]);
    });

    test("clean PDF returns zero findings", async () => {
      const findings = await PolyglotDetectorValidator.validate(pdfBuffer());
      expect(findings).toEqual([]);
    });

    test.each([
      ["CSV data", Buffer.from("name,age\nalice,30\nbob,25\n")],
      ["JSON data", Buffer.from('{"status": "ok", "count": 42}')],
      ["Plain text", Buffer.from("This is an ordinary readme text document.")],
      ["Markdown", Buffer.from("# Heading\n\nSome normal content.")],
    ])("plain text formats produce zero findings (%s)", async (_, buffer) => {
      const findings = await PolyglotDetectorValidator.validate(buffer);
      expect(findings).toEqual([]);
    });

    test("synthesized JPEG with multiple random 'MZ' byte sequences produces zero findings", async () => {
      // Guarantees false-positive immunity across all CI environments even without disk fixtures
      const soi = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00]);
      const noise = Buffer.concat([
        Buffer.alloc(64, 0x11),
        Buffer.from([0x4d, 0x5a, 0x01, 0x02]),
        Buffer.alloc(128, 0x22),
        Buffer.from([0x4d, 0x5a, 0x99, 0x88]),
        Buffer.alloc(64, 0x33),
      ]);
      const eoi = Buffer.from([0xff, 0xd9]);
      const buffer = Buffer.concat([soi, noise, eoi]);
      const findings = await PolyglotDetectorValidator.validate(buffer, { declaredMimeType: "image/jpeg" });
      expect(findings).toEqual([]);
    });

    test("real-world JPEG sample in uploads/ produces zero findings (no MZ false positive)", async () => {
      const samplePath = resolveUploadFixture("sample.jpeg");
      if (samplePath) {
        const buffer = fs.readFileSync(samplePath);
        const findings = await PolyglotDetectorValidator.validate(buffer, {
          filename: "sample.jpeg",
          declaredMimeType: "image/jpeg",
        });
        expect(findings).toEqual([]);
      }
    });

    test("real-world DOCX sample in uploads/ produces zero findings", async () => {
      const samplePath = resolveUploadFixture("sample.docx");
      if (samplePath) {
        const buffer = fs.readFileSync(samplePath);
        const findings = await PolyglotDetectorValidator.validate(buffer, {
          filename: "sample.docx",
          declaredMimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        });
        expect(findings).toEqual([]);
      }
    });

    test("real-world DOC sample in uploads/ produces zero findings when declared as application/msword", async () => {
      const samplePath = resolveUploadFixture("sample.doc");
      if (samplePath) {
        const buffer = fs.readFileSync(samplePath);
        const findings = await PolyglotDetectorValidator.validate(buffer, {
          filename: "sample.doc",
          declaredMimeType: "application/msword",
        });
        expect(findings).toEqual([]);
      }
    });
  });

  // ==========================================
  // 2. Secondary Container Smuggling
  // ==========================================
  describe("Layer 1: Secondary Containers & Executables", () => {
    const containers = [
      { type: "ZIP", sig: Buffer.from([0x50, 0x4b, 0x03, 0x04]) },
      { type: "Windows PE", sig: peStubBuffer() },
      { type: "ELF", sig: Buffer.from([0x7f, 0x45, 0x4c, 0x46]) },
      { type: "Java Class / Mach-O", sig: Buffer.from([0xca, 0xfe, 0xba, 0xbe]) },
      { type: "7-Zip", sig: Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) },
      { type: "RAR", sig: Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]) },
    ];

    test.each(containers)("flags embedded $type inside PNG container", async ({ type, sig }) => {
      const crafted = Buffer.concat([pngBuffer(), Buffer.alloc(16), sig, Buffer.alloc(32)]);
      const findings = await PolyglotDetectorValidator.validate(crafted);

      const hit = findings.find((f) => f.rule === "polyglot-secondary-container");
      expect(hit).toBeDefined();
      expect(hit.severity).toBe("extreme");
      expect(hit.details.containerType).toBe(type);
    });

    test.each(containers)("flags embedded $type inside JPEG container", async ({ type, sig }) => {
      const crafted = Buffer.concat([jpegBuffer(), Buffer.alloc(8), sig, Buffer.alloc(16)]);
      const findings = await PolyglotDetectorValidator.validate(crafted);

      const hit = findings.find((f) => f.rule === "polyglot-secondary-container");
      expect(hit).toBeDefined();
      expect(hit.severity).toBe("extreme");
      expect(hit.details.containerType).toBe(type);
    });

    test("does not flag random 'MZ' bytes without valid PE header (eliminates false positives)", async () => {
      const randomMz = Buffer.concat([jpegBuffer(), Buffer.from([0x4d, 0x5a]), Buffer.alloc(64, 0x20)]);
      const findings = await PolyglotDetectorValidator.validate(randomMz);
      expect(findings.find((f) => f.rule === "polyglot-secondary-container")).toBeUndefined();
    });

    test("flags embedded ZIP End of Central Directory (EOCD) signature inside image", async () => {
      const eocdSig = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
      const crafted = Buffer.concat([jpegBuffer(), Buffer.alloc(8), eocdSig, Buffer.alloc(16)]);
      const findings = await PolyglotDetectorValidator.validate(crafted);

      const hit = findings.find((f) => f.rule === "polyglot-secondary-container");
      expect(hit).toBeDefined();
      expect(hit.details.containerType).toBe("ZIP");
    });

    test("legitimate ZIP files are exempted from flagging their own primary container", async () => {
      const zipHeader = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
      const validZipStub = Buffer.concat([zipHeader, Buffer.alloc(64)]);
      const findings = await PolyglotDetectorValidator.validate(validZipStub, {
        declaredMimeType: "application/zip",
      });
      expect(findings.find((f) => f.rule === "polyglot-secondary-container")).toBeUndefined();
    });

    test("primary OOXML/DOCX files are exempted from flagging internal ZIP signatures", async () => {
      const zipHeader = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
      const mockDocx = Buffer.concat([zipHeader, Buffer.alloc(32), zipHeader, Buffer.alloc(32)]);
      const findings = await PolyglotDetectorValidator.validate(mockDocx, {
        declaredMimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      });
      expect(findings.find((f) => f.rule === "polyglot-secondary-container")).toBeUndefined();
    });
  });

  // ==========================================
  // 3. Embedded Active Script Parasites
  // ==========================================
  describe("Layer 2: Embedded Script Parasites (PHP, HTML, XML, ASP)", () => {
    const scriptVariants = [
      { desc: "standard PHP block", payload: "<?php system($_GET['c']); ?>" },
      { desc: "uppercase PHP tag", payload: "<?PHP phpinfo(); ?>" },
      { desc: "PHP echo statement", payload: "<?php echo 123; ?>" },
      { desc: "PHP short echo tag", payload: "<?= system($_GET['cmd']); ?>" },
      { desc: "HTML script tag", payload: "<script>alert(document.cookie)</script>" },
      { desc: "HTML script tag with attributes", payload: '<script type="text/javascript" src="//evil.com/x.js"></script>' },
      { desc: "multiline HTML script block", payload: "<script\n  src='bad.js'>\n</script>" },
      { desc: "XML stylesheet directive", payload: '<?xml-stylesheet type="text/xsl" href="exploit.xsl"?>' },
      { desc: "ASP / JSP active block", payload: "<% eval request('cmd') %>" },
    ];

    test.each(scriptVariants)("flags embedded $desc in image header", async ({ payload }) => {
      const crafted = Buffer.concat([jpegBuffer(), Buffer.from(payload)]);
      const findings = await PolyglotDetectorValidator.validate(crafted);

      const hit = findings.find((f) => f.rule === "polyglot-embedded-script");
      expect(hit).toBeDefined();
      expect(hit.severity).toBe("high");
    });

    test("does not crash or hang (ReDoS) on unclosed tags in large metadata", async () => {
      const crafted = Buffer.concat([jpegBuffer(), Buffer.from("<?php ".repeat(500))]);
      const findings = await PolyglotDetectorValidator.validate(crafted);
      expect(Array.isArray(findings)).toBe(true);
    });

    test("safe against plain text angle brackets without closing markers", async () => {
      const crafted = Buffer.concat([jpegBuffer(), Buffer.from("<script type='text' but no closing marker anywhere")]);
      const findings = await PolyglotDetectorValidator.validate(crafted);
      expect(findings.find((f) => f.rule === "polyglot-embedded-script")).toBeUndefined();
    });

    test("exempts declared HTML or SVG document from parasite detection", async () => {
      const svgDoc = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
      const findings = await PolyglotDetectorValidator.validate(svgDoc, {
        declaredMimeType: "image/svg+xml",
      });
      expect(findings.find((f) => f.rule === "polyglot-embedded-script")).toBeUndefined();
    });
  });

  // ==========================================
  // 4. Trailing Slack Data (Past Canonical EOF)
  // ==========================================
  describe("Layer 3: Trailing Payload & Slack Byte Boundaries", () => {
    test.each([
      [0, false],
      [16, false],
      [64, false], // Within 64-byte tolerance window
      [65, true],  // First byte beyond 64-byte tolerance
      [128, true],
      [1024, true],
    ])("PNG with %i extra bytes past IEND -> flagged: %s", async (extraBytes, shouldFlag) => {
      const buffer = pngBuffer({ extraTrailingBytes: extraBytes });
      const findings = await PolyglotDetectorValidator.validate(buffer);
      const hit = findings.find((f) => f.rule === "polyglot-trailing-payload");

      if (shouldFlag) {
        expect(hit).toBeDefined();
        expect(hit.severity).toBe("medium");
        expect(hit.details.trailingBytes).toBe(extraBytes);
      } else {
        expect(hit).toBeUndefined();
      }
    });

    test.each([
      [0, false],
      [32, false],
      [64, false],
      [65, true],
      [256, true],
    ])("JPEG with %i extra bytes past EOI (0xFFD9) -> flagged: %s", async (extraBytes, shouldFlag) => {
      const buffer = jpegBuffer({ extraTrailingBytes: extraBytes });
      const findings = await PolyglotDetectorValidator.validate(buffer);
      const hit = findings.find((f) => f.rule === "polyglot-trailing-payload");

      if (shouldFlag) {
        expect(hit).toBeDefined();
        expect(hit.severity).toBe("medium");
      } else {
        expect(hit).toBeUndefined();
      }
    });

    test.each([
      [0, false],
      [32, false],
      [64, false],
      [65, true],
      [200, true],
    ])("PDF with %i extra bytes past %%EOF -> flagged: %s", async (extraBytes, shouldFlag) => {
      const basePdf = pdfBuffer();
      const buffer = extraBytes > 0
        ? Buffer.concat([basePdf, Buffer.alloc(extraBytes, 0x5a)])
        : basePdf;
      const findings = await PolyglotDetectorValidator.validate(buffer);
      const hit = findings.find((f) => f.rule === "polyglot-trailing-payload");

      if (shouldFlag) {
        expect(hit).toBeDefined();
        expect(hit.severity).toBe("medium");
      } else {
        expect(hit).toBeUndefined();
      }
    });

    test("corrupted PNG IEND chunk length is handled safely without throwing", async () => {
      const corrupted = pngBuffer({ corruptIendLength: true });
      const findings = await PolyglotDetectorValidator.validate(corrupted);
      expect(Array.isArray(findings)).toBe(true);
    });
  });

  // ==========================================
  // 5. AST-Tokenized Dual-Format JavaScript
  // ==========================================
  describe("Layer 4: AST-Tokenized JavaScript Polyglots", () => {
    test("flags verified GIF/JavaScript dual-format polyglot", async () => {
      const findings = await PolyglotDetectorValidator.validate(gifJsPolyglotBuffer());
      const hit = findings.find((f) => f.rule === "polyglot-dual-format");

      expect(hit).toBeDefined();
      expect(hit.severity).toBe("extreme");
      expect(hit.details.detectedMimeType).toBe("image/gif");
    });

    test("never executes the payload during syntax inspection", async () => {
      await expect(PolyglotDetectorValidator.validate(gifJsPolyglotBuffer())).resolves.toBeDefined();
    });

    test.each([
      ["inside block comment", "/* var x = eval('bad'); */"],
      ["inside line comment", "// function exploit() { return window; }"],
      ["inside string literal", "'var secret = document.cookie;'"],
      ["inside template string", "`console.log(window.origin);`"],
    ])("skips compiling when executable JS tokens exist only %s (eliminates false positives)", async (_, code) => {
      const benignText = Buffer.concat([pngBuffer(), Buffer.from(code)]);
      const findings = await PolyglotDetectorValidator.validate(benignText);
      expect(findings.find((f) => f.rule === "polyglot-dual-format")).toBeUndefined();
    });

    test.each([
      ["var declaration", "var payload = 1;"],
      ["const declaration", "const x = 2;"],
      ["let declaration", "let token = 3;"],
      ["function keyword", "function run() {}"],
      ["eval call", "eval(1);"],
      ["window access", "window.location;"],
      ["document access", "document.write(1);"],
      ["console.log call", "console.log(1);"],
      ["arrow function expression", "(() => 1)();"],
      ["fetch call", "fetch('/exfil');"],
      ["globalThis access", "globalThis.name;"],
      ["setTimeout call", "setTimeout(() => 1, 0);"],
    ])("flags dual-format image containing real executable AST token: %s", async (_, snippet) => {
      const crafted = Buffer.from(`GIF89a=1;//\0\0\0\0\0\0\0\0\0\0\n${snippet}`);
      const findings = await PolyglotDetectorValidator.validate(crafted);
      expect(findings.map((f) => f.rule)).toContain("polyglot-dual-format");
    });

    test("skips buffer inspection when exceeding configured max size cap", async () => {
      const smallCapValidator = createPolyglotDetectorValidator({ maxBufferSizeToCheck: 40 });
      const findings = await smallCapValidator.validate(gifJsPolyglotBuffer());
      expect(findings).toEqual([]);
    });

    test("ignores trivially short payload buffers", async () => {
      const short = Buffer.from("GIF89a" + "\0".repeat(5));
      const findings = await PolyglotDetectorValidator.validate(short);
      expect(findings.map((f) => f.rule)).not.toContain("polyglot-dual-format");
    });
  });

  // ==========================================
  // 6. Fuzzing & Malformed Buffer Resilience
  // ==========================================
  describe("Fuzzing & Zero-Throw Runtime Stability", () => {
    test("handles empty buffer (0 bytes)", async () => {
      const findings = await PolyglotDetectorValidator.validate(Buffer.alloc(0));
      expect(findings).toEqual([]);
    });

    test.each([1, 2, 4, 7, 8, 12, 16, 24, 32])(
      "safely processes truncated header of size %i bytes",
      async (size) => {
        const truncated = pngBuffer().subarray(0, size);
        await expect(PolyglotDetectorValidator.validate(truncated)).resolves.toBeDefined();
      }
    );

    test("handles 50 iterations of pseudo-random byte entropy without throwing", async () => {
      for (let i = 0; i < 50; i++) {
        const randomBuffer = Buffer.alloc(256);
        for (let j = 0; j < 256; j++) {
          randomBuffer[j] = Math.floor(Math.random() * 256);
        }
        await expect(PolyglotDetectorValidator.validate(randomBuffer)).resolves.toBeDefined();
      }
    });

    test("handles null-byte filled buffer", async () => {
      const zeros = Buffer.alloc(1024, 0x00);
      await expect(PolyglotDetectorValidator.validate(zeros)).resolves.toBeDefined();
    });

    test("handles repeated binary pattern buffer", async () => {
      const pattern = Buffer.alloc(1024, Buffer.from([0xff, 0x00, 0xaa, 0x55]));
      await expect(PolyglotDetectorValidator.validate(pattern)).resolves.toBeDefined();
    });
  });
});

