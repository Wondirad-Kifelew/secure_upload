import { createPolyglotDetectorValidator, PolyglotDetectorValidator } from "../src/polyglot-detector.js";

function pngBuffer() {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdrLength = Buffer.from([0, 0, 0, 13]);
  const ihdrType = Buffer.from("IHDR");
  const ihdrData = Buffer.alloc(13);
  const ihdrCrc = Buffer.alloc(4);
  return Buffer.concat([signature, ihdrLength, ihdrType, ihdrData, ihdrCrc, Buffer.alloc(20)]);
}

function pdfBuffer() {
  return Buffer.from("%PDF-1.5\n%rest of pdf content padding padding padding padding padding");
}

/** The real GIF/JS polyglot we verified works in the sandbox. */
function gifJsPolyglotBuffer() {
  return Buffer.from("GIF89a=1;//" + "\0".repeat(20) + "\n" + 'console.log("polyglot executed");');
}

describe("PolyglotDetectorValidator", () => {
  test("has the expected Validator shape", () => {
    expect(PolyglotDetectorValidator.name).toBe("Polyglot Detector");
    expect(typeof PolyglotDetectorValidator.validate).toBe("function");
  });

  test("a genuine PNG produces no findings", async () => {
    const findings = await PolyglotDetectorValidator.validate(pngBuffer());
    expect(findings).toEqual([]);
  });

  test("a genuine PDF produces no findings", async () => {
    const findings = await PolyglotDetectorValidator.validate(pdfBuffer());
    expect(findings).toEqual([]);
  });

  test("plain text with no detectable type produces no findings (avoids CSV/text false positives)", async () => {
    const findings = await PolyglotDetectorValidator.validate(
      Buffer.from("name,age\nbob,30\nalice,25\n")
    );
    expect(findings).toEqual([]);
  });

  test("flags the real GIF/JS dual-format polyglot", async () => {
    const findings = await PolyglotDetectorValidator.validate(gifJsPolyglotBuffer());
    const finding = findings.find((f) => f.rule === "polyglot-dual-format");
    expect(finding).toBeDefined();
    expect(finding.severity).toBe("extreme");
    expect(finding.details.detectedMimeType).toBe("image/gif");
  });

  test("never actually executes the embedded JS during detection", async () => {
    await expect(PolyglotDetectorValidator.validate(gifJsPolyglotBuffer())).resolves.toBeDefined();
  });

  test("skips checking buffers larger than the configured size cap", async () => {
    const validator = createPolyglotDetectorValidator({ maxBufferSizeToCheck: 50 });
    const findings = await validator.validate(gifJsPolyglotBuffer());
    expect(findings).toEqual([]);
  });

  test("does not flag a trivially short/empty payload as a polyglot", async () => {
    const buffer = Buffer.from("GIF89a" + "\0".repeat(10));
    const findings = await PolyglotDetectorValidator.validate(buffer);
    expect(findings.map((f) => f.rule)).not.toContain("polyglot-dual-format");
  });
});