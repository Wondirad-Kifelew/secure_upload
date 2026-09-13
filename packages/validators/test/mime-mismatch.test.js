import { MimeMismatchValidator } from "../src/mime-mismatch.js";

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

describe("MimeMismatchValidator", () => {
  test("has the expected Validator shape", () => {
    expect(MimeMismatchValidator.name).toBe("MIME Mismatch Detector");
    expect(typeof MimeMismatchValidator.validate).toBe("function");
  });

  test("a correctly named, correctly declared, correctly-content file produces no findings", async () => {
    const findings = await MimeMismatchValidator.validate(pngBuffer(), {
      filename: "photo.png",
      declaredMimeType: "image/png",
    });
    expect(findings).toEqual([]);
  });

  test("no filename provided produces no findings", async () => {
    const findings = await MimeMismatchValidator.validate(pngBuffer(), {});
    expect(findings).toEqual([]);
  });

  test("an unrecognized extension produces no findings (nothing to compare against)", async () => {
    const findings = await MimeMismatchValidator.validate(pngBuffer(), {
      filename: "data.xyz",
      declaredMimeType: "image/png",
    });
    expect(findings).toEqual([]);
  });

  test("flags extension-vs-declared mismatch when content still matches the extension", async () => {
    const findings = await MimeMismatchValidator.validate(pngBuffer(), {
      filename: "photo.png",
      declaredMimeType: "application/pdf",
    });
    const rules = findings.map((f) => f.rule);
    expect(rules).toContain("extension-declared-mismatch");
    expect(rules).not.toContain("extension-content-mismatch"); // content really is a png
  });

  test("flags extension-vs-content mismatch — the renamed-file / double-extension case", async () => {
    const findings = await MimeMismatchValidator.validate(pngBuffer(), {
      filename: "resume.pdf",
      declaredMimeType: "application/pdf", // declared type even agrees with the (wrong) extension
    });
    const finding = findings.find((f) => f.rule === "extension-content-mismatch");
    expect(finding).toBeDefined();
    expect(finding.severity).toBe("high");
    expect(finding.details.detectedMimeType).toBe("image/png");
  });

  test("only checks the LAST extension in a double-extension filename", async () => {
    const findings = await MimeMismatchValidator.validate(pngBuffer(), {
      filename: "resume.php.jpg",
    });
    const finding = findings.find((f) => f.rule === "extension-content-mismatch");
    expect(finding).toBeDefined();
    expect(finding.details.extension).toBe(".jpg");
  });

  test("a real PDF named .pdf produces no content mismatch", async () => {
    const findings = await MimeMismatchValidator.validate(pdfBuffer(), {
      filename: "contract.pdf",
      declaredMimeType: "application/pdf",
    });
    expect(findings).toEqual([]);
  });

  test("does not false-positive on legacy .doc files (which sniff as generic CFB)", async () => {
    const cfbSignature = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, ...Array(50).fill(0)]);
    const findings = await MimeMismatchValidator.validate(cfbSignature, {
      filename: "old-report.doc",
      declaredMimeType: "application/msword",
    });
    expect(findings).toEqual([]);
  });
});