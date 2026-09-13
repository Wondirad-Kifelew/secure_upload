import { MagicByteValidator } from "../src/magic-byte.js";

/**
 * Minimal-but-real magic-byte fixtures. These aren't full valid files —
 * just enough bytes for the file-type library's signature parser to
 * confidently identify the format, which is all this validator cares
 * about. Kept inline (not as binary fixture files) since they're tiny
 * and it's obvious from reading the test what each one represents.
 */
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

function plainTextBuffer() {
  return Buffer.from("just some plain text, nothing special here at all, padded out a bit more");
}

describe("MagicByteValidator", () => {
  test("has the expected Validator shape", () => {
    expect(MagicByteValidator.name).toBe("Magic Byte Sniffer");
    expect(typeof MagicByteValidator.validate).toBe("function");
  });

  test("returns no findings when no declaredMimeType is given", async () => {
    const findings = await MagicByteValidator.validate(pngBuffer(), {});
    expect(findings).toEqual([]);
  });

  test("returns no findings when declared type matches the sniffed content (PNG)", async () => {
    const findings = await MagicByteValidator.validate(pngBuffer(), {
      declaredMimeType: "image/png",
    });
    expect(findings).toEqual([]);
  });

  test("returns no findings when declared type matches the sniffed content (PDF)", async () => {
    const findings = await MagicByteValidator.validate(pdfBuffer(), {
      declaredMimeType: "application/pdf",
    });
    expect(findings).toEqual([]);
  });

  test("flags a mismatch when a PNG is declared as a PDF (spoofing case)", async () => {
    const findings = await MagicByteValidator.validate(pngBuffer(), {
      declaredMimeType: "application/pdf",
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("magic-byte-mismatch");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].details.declaredMimeType).toBe("application/pdf");
    expect(findings[0].details.detectedMimeType).toBe("image/png");
  });

  test("flags undetected content when declared type can't be verified from magic bytes", async () => {
    const findings = await MagicByteValidator.validate(plainTextBuffer(), {
      declaredMimeType: "image/png",
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("magic-byte-undetected");
    expect(findings[0].severity).toBe("low");
  });
});
