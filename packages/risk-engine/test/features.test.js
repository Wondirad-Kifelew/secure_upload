import { extractFeatures, FEATURE_NAMES } from "../src/index.js";

describe("feature extraction", () => {
  test("creates a stable numeric vector", () => {
    const result = extractFeatures({
      buffer: Buffer.from("hello world"),
      filename: "invoice.pdf",
      findings: [
        { rule: "magic-byte-mismatch", severity: "high" },
        { rule: "macro-detected", severity: "medium" },
      ],
    });

    expect(result.vector).toHaveLength(FEATURE_NAMES.length);
    expect(result.typeMismatch).toBe(true);
    expect(result.macroDetected).toBe(true);
    expect(result.vector.every(Number.isFinite)).toBe(true);
  });

  test("maps real finding rule names to features", () => {
    const result = extractFeatures({
      buffer: Buffer.from("hello world"),
      filename: "invoice.pdf",
      findings: [
        { rule: "extension-content-mismatch", severity: "high" },
        { rule: "zip-bomb-compression-ratio", severity: "high" },
        { rule: "ooxml-macro-removed", severity: "medium" },
        { rule: "ooxml-embedded-object-removed", severity: "medium" },
        { rule: "ooxml-activex-removed", severity: "medium" },
        { rule: "polyglot-embedded-script", severity: "high" },
        { rule: "zip-executable-content", severity: "high" },
      ],
    });

    expect(result.typeMismatch).toBe(true);
    expect(result.zipBombSignal).toBe(true);
    expect(result.macroDetected).toBe(true);
    expect(result.embeddedObjectDetected).toBe(true);
    expect(result.scriptDetected).toBe(true);
    expect(result.suspiciousExecutable).toBe(true);
  });
});
