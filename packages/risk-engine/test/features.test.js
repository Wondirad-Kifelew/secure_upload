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
});
