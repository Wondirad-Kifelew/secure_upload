import { shouldSandbox } from "../src/index.js";

describe("Sandbox policy", () => {
  test("does not trigger below the risk threshold with no findings", () => {
    const result = shouldSandbox({ riskScore: 20, findings: [] });
    expect(result.required).toBe(false);
  });

  test("triggers at the configured risk threshold", () => {
    const result = shouldSandbox({ riskScore: 60, findings: [] });
    expect(result.required).toBe(true);
  });

  test("triggers for a high-severity finding even without a risk score", () => {
    const result = shouldSandbox({
      findings: [
        {
          rule: "magic-byte-mismatch",
          severity: "high",
          message: "Mismatch",
        },
      ],
    });

    expect(result.required).toBe(true);
  });

  test("triggers for behavior-sensitive evidence", () => {
    const result = shouldSandbox({
      findings: [
        {
          rule: "macro-detected",
          severity: "medium",
          message: "Macro present",
        },
      ],
    });

    expect(result.required).toBe(true);
  });
});
