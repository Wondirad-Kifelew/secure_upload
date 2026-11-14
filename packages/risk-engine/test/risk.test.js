import { calculateRisk } from "../src/index.js";

describe("risk engine", () => {
  test("includes ML and evidence contributions", () => {
    const result = calculateRisk({
      features: { typeMismatch: true, macroDetected: true },
      findings: [{ severity: "high", rule: "macro-detected" }],
      anomaly: { anomalyScore: 0.9, isAnomalous: true },
    });

    expect(result.score).toBeGreaterThan(0);
    expect(result.reasons).toContain("ML model classified the file as anomalous");
    expect(result.policyVersion).toBe("risk-v1");
  });

  test("a caller-provided score raises the computed risk to a floor", () => {
    const result = calculateRisk({
      features: {},
      findings: [],
      riskOverride: 90,
    });

    expect(result.score).toBe(90);
    expect(result.reasons).toContain("Caller-provided risk score exceeded the computed score");
  });

  test("a caller-provided score cannot lower evidence-based risk", () => {
    const baseline = calculateRisk({
      features: { typeMismatch: true, macroDetected: true },
      findings: [{ severity: "extreme", rule: "macro-detected" }],
    });
    const result = calculateRisk({
      features: { typeMismatch: true, macroDetected: true },
      findings: [{ severity: "extreme", rule: "macro-detected" }],
      riskOverride: 1,
    });

    expect(result.score).toBe(baseline.score);
  });
});
