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
});
