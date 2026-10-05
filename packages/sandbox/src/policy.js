/**
 * Sandbox trigger policy.
 *
 * The default policy is conservative: high/extreme findings or a sufficiently
 * high pre-sandbox risk score trigger dynamic analysis. The score threshold is
 * intentionally configurable because the project's later risk engine will own
 * the final scoring policy.
 */
export function shouldSandbox({ findings = [], riskScore = null, threshold = 60 } = {}) {
  if (Number.isFinite(riskScore) && riskScore >= threshold) {
    return {
      required: true,
      reason: `Risk score ${riskScore} reached sandbox threshold ${threshold}`,
    };
  }

  const highSeverity = findings.find(
    (finding) => finding.severity === "high" || finding.severity === "extreme"
  );

  if (highSeverity) {
    return {
      required: true,
      reason: `High-priority finding: ${highSeverity.rule}`,
    };
  }

  const behaviorSensitiveRule = findings.find((finding) =>
    [
      "macro-detected",
      "embedded-object-detected",
      "script-detected",
      "suspicious-executable",
    ].includes(finding.rule)
  );

  if (behaviorSensitiveRule) {
    return {
      required: true,
      reason: `Behavior-sensitive content detected: ${behaviorSensitiveRule.rule}`,
    };
  }

  return {
    required: false,
    reason: "No sandbox trigger matched",
  };
}
