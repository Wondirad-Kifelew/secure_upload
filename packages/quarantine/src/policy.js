/**
 * Initial quarantine policy.
 *
 * Zero-trust rule: every upload is stored in quarantine before it can be
 * released to the application. This function decides whether the file also
 * carries an explicit "suspicious" reason based on what the validators have
 * already observed.
 */

const SEVERITY_WEIGHT = {
  low: 10,
  medium: 25,
  high: 60,
  extreme: 100,
};

export function evaluateQuarantine(findings = [], options = {}) {
  const suspiciousThreshold = options.suspiciousThreshold ?? 60;

  const evidence = findings.map((finding) => ({
    rule: finding.rule,
    severity: finding.severity,
    message: finding.message,
    source: finding.source ?? null,
  }));

  const strongestFinding = findings.reduce((strongest, finding) => {
    const weight = SEVERITY_WEIGHT[finding.severity] ?? 0;
    const strongestWeight = strongest ? SEVERITY_WEIGHT[strongest.severity] ?? 0 : -1;
    return weight > strongestWeight ? finding : strongest;
  }, null);

  const suspicionScore = findings.reduce(
    (total, finding) => Math.max(total, SEVERITY_WEIGHT[finding.severity] ?? 0),
    0
  );

  return {
    storageState: "quarantined",
    suspicious: suspicionScore >= suspiciousThreshold,
    requiresSandbox: findings.some(
      (finding) => finding.severity === "high" || finding.severity === "extreme"
    ),
    suspicionScore,
    strongestFinding: strongestFinding
      ? {
          rule: strongestFinding.rule,
          severity: strongestFinding.severity,
        }
      : null,
    evidence,
  };
}
