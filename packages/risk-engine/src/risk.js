const WEIGHTS = Object.freeze({
  typeMismatch: 12,
  filenameRisk: 6,
  macroDetected: 18,
  embeddedObjectDetected: 14,
  scriptDetected: 14,
  suspiciousExecutable: 18,
  zipBombSignal: 20,
  highFinding: 7,
  extremeFinding: 15,
  anomaly: 20,
  sandboxSuspicious: 25,
  outboundNetwork: 8,
  createdExecutable: 10,
  suspiciousChildProcess: 12,
});

function clamp(value, min = 0, max = 100) {
  return Math.max(min, Math.min(max, value));
}

function dynamicFlags(dynamic) {
  const filesCreated = dynamic?.filesCreated ?? [];
  const suspiciousBehaviors = dynamic?.suspiciousBehaviors ?? [];
  const processes = dynamic?.processes ?? [];
  const dnsQueries = dynamic?.dnsQueries ?? [];
  const networkConnections = dynamic?.networkConnections ?? [];

  return {
    suspicious: suspiciousBehaviors.length > 0,
    createdExecutable:
      Boolean(dynamic?.createdExecutable) || filesCreated.some((file) => /\.(exe|dll|scr|bat|cmd)$/i.test(String(file))),
    suspiciousChildProcess:
      Boolean(dynamic?.suspiciousChildProcess)
      || processes.some((process) => /powershell|cmd\.exe|wscript|cscript|rundll32/i.test(String(process.child ?? process))),
    outboundNetwork:
      Boolean(dynamic?.outboundNetwork) || networkConnections.length > 0 || dnsQueries.length > 0,
  };
}

export function calculateRisk({ features = {}, anomaly = null, findings = [], sandbox = null } = {}) {
  let score = 0;
  const reasons = [];
  const contributions = [];

  const add = (condition, weight, reason) => {
    if (!condition) return;
    score += weight;
    contributions.push({ signal: reason, points: weight });
    reasons.push(reason);
  };

  add(features.typeMismatch, WEIGHTS.typeMismatch, "File type/content mismatch detected");
  add(features.filenameRisk, WEIGHTS.filenameRisk, "Risky filename characteristics detected");
  add(features.macroDetected, WEIGHTS.macroDetected, "Macro-related content detected");
  add(features.embeddedObjectDetected, WEIGHTS.embeddedObjectDetected, "Embedded-object content detected");
  add(features.scriptDetected, WEIGHTS.scriptDetected, "Script-related content detected");
  add(features.suspiciousExecutable, WEIGHTS.suspiciousExecutable, "Executable content is suspicious");
  add(features.zipBombSignal, WEIGHTS.zipBombSignal, "Archive expansion/zip-bomb signal detected");

  const highCount = findings.filter((finding) => finding.severity === "high").length;
  const extremeCount = findings.filter((finding) => finding.severity === "extreme").length;
  if (highCount > 0) {
    const points = Math.min(highCount * WEIGHTS.highFinding, 20);
    score += points;
    contributions.push({ signal: "High-severity findings", points });
    reasons.push(`${highCount} high-severity finding(s)`);
  }
  if (extremeCount > 0) {
    const points = Math.min(extremeCount * WEIGHTS.extremeFinding, 30);
    score += points;
    contributions.push({ signal: "Extreme-severity findings", points });
    reasons.push(`${extremeCount} extreme-severity finding(s)`);
  }

  if (anomaly && Number.isFinite(anomaly.anomalyScore)) {
    // Isolation Forest scores around 0.5 for a typical baseline. Only the
    // excess above 0.5 contributes to risk, preventing neutral predictions
    // from adding a large score to every file.
    const points = Math.max(0, clamp((anomaly.anomalyScore - 0.5) * 40, 0, 1)) * WEIGHTS.anomaly;
    score += points;
    contributions.push({ signal: "ML anomaly score", points: Number(points.toFixed(2)) });
    if (anomaly.isAnomalous) reasons.push("ML model classified the file as anomalous");
  }

  const dynamic = sandbox?.result ?? sandbox;
  if (dynamic) {
    const flags = dynamicFlags(dynamic);
    add(flags.suspicious, WEIGHTS.sandboxSuspicious, "Sandbox reported suspicious behavior");
    add(flags.createdExecutable, WEIGHTS.createdExecutable, "Sandbox observed executable file creation");
    add(flags.suspiciousChildProcess, WEIGHTS.suspiciousChildProcess, "Sandbox observed a suspicious child process");
    add(flags.outboundNetwork, WEIGHTS.outboundNetwork, "Sandbox observed outbound network activity");
  }

  return {
    score: Math.round(clamp(score) * 100) / 100,
    reasons: [...new Set(reasons)],
    contributions,
    policyVersion: "risk-v1",
  };
}
