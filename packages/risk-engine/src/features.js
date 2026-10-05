export const FEATURE_NAMES = Object.freeze([
  "sizeLog10",
  "entropy",
  "findingCount",
  "lowCount",
  "mediumCount",
  "highCount",
  "extremeCount",
  "macroDetected",
  "embeddedObjectDetected",
  "scriptDetected",
  "suspiciousExecutable",
  "typeMismatch",
  "zipBombSignal",
  "filenameRisk",
]);

function countSeverity(findings, severity) {
  return findings.filter((finding) => finding.severity === severity).length;
}

function hasRule(findings, rules) {
  return findings.some((finding) => rules.includes(finding.rule));
}

function entropyOf(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) return 0;

  const frequencies = new Array(256).fill(0);
  for (const byte of buffer) frequencies[byte] += 1;

  let entropy = 0;
  for (const count of frequencies) {
    if (count === 0) continue;
    const p = count / buffer.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function extractFeatures({ buffer, findings = [], filename = "" } = {}) {
  if (!Buffer.isBuffer(buffer)) {
    throw new TypeError("extractFeatures expects a Buffer.");
  }

  const lowCount = countSeverity(findings, "low");
  const mediumCount = countSeverity(findings, "medium");
  const highCount = countSeverity(findings, "high");
  const extremeCount = countSeverity(findings, "extreme");

  const macroDetected = hasRule(findings, ["macro-detected", "macro"]);
  const embeddedObjectDetected = hasRule(findings, ["embedded-object-detected", "embedded-object"]);
  const scriptDetected = hasRule(findings, ["script-detected", "script"]);
  const suspiciousExecutable = hasRule(findings, ["suspicious-executable", "executable-detected"]);
  const typeMismatch = hasRule(findings, [
    "mime-mismatch",
    "magic-byte-mismatch",
    "extension-mismatch",
    "type-mismatch",
  ]);
  const zipBombSignal = hasRule(findings, ["zip-bomb", "zip-bomb-suspected", "archive-expansion"]);

  const lowerName = String(filename).toLowerCase();
  const filenameRisk = /(^|[.\\/])\.\.?($|[.\\/])/.test(lowerName)
    || /[<>:"|?*]/.test(lowerName)
    || /\p{C}/u.test(lowerName);

  const features = {
    sizeBytes: buffer.length,
    sizeLog10: Math.log10(Math.max(buffer.length, 1)),
    entropy: entropyOf(buffer),
    findingCount: findings.length,
    lowCount,
    mediumCount,
    highCount,
    extremeCount,
    macroDetected,
    embeddedObjectDetected,
    scriptDetected,
    suspiciousExecutable,
    typeMismatch,
    zipBombSignal,
    filenameRisk,
  };

  return {
    ...features,
    vector: FEATURE_NAMES.map((name) => Number(features[name] || 0)),
  };
}
