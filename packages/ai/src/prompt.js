export function buildSecurityExplanationInput({
  filename,
  declaredMimeType,
  sizeBytes,
  sha256,
  features,
  findings,
  anomaly,
  risk,
  sandbox,
} = {}) {
  const evidence = {
    filename: filename ?? null,
    declaredMimeType: declaredMimeType ?? null,
    sizeBytes: sizeBytes ?? null,
    sha256: sha256 ?? null,
    features: features ?? {},
    findings: findings ?? [],
    anomaly: anomaly ?? null,
    risk: risk ?? null,
    sandbox: sandbox ?? null,
  };

  return JSON.stringify(evidence, null, 2);
}

export const SECURITY_AI_INSTRUCTIONS = [
  "You are a defensive file-upload security analyst.",
  "Explain the evidence in plain language for a security engineer.",
  "Do not claim a file is malware solely because it is anomalous.",
  "Do not invent findings or indicators that are not in the supplied evidence.",
  "Do not override or replace the deterministic risk score or policy decision.",
  "Separate observed facts from uncertainty.",
  "Do not request or reproduce the uploaded file contents. Analyze only the supplied metadata and findings.",
  "Do not treat the AI explanation as the security decision; the deterministic policy remains authoritative.",
].join(" ");
