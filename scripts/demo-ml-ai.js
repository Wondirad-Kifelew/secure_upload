import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { UploadSecurityService } from "../packages/service/src/index.js";
import { QuarantineStore } from "../packages/quarantine/src/index.js";
import { DryRunSandboxAdapter, SandboxManager } from "../packages/sandbox/src/index.js";
import { createAIProviderFromEnv } from "../packages/ai/src/index.js";

const root = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-demo-"));
try {
  const demoSignalValidator = {
    name: "DemoSignalValidator",
    async validate() {
      return [
        {
          rule: "macro-detected",
          severity: "high",
          message: "Synthetic demo signal: macro-like active content was detected.",
          details: { demo: true },
        },
      ];
    },
  };

  const service = new UploadSecurityService({
    validators: [demoSignalValidator],
    quarantineStore: new QuarantineStore({ rootDirectory: root }),
    sandboxManager: new SandboxManager({
      adapter: new DryRunSandboxAdapter(),
      threshold: 30,
    }),
    // With no ANOMALY_MODEL_PATH, the service uses its development bootstrap model.
    // With no OPENAI_API_KEY, the AI layer uses the local provider.
    // Set either variable to use a trained ML model or remote AI.
    aiProvider: createAIProviderFromEnv(),
  });

  const result = await service.analyze({
    buffer: Buffer.from("SAFE DEMO DATA — not malware"),
    filename: "training-example.docm",
    declaredMimeType: "application/vnd.ms-word.document.macroEnabled.12",
  });

  console.log(JSON.stringify({
    features: {
      vector: result.features.vector,
      entropy: result.features.entropy,
      macroDetected: result.features.macroDetected,
    },
    ml: result.ml,
    risk: result.risk,
    ai: result.ai,
    sandbox: {
      status: result.sandbox.status,
      triggered: result.sandbox.triggered,
      executed: result.sandbox.result?.executed ?? false,
    },
    quarantine: {
      id: result.quarantine.id,
      status: result.quarantine.status,
      sha256: result.quarantine.sha256,
    },
  }, null, 2));
} finally {
  await fs.rm(root, { recursive: true, force: true });
}
