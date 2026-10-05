import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { MagicByteValidator } from "@secureupload/validators";
import { QuarantineStore } from "@secureupload/quarantine";
import { DryRunSandboxAdapter, SandboxManager } from "@secureupload/sandbox";
import { createBootstrapAnomalyDetector } from "@secureupload/risk-engine";
import { LocalExplanationProvider } from "@secureupload/ai";
import { UploadSecurityService } from "../src/index.js";

describe("UploadSecurityService ML + AI integration", () => {
  test("returns anomaly, risk, and AI explanation without executing the file", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secureupload-ml-ai-"));
    try {
      const service = new UploadSecurityService({
        validators: [MagicByteValidator],
        quarantineStore: new QuarantineStore({ rootDirectory: root }),
        sandboxManager: new SandboxManager({ adapter: new DryRunSandboxAdapter(), threshold: 60 }),
        anomalyDetector: createBootstrapAnomalyDetector({ threshold: 0.58 }),
        aiProvider: new LocalExplanationProvider(),
      });

      const result = await service.analyze({
        buffer: Buffer.from("this is not really a png"),
        filename: "image.png",
        declaredMimeType: "image/png",
      });

      expect(result.ml.status).toBe("completed");
      expect(result.ml.anomalyScore).toBeGreaterThanOrEqual(0);
      expect(result.ml.anomalyScore).toBeLessThanOrEqual(1);
      expect(result.risk.policyVersion).toBe("risk-v1");
      expect(result.ai.provider).toBe("local");
      expect(result.ai.explanation).toMatch(/risk engine/i);
      expect(result.sandbox.result?.executed ?? false).toBe(false);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
