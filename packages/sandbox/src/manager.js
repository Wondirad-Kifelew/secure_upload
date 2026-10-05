import { shouldSandbox } from "./policy.js";

export class SandboxManager {
  constructor({ adapter, threshold = 60 } = {}) {
    if (!adapter || typeof adapter.analyze !== "function") {
      throw new TypeError("SandboxManager requires an adapter with an analyze() method.");
    }

    this.adapter = adapter;
    this.threshold = threshold;
  }

  async analyze({ quarantineRecord, findings = [], riskScore = null, metadata = {} }) {
    const trigger = shouldSandbox({
      findings,
      riskScore,
      threshold: this.threshold,
    });

    if (!trigger.required) {
      return {
        status: "skipped",
        triggered: false,
        trigger,
        result: null,
      };
    }

    const startedAt = new Date().toISOString();

    try {
      const result = await this.adapter.analyze({
        samplePath: quarantineRecord.samplePath,
        timeoutMs: 30_000,
        metadata,
      });

      return {
        status: "completed",
        triggered: true,
        trigger,
        startedAt,
        completedAt: new Date().toISOString(),
        result,
      };
    } catch (error) {
      return {
        status: "failed",
        triggered: true,
        trigger,
        startedAt,
        completedAt: new Date().toISOString(),
        error: {
          name: error.name,
          message: error.message,
        },
      };
    }
  }
}
