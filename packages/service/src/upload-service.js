import { PipelineContext, ValidationPipeline } from "@secureupload/core";
import { evaluateQuarantine, QuarantineStore } from "@secureupload/quarantine";
import { SandboxManager, shouldSandbox } from "@secureupload/sandbox";
import { calculateRisk, createAnomalyDetectorFromEnv, createBootstrapAnomalyDetector, extractFeatures } from "@secureupload/risk-engine";
import { createAIProviderFromEnv } from "@secureupload/ai";

/**
 * Application-facing security workflow.
 *
 * Security stages:
 * validation -> quarantine -> feature extraction -> ML anomaly ->
 * deterministic risk -> AI explanation -> conditional sandbox.
 *
 * ML and AI are advisory evidence layers. They do not replace validation or
 * the deterministic policy, and AI is never allowed to override the policy.
 */
export class UploadSecurityService {
  constructor({
    validators = [],
    quarantineStore = new QuarantineStore(),
    sandboxManager,
    anomalyDetector = createAnomalyDetectorFromEnv() ?? createBootstrapAnomalyDetector(),
    aiProvider = createAIProviderFromEnv(),
  } = {}) {
    if (!sandboxManager) {
      throw new TypeError("UploadSecurityService requires a SandboxManager.");
    }

    this.validationPipeline = new ValidationPipeline(validators);
    this.quarantineStore = quarantineStore;
    this.sandboxManager = sandboxManager;
    this.anomalyDetector = anomalyDetector;
    this.aiProvider = aiProvider;
  }

  async analyze({ buffer, filename, declaredMimeType, riskScore = null } = {}) {
    if (!Buffer.isBuffer(buffer)) {
      throw new TypeError("UploadSecurityService.analyze expects a Buffer.");
    }

    const context = new PipelineContext({ filename, declaredMimeType });
    await this.validationPipeline.run(buffer, context);

    // Every upload enters quarantine before deeper analysis or release.
    const quarantineDecision = evaluateQuarantine(context.findings);
    const quarantine = await this.quarantineStore.put(
      buffer,
      { filename, declaredMimeType },
      quarantineDecision
    );

    // Turn heterogeneous validator observations into a stable numeric vector.
    const features = extractFeatures({
      buffer,
      findings: context.findings,
      filename,
    });

    // ML failure must not silently become a release decision. Keep the
    // deterministic engine operational and record the ML failure as evidence.
    let ml;
    if (!this.anomalyDetector) {
      ml = { status: "not-configured", anomalyScore: null, isAnomalous: false };
    } else {
      try {
        ml = { status: "completed", ...this.anomalyDetector.predict(features.vector) };
      } catch (error) {
        ml = {
          status: "failed",
          anomalyScore: null,
          isAnomalous: false,
          error: { name: error.name, message: error.message },
        };
      }
    }

    const initialRisk = calculateRisk({
      features,
      anomaly: Number.isFinite(ml.anomalyScore) ? ml : null,
      findings: context.findings,
      riskOverride: riskScore,
    });

    // Sandbox triggering uses deterministic findings + the calculated score.
    const triggerScore = Math.max(
      Number.isFinite(initialRisk.score) ? initialRisk.score : 0,
      Number.isFinite(riskScore) ? riskScore : 0
    );

    const trigger = shouldSandbox({
      findings: context.findings,
      riskScore: triggerScore,
      threshold: this.sandboxManager.threshold,
    });

    if (trigger.required) {
      await this.quarantineStore.transition(quarantine.id, "sandboxing", {
        sandboxTrigger: trigger,
      });
    }

    const sandbox = await this.sandboxManager.analyze({
      quarantineRecord: quarantine,
      findings: context.findings,
      riskScore: triggerScore,
      metadata: {
        uploadId: quarantine.id,
        filename,
        declaredMimeType,
        sha256: quarantine.sha256,
      },
    });

    const finalRisk = calculateRisk({
      features,
      anomaly: Number.isFinite(ml.anomalyScore) ? ml : null,
      findings: context.findings,
      sandbox: sandbox.result,
    });

    // AI receives structured evidence only. Raw file bytes are never sent.
    let ai = null;
    if (this.aiProvider) {
      try {
        ai = await this.aiProvider.explain({
          filename,
          declaredMimeType,
          sizeBytes: buffer.length,
          sha256: quarantine.sha256,
          features,
          findings: context.findings,
          anomaly: ml,
          risk: finalRisk,
          sandbox: {
            triggered: sandbox.triggered,
            status: sandbox.status,
            result: sandbox.result,
          },
        });
      } catch (error) {
        ai = {
          provider: "error",
          model: null,
          explanation: null,
          error: { name: error.name, message: error.message },
        };
      }
    }

    context.features = features;
    context.ml = ml;
    context.risk = finalRisk;
    context.ai = ai;

    if (sandbox.triggered && sandbox.status === "completed") {
      await this.quarantineStore.transition(quarantine.id, "sandboxed", {
        sandbox: sandbox.result,
        ml: ml.status === "completed" ? { anomalyScore: ml.anomalyScore, isAnomalous: ml.isAnomalous } : ml,
        risk: finalRisk,
        ai: ai ? { provider: ai.provider, model: ai.model, explanation: ai.explanation } : null,
      });
    } else if (sandbox.triggered && sandbox.status === "failed") {
      await this.quarantineStore.transition(quarantine.id, "manual-review", {
        sandboxError: sandbox.error,
        ml: ml.status === "completed" ? { anomalyScore: ml.anomalyScore, isAnomalous: ml.isAnomalous } : ml,
        risk: finalRisk,
        ai: ai ? { provider: ai.provider, model: ai.model, explanation: ai.explanation } : null,
      });
    } else {
      await this.quarantineStore.annotate(quarantine.id, {
        ml: ml.status === "completed" ? { anomalyScore: ml.anomalyScore, isAnomalous: ml.isAnomalous } : ml,
        risk: finalRisk,
        ai: ai ? { provider: ai.provider, model: ai.model, explanation: ai.explanation } : null,
      });
    }

    const finalQuarantine = await this.quarantineStore.get(quarantine.id);

    return {
      context,
      quarantine: finalQuarantine,
      features,
      ml,
      risk: finalRisk,
      ai,
      sandbox,
    };
  }
}
