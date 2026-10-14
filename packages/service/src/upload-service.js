import { PipelineContext, ValidationPipeline } from "@secureupload/core";
import { evaluateQuarantine, QuarantineStore } from "@secureupload/quarantine";
import { SandboxManager, shouldSandbox } from "@secureupload/sandbox";
import { calculateRisk, createAnomalyDetectorFromEnv, createBootstrapAnomalyDetector, extractFeatures } from "@secureupload/risk-engine";
import { createAIProviderFromEnv } from "@secureupload/ai";
import { ScanPipeline } from "@secureupload/scanners";
import { ImageSanitizer, PdfSanitizer, OoxmlSanitizer } from "@secureupload/cdr";


/**
 * Which CDR sanitizer applies to a given declared MIME type. There is no
 * entry for OOXML (docx/xlsx/pptx) yet — that sanitizer doesn't exist,
 * so those files simply skip CDR and pass through as-is. Order matters:
 * first match wins.
 */
const OOXML_MIME_TYPES = new Set([
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "application/vnd.ms-word.document.macroEnabled.12",
  "application/vnd.ms-excel.sheet.macroEnabled.12",
  "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
]);

const DEFAULT_SANITIZER_RULES = [
  { test: (mime) => typeof mime === "string" && mime.startsWith("image/"), sanitizer: ImageSanitizer },
  { test: (mime) => mime === "application/pdf", sanitizer: PdfSanitizer },
  { test: (mime) => OOXML_MIME_TYPES.has(mime), sanitizer: OoxmlSanitizer },
];

/**
 * Application-facing security workflow.
 *
 * Security stages:
 * validation -> scanning -> CDR sanitization -> quarantine ->
 * feature extraction -> ML anomaly -> deterministic risk ->
 * AI explanation -> conditional sandbox.
 *
 * Quarantine, risk scoring, the sandbox and AI explanation all operate on
 * the SANITIZED buffer, not the original upload — once CDR has rebuilt a
 * clean version, that's the artifact the rest of the pipeline treats as
 * canonical. The original bytes are not separately retained today (known
 * simplification, not an oversight).
 *
 * ML and AI are advisory evidence layers. They do not replace validation or
 * the deterministic policy, and AI is never allowed to override the policy.
 */
export class UploadSecurityService {
  constructor({
    validators = [],
    scanners = [],
    sanitizerRules = DEFAULT_SANITIZER_RULES,
    quarantineStore = new QuarantineStore(),
    sandboxManager,
    anomalyDetector = createAnomalyDetectorFromEnv() ?? createBootstrapAnomalyDetector(),
    aiProvider = createAIProviderFromEnv(),
  } = {}) {
    if (!sandboxManager) {
      throw new TypeError("UploadSecurityService requires a SandboxManager.");
    }

    this.validationPipeline = new ValidationPipeline(validators);
    this.scanPipeline = new ScanPipeline(scanners);
    this.sanitizerRules = sanitizerRules;
    this.quarantineStore = quarantineStore;
    this.sandboxManager = sandboxManager;
    this.anomalyDetector = anomalyDetector;
    this.aiProvider = aiProvider;
  }

  /** Returns the first matching CDR sanitizer for a declared MIME type, or null. */
  resolveSanitizer(declaredMimeType) {
    return this.sanitizerRules.find((rule) => rule.test(declaredMimeType))?.sanitizer ?? null;
  }

  async analyze({ buffer, filename, declaredMimeType, riskScore = null } = {}) {
    if (!Buffer.isBuffer(buffer)) {
      throw new TypeError("UploadSecurityService.analyze expects a Buffer.");
    }

    const context = new PipelineContext({ filename, declaredMimeType });
    await this.validationPipeline.run(buffer, context);
    await this.scanPipeline.run(buffer, context);

    // CDR: rebuild a clean version of the file before anything downstream
    // treats it as trusted. Unconditional for types with a sanitizer; types
    // without one (OOXML, for now) pass through unchanged. A sanitizer that
    // can't even parse the file isn't a crash — it's evidence the declared
    // type is a lie, so it becomes a finding and the original buffer carries
    // on rather than aborting the whole analysis.
    let sanitizedBuffer = buffer;
    const sanitizer = this.resolveSanitizer(declaredMimeType);
    if (sanitizer) {
      try {
        const result = await sanitizer.sanitize(buffer, { filename, declaredMimeType });
        sanitizedBuffer = result.buffer;
        for (const finding of result.findings ?? []) {
          context.addFinding({ ...finding, stage: "cdr", source: sanitizer.name });
        }
      } catch (error) {
        context.addFinding({
          rule: "cdr-sanitization-failed",
          severity: "high",
          message: `${sanitizer.name} could not sanitize this file: ${error.message}. The declared type (${declaredMimeType}) may be spoofed. Proceeding with the original, unsanitized buffer.`,
          stage: "cdr",
          source: sanitizer.name,
        });
      }
    }

    // Every upload enters quarantine before deeper analysis or release.
    const quarantineDecision = evaluateQuarantine(context.findings);
    const quarantine = await this.quarantineStore.put(
      sanitizedBuffer,
      { filename, declaredMimeType },
      quarantineDecision
    );

    // Turn heterogeneous validator observations into a stable numeric vector.
    const features = extractFeatures({
      buffer: sanitizedBuffer,
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
          sizeBytes: sanitizedBuffer.length,
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