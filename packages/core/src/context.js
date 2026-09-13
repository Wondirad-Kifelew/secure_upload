/**
 * PipelineContext
 * ----------------
 * The one object that travels through every stage of the pipeline
 * (validation → scanning → CDR → quarantine, once those stages exist).
 *
 * It plays two roles, deliberately kept in the same object rather than
 * split apart, mirroring how DocBleach's BleachSession works:
 *
 *   1. Findings accumulator — every stage appends its findings here,
 *      so by the end of the run this object *is* the audit trail.
 *   2. Recursion/depth guard — nested content (a zip inside a zip,
 *      an embedded object inside a document) increments a depth
 *      counter instead of recursing unbounded. This is our zip-bomb /
 *      nested-archive guard, and it lives here so every future stage
 *      that processes nested content gets the guard for free instead
 *      of re-implementing it.
 *
 * One PipelineContext = one file's journey through the pipeline.
 * Don't share a context across two unrelated files.
 */

export class RecursionGuardError extends Error {
  constructor(depth, max) {
    super(`Recursion depth ${depth} exceeded max of ${max} — possible zip bomb or nested-content attack.`);
    this.name = "RecursionGuardError";
    this.depth = depth;
    this.max = max;
  }
}

export class PipelineContext {
  /**
   * @param {Object} fileMeta
   * @param {string} [fileMeta.filename]
   * @param {string} [fileMeta.declaredMimeType]
   */
  constructor(fileMeta = {}) {
    this.filename = fileMeta.filename ?? null;
    this.declaredMimeType = fileMeta.declaredMimeType ?? null;

    /** @type {Array<Object>} */
    this.findings = [];

    this._recursionDepth = 0;
    this._maxRecursionDepth = 10; // matches DocBleach's default; revisit if needed
  }

  /**
   * Record a finding from any pipeline stage.
   * Findings are never thrown as errors — a "bad" file is a normal
   * outcome the pipeline should describe, not an exception.
   *
   * @param {Object} finding
   * @param {string} finding.rule       - machine-readable id, e.g. "magic-byte-mismatch"
   * @param {"low"|"medium"|"high"|"extreme"} finding.severity
   * @param {string} finding.message
   * @param {string} finding.stage      - "validation" | "scanning" | "cdr" | "quarantine"
   * @param {string} [finding.source]   - which validator/scanner/etc. raised it
   * @param {Object} [finding.details]
   */
  addFinding(finding) {
    this.findings.push({
      ...finding,
      recordedAt: new Date().toISOString(),
    });
  }

  get hasFindings() {
    return this.findings.length > 0;
  }

  /**
   * Highest severity seen so far, or null if no findings.
   */
  get highestSeverity() {
    const order = ["low", "medium", "high", "extreme"];
    return this.findings.reduce((highest, f) => {
      if (!highest) return f.severity;
      return order.indexOf(f.severity) > order.indexOf(highest) ? f.severity : highest;
    }, null);
  }

  /**
   * Call before descending into nested content (an archive entry, an
   * embedded object, etc). Throws RecursionGuardError if the file is
   * nesting deeper than allowed — this is the zip-bomb guard.
   */
  enterNested() {
    this._recursionDepth += 1;
    if (this._recursionDepth > this._maxRecursionDepth) {
      throw new RecursionGuardError(this._recursionDepth, this._maxRecursionDepth);
    }
  }

  /** Call when finished processing a level of nested content. */
  exitNested() {
    this._recursionDepth = Math.max(0, this._recursionDepth - 1);
  }

  /**
   * Plain-object snapshot suitable for logging or persisting as the
   * Phase 4 audit record.
   */
  toAuditLog() {
    return {
      filename: this.filename,
      declaredMimeType: this.declaredMimeType,
      findingCount: this.findings.length,
      highestSeverity: this.highestSeverity,
      findings: this.findings,
    };
  }
}
 