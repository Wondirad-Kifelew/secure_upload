/**
 * ValidationPipeline
 * -------------------
 * Runs Phase 1 validators (see interfaces/validator.js for the contract)
 * against a file buffer, in order, recording every finding onto the
 * shared PipelineContext.
 *
 * This intentionally does NOT decide what to do with the findings
 * (reject / flag / quarantine) — that's a policy decision for whoever
 * calls the pipeline (e.g. Phase 4's state machine, later). This stage
 * just observes and reports.
 *
 * Scanning, CDR, and quarantine each get their own pipeline/runner
 * later, following the same shape: take a context, run a list of
 * stage-appropriate units, record findings, return the context.
 */

export class ValidationPipeline {
  /**
   * @param {import('./interfaces/validator.js').Validator[]} validators
   */
  constructor(validators = []) {
    this.validators = validators;
  }
 
  /**
   * @param {Buffer} buffer
   * @param {import('./context.js').PipelineContext} context
   * @returns {Promise<import('./context.js').PipelineContext>}
   */
  async run(buffer, context) {
    for (const validator of this.validators) {
      const meta = { filename: context.filename, declaredMimeType: context.declaredMimeType };
      const findings = await validator.validate(buffer, meta);

      for (const finding of findings ?? []) {
        context.addFinding({
          ...finding,
          stage: "validation",
          source: validator.name,
        });
      }
    }
 
    return context;
  }
}
