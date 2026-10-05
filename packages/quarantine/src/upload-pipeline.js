import { evaluateQuarantine } from "./policy.js";
import { QuarantineStore } from "./quarantine-store.js";

/**
 * Runs upload stages and stores every result in quarantine.
 */
export class QuarantinePipeline {
  constructor({ stages = [], store = new QuarantineStore(), policyOptions = {} } = {}) {
    this.stages = stages;
    this.store = store;
    this.policyOptions = policyOptions;
  }

  async run(buffer, context) {
    for (const stage of this.stages) {
      await stage.run(buffer, context);
    }

    const decision = evaluateQuarantine(context.findings, this.policyOptions);
    const record = await this.store.put(
      buffer,
      {
        filename: context.filename,
        declaredMimeType: context.declaredMimeType,
      },
      decision
    );

    return { context, decision, record };
  }
}