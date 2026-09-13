import { ValidationPipeline } from "../src/pipeline.js";
import { PipelineContext } from "../src/context.js";

/** A minimal fake validator, used only to test the pipeline plumbing. */
function makeFakeValidator({ name, findings = [] }) {
  return {
    name,
    validate: async () => findings,
  };
}

describe("ValidationPipeline", () => {
  test("runs with zero validators without error", async () => {
    const pipeline = new ValidationPipeline([]);
    const ctx = new PipelineContext();

    await pipeline.run(Buffer.from("irrelevant"), ctx);

    expect(ctx.hasFindings).toBe(false);
  });

  test("records findings from a validator, tagged with stage and source", async () => {
    const validator = makeFakeValidator({
      name: "Fake Validator",
      findings: [{ rule: "fake-rule", severity: "medium", message: "looks suspicious" }],
    });
    const pipeline = new ValidationPipeline([validator]);
    const ctx = new PipelineContext();

    await pipeline.run(Buffer.from("irrelevant"), ctx);

    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].stage).toBe("validation");
    expect(ctx.findings[0].source).toBe("Fake Validator");
    expect(ctx.findings[0].rule).toBe("fake-rule");
  });

  test("runs multiple validators and accumulates findings from all of them", async () => {
    const validatorA = makeFakeValidator({
      name: "A",
      findings: [{ rule: "a-rule", severity: "low", message: "a" }],
    });
    const validatorB = makeFakeValidator({
      name: "B",
      findings: [{ rule: "b-rule", severity: "high", message: "b" }],
    });
    const pipeline = new ValidationPipeline([validatorA, validatorB]);
    const ctx = new PipelineContext();

    await pipeline.run(Buffer.from("irrelevant"), ctx);

    expect(ctx.findings).toHaveLength(2);
    expect(ctx.highestSeverity).toBe("high");
  });

  test("a validator returning no findings does not affect the context", async () => {
    const cleanValidator = makeFakeValidator({ name: "Clean", findings: [] });
    const pipeline = new ValidationPipeline([cleanValidator]);
    const ctx = new PipelineContext();

    await pipeline.run(Buffer.from("irrelevant"), ctx);

    expect(ctx.hasFindings).toBe(false);
  });
});
