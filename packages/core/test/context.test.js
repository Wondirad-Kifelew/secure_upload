import { PipelineContext, RecursionGuardError } from "../src/context.js";

describe("PipelineContext", () => {
  test("starts with no findings", () => {
    const ctx = new PipelineContext({ filename: "resume.pdf" });
    expect(ctx.hasFindings).toBe(false);
    expect(ctx.highestSeverity).toBeNull();
  });

  test("addFinding records a finding with a timestamp", () => {
    const ctx = new PipelineContext();
    ctx.addFinding({ rule: "test-rule", severity: "low", message: "test", stage: "validation" });

    expect(ctx.hasFindings).toBe(true);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].rule).toBe("test-rule");
    expect(ctx.findings[0].recordedAt).toBeDefined();
  });

  test("highestSeverity tracks the worst finding seen", () => {
    const ctx = new PipelineContext();
    ctx.addFinding({ rule: "a", severity: "low", message: "a", stage: "validation" });
    ctx.addFinding({ rule: "b", severity: "extreme", message: "b", stage: "validation" });
    ctx.addFinding({ rule: "c", severity: "medium", message: "c", stage: "validation" });

    expect(ctx.highestSeverity).toBe("extreme");
  });

  test("enterNested increments depth and allows normal nesting", () => {
    const ctx = new PipelineContext();
    expect(() => {
      ctx.enterNested();
      ctx.enterNested();
      ctx.exitNested();
      ctx.exitNested();
    }).not.toThrow();
  });

  test("enterNested throws RecursionGuardError past the max depth (zip-bomb guard)", () => {
    const ctx = new PipelineContext();
    expect(() => {
      for (let i = 0; i < 11; i++) {
        ctx.enterNested();
      }
    }).toThrow(RecursionGuardError);
  });

  test("toAuditLog returns a plain-object summary", () => {
    const ctx = new PipelineContext({ filename: "invoice.docx", declaredMimeType: "application/pdf" });
    ctx.addFinding({ rule: "mime-mismatch", severity: "high", message: "mismatch", stage: "validation" });

    const log = ctx.toAuditLog();
    expect(log.filename).toBe("invoice.docx");
    expect(log.declaredMimeType).toBe("application/pdf");
    expect(log.findingCount).toBe(1);
    expect(log.highestSeverity).toBe("high");
  });
});
