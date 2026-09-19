import { ScanPipeline } from "../src/scan-pipeline.js";
import { createFakeScanner } from "../src/fake-scanner.js";
import { PipelineContext } from "@secureupload/core";

describe("ScanPipeline", () => {
  test("runs with zero scanners without error", async () => {
    const pipeline = new ScanPipeline([]);
    const context = new PipelineContext();

    await pipeline.run(Buffer.alloc(0), context);

    expect(context.hasFindings).toBe(false);
  });

  test("a clean scanner adds no findings", async () => {
    const cleanScanner = createFakeScanner({ clean: true, findings: [] });
    const pipeline = new ScanPipeline([cleanScanner]);
    const context = new PipelineContext();

    await pipeline.run(Buffer.alloc(0), context);

    expect(context.hasFindings).toBe(false);
  });

  test("records findings from an unclean scanner, tagged with stage and source", async () => {
    const infectedScanner = createFakeScanner({
      clean: false,
      findings: [{ rule: "clamav-match", severity: "extreme", message: "Eicar-Test-Signature" }],
    });
    const pipeline = new ScanPipeline([infectedScanner]);
    const context = new PipelineContext();

    await pipeline.run(Buffer.alloc(0), context);

    expect(context.findings).toHaveLength(1);
    expect(context.findings[0].stage).toBe("scanning");
    expect(context.findings[0].source).toBe("Fake Scanner");
    expect(context.findings[0].rule).toBe("clamav-match");
  });

  test("records a generic finding when a scanner reports unclean but gives no findings", async () => {
    const vagueScanner = createFakeScanner({ clean: false, findings: [] });
    const pipeline = new ScanPipeline([vagueScanner]);
    const context = new PipelineContext();

    await pipeline.run(Buffer.alloc(0), context);

    expect(context.findings).toHaveLength(1);
    expect(context.findings[0].rule).toBe("scanner-reported-unclean");
    expect(context.findings[0].severity).toBe("high");
  });

  test("aggregates findings from multiple scanners", async () => {
    const scannerA = createFakeScanner({
      clean: false,
      findings: [{ rule: "a-rule", severity: "low", message: "a" }],
    });
    const scannerB = createFakeScanner({
      clean: false,
      findings: [{ rule: "b-rule", severity: "high", message: "b" }],
    });
    const pipeline = new ScanPipeline([scannerA, scannerB]);
    const context = new PipelineContext();

    await pipeline.run(Buffer.alloc(0), context);

    expect(context.findings).toHaveLength(2);
    expect(context.highestSeverity).toBe("high");
  });
});