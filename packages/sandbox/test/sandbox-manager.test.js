import { DryRunSandboxAdapter, SandboxManager } from "../src/index.js";

describe("SandboxManager", () => {
  test("skips when no trigger is present", async () => {
    const manager = new SandboxManager({ adapter: new DryRunSandboxAdapter() });
    const result = await manager.analyze({
      quarantineRecord: { samplePath: "/quarantine/id/sample.bin" },
      riskScore: 10,
      findings: [],
    });

    expect(result.status).toBe("skipped");
    expect(result.triggered).toBe(false);
  });

  test("uses the injected adapter without executing the sample on the host", async () => {
    const manager = new SandboxManager({ adapter: new DryRunSandboxAdapter() });
    const result = await manager.analyze({
      quarantineRecord: { samplePath: "/quarantine/id/sample.bin" },
      riskScore: 80,
      findings: [],
    });

    expect(result.status).toBe("completed");
    expect(result.result.mode).toBe("dry-run");
    expect(result.result.executed).toBe(false);
    expect(result.result.samplePath).toBe("/quarantine/id/sample.bin");
  });
});
