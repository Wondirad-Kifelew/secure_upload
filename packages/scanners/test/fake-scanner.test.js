import { FakeScanner, createFakeScanner } from "../src/fake-scanner.js";

describe("FakeScanner", () => {
  test("has the expected Scanner shape", () => {
    expect(FakeScanner.name).toBe("Fake Scanner");
    expect(typeof FakeScanner.scan).toBe("function");
  });

  test("default instance always reports clean with no findings", async () => {
    const result = await FakeScanner.scan(Buffer.alloc(0), {});
    expect(result).toEqual({ clean: true, findings: [] });
  });

  test("createFakeScanner can be configured to report unclean with findings", async () => {
    const scanner = createFakeScanner({
      clean: false,
      findings: [{ rule: "test-malware", severity: "extreme", message: "test" }],
    });
    const result = await scanner.scan(Buffer.alloc(0), {});
    expect(result.clean).toBe(false);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].rule).toBe("test-malware");
  });

  test("ignores buffer and meta entirely — always returns the configured canned response", async () => {
    const scanner = createFakeScanner({ clean: false, findings: [] });
    const resultA = await scanner.scan(Buffer.from("anything"), { filename: "a.exe" });
    const resultB = await scanner.scan(Buffer.from("something else"), { filename: "b.pdf" });
    expect(resultA).toEqual(resultB);
  });
});