import { FilenameSanitizerValidator } from "../src/filename-sanitizer.js";

describe("FilenameSanitizerValidator", () => {
  test("has the expected Validator shape", () => {
    expect(FilenameSanitizerValidator.name).toBe("Filename Sanitizer");
    expect(typeof FilenameSanitizerValidator.validate).toBe("function");
  });

  test("a normal, boring filename produces no findings", async () => {
    const findings = await FilenameSanitizerValidator.validate(Buffer.alloc(0), {
      filename: "invoice-2024.pdf",
    });
    expect(findings).toEqual([]);
  });

  test("no filename provided produces no findings", async () => {
    const findings = await FilenameSanitizerValidator.validate(Buffer.alloc(0), {});
    expect(findings).toEqual([]);
  });

  test("flags a null byte in the filename", async () => {
    const findings = await FilenameSanitizerValidator.validate(Buffer.alloc(0), {
      filename: "shell.php\0.png",
    });
    const rules = findings.map((f) => f.rule);
    expect(rules).toContain("filename-null-byte");
    expect(findings.find((f) => f.rule === "filename-null-byte").severity).toBe("extreme");
  });

  test("flags path traversal sequences", async () => {
    const findings = await FilenameSanitizerValidator.validate(Buffer.alloc(0), {
      filename: "../../etc/passwd",
    });
    const rules = findings.map((f) => f.rule);
    expect(rules).toContain("filename-path-traversal");
    expect(findings.find((f) => f.rule === "filename-path-traversal").severity).toBe("extreme");
  });

  test("flags an absolute path", async () => {
    const findings = await FilenameSanitizerValidator.validate(Buffer.alloc(0), {
      filename: "/etc/passwd",
    });
    expect(findings.map((f) => f.rule)).toContain("filename-path-traversal");
  });

  test("flags un-normalized Unicode (decomposed accent vs precomposed)", async () => {
    // "cafe" + combining acute accent (U+0301), instead of the single
    // precomposed "é" character. Visually identical, different bytes.
    const decomposed = "cafe\u0301.pdf";
    const findings = await FilenameSanitizerValidator.validate(Buffer.alloc(0), {
      filename: decomposed,
    });
    const finding = findings.find((f) => f.rule === "filename-not-normalized");
    expect(finding).toBeDefined();
    expect(finding.severity).toBe("low");
    expect(finding.details.normalized).toBe("café.pdf");
  });

  test("flags a mixed-script filename (Cyrillic + Latin homoglyph)", async () => {
    // First character is Cyrillic "а" (U+0430), not Latin "a" — looks
    // identical, common technique for disguising a malicious filename.
    const findings = await FilenameSanitizerValidator.validate(Buffer.alloc(0), {
      filename: "\u0430pple.exe",
    });
    const finding = findings.find((f) => f.rule === "filename-mixed-script");
    expect(finding).toBeDefined();
    expect(finding.severity).toBe("medium");
    expect(finding.details.scripts).toEqual(expect.arrayContaining(["Latin", "Cyrillic"]));
  });

  test("a filename with digits and punctuation only does not trigger mixed-script", async () => {
    const findings = await FilenameSanitizerValidator.validate(Buffer.alloc(0), {
      filename: "report-2024_final (v2).pdf",
    });
    expect(findings.map((f) => f.rule)).not.toContain("filename-mixed-script");
  });

  test("a single malicious filename can trigger multiple findings at once", async () => {
    const findings = await FilenameSanitizerValidator.validate(Buffer.alloc(0), {
      filename: "../../\u0430pple.exe\0.png",
    });
    const rules = findings.map((f) => f.rule);
    expect(rules).toContain("filename-null-byte");
    expect(rules).toContain("filename-path-traversal");
    expect(rules).toContain("filename-mixed-script");
  });
});