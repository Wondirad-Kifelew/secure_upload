import { DangerousExtensionGuardValidator, createDangerousExtensionGuardValidator } from "../src/zip/after-unzip/dangerous-extension-guard.js";

describe("DangerousExtensionGuardValidator", () => {
  test("has expected validator shape", () => {
    expect(DangerousExtensionGuardValidator.name).toBe("Dangerous Extension Guard");
    expect(typeof DangerousExtensionGuardValidator.validate).toBe("function");
  });

  test("safe files produce no findings", async () => {
    const findings = await DangerousExtensionGuardValidator.validate(
      Buffer.from("hello"),
      { filename: "report.pdf" }
    );
    expect(findings).toEqual([]);
  });

  test("flags Windows executables (.exe, .dll, .bat)", async () => {
    const exeFindings = await DangerousExtensionGuardValidator.validate(
      Buffer.from("fake binary"),
      { filename: "payload.exe" }
    );
    expect(exeFindings).toHaveLength(1);
    expect(exeFindings[0].rule).toBe("zip-extracted-dangerous-extension");
    expect(exeFindings[0].severity).toBe("high");

    const batFindings = await DangerousExtensionGuardValidator.validate(
      Buffer.from("fake script"),
      { filename: "setup.bat" }
    );
    expect(batFindings).toHaveLength(1);
  });

  test("flags scripts (.sh, .vbs, .ps1)", async () => {
    const psFindings = await DangerousExtensionGuardValidator.validate(
      Buffer.from("Get-Process"),
      { filename: "attack.ps1" }
    );
    expect(psFindings).toHaveLength(1);
  });

  test("supports custom blocked extensions via factory", async () => {
    const customValidator = createDangerousExtensionGuardValidator({
      blockedExtensions: [".iso", ".dmg"],
    });

    const exeFindings = await customValidator.validate(Buffer.from(""), { filename: "tool.exe" });
    expect(exeFindings).toEqual([]); // Not blocked in custom list

    const isoFindings = await customValidator.validate(Buffer.from(""), { filename: "os.iso" });
    expect(isoFindings).toHaveLength(1);
  });
});
