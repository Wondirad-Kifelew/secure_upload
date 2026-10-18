import yazl from "yazl";
import {
  ExecutableContentGuardValidator,
  createExecutableContentGuardValidator,
} from "../src/zip/after-unzip/executable-content-guard.js";
import { NestedZipInspectorValidator } from "../src/zip/after-unzip/nested-zip-inspector.js";

function buildZip(files) {
  return new Promise((resolve, reject) => {
    const zipfile = new yazl.ZipFile();
    for (const [name, content] of Object.entries(files)) {
      zipfile.addBuffer(content, name, { compress: true });
    }
    const chunks = [];
    zipfile.outputStream.on("data", (c) => chunks.push(c));
    zipfile.outputStream.on("end", () => resolve(Buffer.concat(chunks)));
    zipfile.outputStream.on("error", reject);
    zipfile.end();
  });
}

describe("ExecutableContentGuardValidator", () => {
  test("has expected validator shape", () => {
    expect(ExecutableContentGuardValidator.name).toBe("Executable Content Guard");
    expect(typeof ExecutableContentGuardValidator.validate).toBe("function");
  });

  test("flags Windows PE (MZ) as high severity", async () => {
    const peBuffer = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00]);
    const findings = await ExecutableContentGuardValidator.validate(peBuffer, {
      filename: "notes.txt",
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("zip-executable-content");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].message).toContain("notes.txt");
    expect(findings[0].message).toContain(findings[0].details.detectedType);
    expect(findings[0].message).toContain("the content is an executable even though");
    expect(findings[0].details).toEqual({
      filename: "notes.txt",
      detectedType: "Windows PE executable",
    });
  });

  test("flags Linux ELF as high severity", async () => {
    const elfBuffer = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]);
    const findings = await ExecutableContentGuardValidator.validate(elfBuffer, {
      filename: "data.csv",
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("zip-executable-content");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].message).toContain("data.csv");
    expect(findings[0].details.detectedType).toBe("Linux ELF executable");
  });

  test("flags each of the 4 Mach-O signatures as high severity", async () => {
    const machOSignatures = [
      Buffer.from([0xfe, 0xed, 0xfa, 0xce, 0x00, 0x00]), // 32-bit big-endian
      Buffer.from([0xfe, 0xed, 0xfa, 0xcf, 0x00, 0x00]), // 64-bit big-endian
      Buffer.from([0xce, 0xfa, 0xed, 0xfe, 0x00, 0x00]), // 32-bit little-endian
      Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0x00, 0x00]), // 64-bit little-endian
    ];

    for (const buf of machOSignatures) {
      const findings = await ExecutableContentGuardValidator.validate(buf, {
        filename: "readme.txt",
      });
      expect(findings).toHaveLength(1);
      expect(findings[0].rule).toBe("zip-executable-content");
      expect(findings[0].severity).toBe("high");
      expect(findings[0].details.detectedType).toBe("Mach-O binary");
    }
  });

  test("flags script with '#!' shebang as medium severity", async () => {
    const scriptBuffer = Buffer.from("#!/usr/bin/env python3\nprint('hello')\n");
    const findings = await ExecutableContentGuardValidator.validate(scriptBuffer, {
      filename: "instructions.txt",
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("zip-executable-content");
    expect(findings[0].severity).toBe("medium");
    expect(findings[0].details.detectedType).toBe("script with shebang");
  });

  test("plain text is NOT flagged", async () => {
    const textBuffer = Buffer.from("Just a normal text file with harmless words.");
    const findings = await ExecutableContentGuardValidator.validate(textBuffer, {
      filename: "notes.txt",
    });
    expect(findings).toEqual([]);
  });

  test("PNG signature is NOT flagged", async () => {
    const pngBuffer = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00]);
    const findings = await ExecutableContentGuardValidator.validate(pngBuffer, {
      filename: "photo.png",
    });
    expect(findings).toEqual([]);
  });

  test("empty buffer is NOT flagged", async () => {
    const emptyBuffer = Buffer.alloc(0);
    const findings = await ExecutableContentGuardValidator.validate(emptyBuffer, {
      filename: "empty.txt",
    });
    expect(findings).toEqual([]);
  });

  test("1-byte buffer is NOT flagged", async () => {
    const oneByteM = Buffer.from([0x4d]);
    const oneByteHash = Buffer.from([0x23]);
    expect(await ExecutableContentGuardValidator.validate(oneByteM, { filename: "short.txt" })).toEqual([]);
    expect(await ExecutableContentGuardValidator.validate(oneByteHash, { filename: "short.txt" })).toEqual([]);
  });

  test("Java class files (CAFEBABE) are NOT flagged", async () => {
    const javaBuffer = Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34]);
    const findings = await ExecutableContentGuardValidator.validate(javaBuffer, {
      filename: "App.class",
    });
    expect(findings).toEqual([]);
  });

  test("integration: zip with notes.txt containing MZ bytes built with deflate compression produces zip-executable-content finding mentioning notes.txt", async () => {
    const mzPayload = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
    const zip = await buildZip({ "notes.txt": mzPayload });

    const findings = await NestedZipInspectorValidator.validate(zip, { filename: "archive.zip" });
    const finding = findings.find((f) => f.rule === "zip-executable-content");

    expect(finding).toBeDefined();
    expect(finding.severity).toBe("high");
    expect(finding.details?.nestedPath).toBeDefined();
    expect(finding.details.nestedPath).toContain("notes.txt");
  });
});
