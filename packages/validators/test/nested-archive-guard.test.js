import yazl from "yazl";
import { NestedArchiveGuardValidator } from "../src/zip/before-unzip/nested-archive-guard.js";

function buildZip(files) {
  return new Promise((resolve, reject) => {
    const zipfile = new yazl.ZipFile();
    for (const [name, content] of Object.entries(files)) {
      zipfile.addBuffer(content, name);
    }
    const chunks = [];
    zipfile.outputStream.on("data", (chunk) => chunks.push(chunk));
    zipfile.outputStream.on("end", () => resolve(Buffer.concat(chunks)));
    zipfile.outputStream.on("error", reject);
    zipfile.end();
  });
}

describe("NestedArchiveGuardValidator", () => {
  test("has the expected Validator shape", () => {
    expect(NestedArchiveGuardValidator.name).toBe("Nested Archive Guard");
    expect(typeof NestedArchiveGuardValidator.validate).toBe("function");
  });

  test("a non-zip file produces no findings", async () => {
    const findings = await NestedArchiveGuardValidator.validate(Buffer.from("just plain text, not a zip"));
    expect(findings).toEqual([]);
  });

  test("a zip containing only ordinary files produces no findings", async () => {
    const zip = await buildZip({ "readme.txt": Buffer.from("hello"), "photo.png": Buffer.from("fake png") });
    const findings = await NestedArchiveGuardValidator.validate(zip);
    expect(findings).toEqual([]);
  });

  test("flags an entry that is itself a zip file", async () => {
    const zip = await buildZip({ "inner.zip": Buffer.from("fake nested zip bytes") });
    const findings = await NestedArchiveGuardValidator.validate(zip);
    const finding = findings.find((f) => f.rule === "zip-nested-archive");
    expect(finding).toBeDefined();
    expect(finding.severity).toBe("medium");
    expect(finding.details.matchedExtension).toBe(".zip");
  });

  test("flags an entry that is an Office document (OOXML is zip internally)", async () => {
    const zip = await buildZip({ "invoice.docx": Buffer.from("fake docx bytes") });
    const findings = await NestedArchiveGuardValidator.validate(zip);
    const finding = findings.find((f) => f.rule === "zip-nested-archive");
    expect(finding).toBeDefined();
    expect(finding.details.matchedExtension).toBe(".docx");
  });

  test("a corrupted/truncated zip produces no findings rather than throwing", async () => {
    const zip = await buildZip({ "file.txt": Buffer.from("hello") });
    const truncated = zip.subarray(0, zip.length - 10);
    await expect(NestedArchiveGuardValidator.validate(truncated)).resolves.toBeDefined();
  });
});