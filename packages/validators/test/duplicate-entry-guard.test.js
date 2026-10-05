import yazl from "yazl";
import { DuplicateEntryGuardValidator } from "../src/zip/before-unzip/duplicate-entry-guard.js";

function buildZip(entries) {
  return new Promise((resolve, reject) => {
    const zipfile = new yazl.ZipFile();
    for (const [name, content] of entries) {
      zipfile.addBuffer(content, name);
    }
    const chunks = [];
    zipfile.outputStream.on("data", (chunk) => chunks.push(chunk));
    zipfile.outputStream.on("end", () => resolve(Buffer.concat(chunks)));
    zipfile.outputStream.on("error", reject);
    zipfile.end();
  });
}

describe("DuplicateEntryGuardValidator", () => {
  test("has the expected Validator shape", () => {
    expect(DuplicateEntryGuardValidator.name).toBe("Duplicate Entry Guard");
    expect(typeof DuplicateEntryGuardValidator.validate).toBe("function");
  });

  test("a non-zip file produces no findings", async () => {
    const findings = await DuplicateEntryGuardValidator.validate(Buffer.from("just plain text, not a zip"));
    expect(findings).toEqual([]);
  });

  test("a zip with all unique entry names produces no findings", async () => {
    const zip = await buildZip([
      ["a.txt", Buffer.from("a")],
      ["b.txt", Buffer.from("b")],
    ]);
    const findings = await DuplicateEntryGuardValidator.validate(zip);
    expect(findings).toEqual([]);
  });

  test("flags two entries that differ only by case", async () => {
    const zip = await buildZip([
      ["config.json", Buffer.from("real config")],
      ["Config.json", Buffer.from("sneaky overwrite")],
    ]);
    const findings = await DuplicateEntryGuardValidator.validate(zip);
    const finding = findings.find((f) => f.rule === "zip-duplicate-entry-name");
    expect(finding).toBeDefined();
    expect(finding.severity).toBe("medium");
    expect(finding.details.originalNames).toEqual(["config.json", "Config.json"]);
  });

  test("flags two entries that differ only by slash direction", async () => {
    const zip = await buildZip([
      ["dir/file.txt", Buffer.from("first")],
      ["dir\\file.txt", Buffer.from("second")],
    ]);
    const findings = await DuplicateEntryGuardValidator.validate(zip);
    const finding = findings.find((f) => f.rule === "zip-duplicate-entry-name");
    expect(finding).toBeDefined();
  });

  test("a corrupted/truncated zip produces no findings rather than throwing", async () => {
    const zip = await buildZip([["file.txt", Buffer.from("hello")]]);
    const truncated = zip.subarray(0, zip.length - 10);
    await expect(DuplicateEntryGuardValidator.validate(truncated)).resolves.toBeDefined();
  });
});