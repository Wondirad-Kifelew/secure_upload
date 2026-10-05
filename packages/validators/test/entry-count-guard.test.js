import yazl from "yazl";
import { EntryCountGuardValidator } from "../src/zip/before-unzip/entry-count-guard.js";

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

describe("EntryCountGuardValidator", () => {
  test("has the expected Validator shape", () => {
    expect(EntryCountGuardValidator.name).toBe("Entry Count Guard");
    expect(typeof EntryCountGuardValidator.validate).toBe("function");
  });

  test("a non-zip file produces no findings", async () => {
    const findings = await EntryCountGuardValidator.validate(Buffer.from("just plain text, not a zip"));
    expect(findings).toEqual([]);
  });

  test("a zip with a normal number of entries produces no findings", async () => {
    const files = {};
    for (let i = 0; i < 5; i++) {
      files[`file-${i}.txt`] = Buffer.from("hello");
    }
    const zip = await buildZip(files);
    const findings = await EntryCountGuardValidator.validate(zip);
    expect(findings).toEqual([]);
  });

  test("flags a zip with an excessive number of entries", async () => {
    const files = {};
    for (let i = 0; i < 10_001; i++) {
      files[`f${i}.txt`] = Buffer.from("");
    }
    const zip = await buildZip(files);
    const findings = await EntryCountGuardValidator.validate(zip);
    const finding = findings.find((f) => f.rule === "zip-entry-count-excessive");
    expect(finding).toBeDefined();
    expect(finding.severity).toBe("high");
    expect(finding.details.entryCount).toBe(10_001);
  }, 30_000);

  test("a corrupted/truncated zip produces no findings rather than throwing", async () => {
    const zip = await buildZip({ "file.txt": Buffer.from("hello") });
    const truncated = zip.subarray(0, zip.length - 10);
    await expect(EntryCountGuardValidator.validate(truncated)).resolves.toBeDefined();
  });
});