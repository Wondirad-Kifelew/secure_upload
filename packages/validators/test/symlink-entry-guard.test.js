import yazl from "yazl";
import { SymlinkEntryGuardValidator } from "../src/zip/before-unzip/symlink-entry-guard.js";

function buildZip(entries) {
  return new Promise((resolve, reject) => {
    const zipfile = new yazl.ZipFile();
    for (const [name, content, options] of entries) {
      zipfile.addBuffer(content, name, options);
    }
    const chunks = [];
    zipfile.outputStream.on("data", (chunk) => chunks.push(chunk));
    zipfile.outputStream.on("end", () => resolve(Buffer.concat(chunks)));
    zipfile.outputStream.on("error", reject);
    zipfile.end();
  });
}

const SYMLINK_MODE = 0xa1ff; // S_IFLNK | 0o777
const REGULAR_FILE_MODE = 0x81a4; // S_IFREG | 0o644

describe("SymlinkEntryGuardValidator", () => {
  test("has the expected Validator shape", () => {
    expect(SymlinkEntryGuardValidator.name).toBe("Symlink Entry Guard");
    expect(typeof SymlinkEntryGuardValidator.validate).toBe("function");
  });

  test("a non-zip file produces no findings", async () => {
    const findings = await SymlinkEntryGuardValidator.validate(Buffer.from("just plain text, not a zip"));
    expect(findings).toEqual([]);
  });

  test("a zip with only regular files produces no findings", async () => {
    const zip = await buildZip([["readme.txt", Buffer.from("hello"), { mode: REGULAR_FILE_MODE }]]);
    const findings = await SymlinkEntryGuardValidator.validate(zip);
    expect(findings).toEqual([]);
  });

  test("flags an entry stored as a symlink", async () => {
    const zip = await buildZip([
      ["innocent-looking.txt", Buffer.from("/etc/shadow"), { mode: SYMLINK_MODE }],
    ]);
    const findings = await SymlinkEntryGuardValidator.validate(zip);
    const finding = findings.find((f) => f.rule === "zip-symlink-entry");
    expect(finding).toBeDefined();
    expect(finding.severity).toBe("extreme");
    expect(finding.details.fileName).toBe("innocent-looking.txt");
  });

  test("a corrupted/truncated zip produces no findings rather than throwing", async () => {
    const zip = await buildZip([["file.txt", Buffer.from("hello"), { mode: REGULAR_FILE_MODE }]]);
    const truncated = zip.subarray(0, zip.length - 10);
    await expect(SymlinkEntryGuardValidator.validate(truncated)).resolves.toBeDefined();
  });
});