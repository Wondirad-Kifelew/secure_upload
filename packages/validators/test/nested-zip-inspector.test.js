import yazl from "yazl";
import {
  createNestedZipInspectorValidator,
  NestedZipInspectorValidator,
} from "../src/zip/after-unzip/nested-zip-inspector.js";
import { ZipSlipGuardValidator } from "../src/zip/before-unzip/zip-slip-guard.js";
 
function buildZip(files) {
  return new Promise((resolve, reject) => {
    const zipfile = new yazl.ZipFile();
    for (const [name, content] of Object.entries(files)) {
      zipfile.addBuffer(content, name);
    }
    const chunks = [];
    zipfile.outputStream.on("data", (c) => chunks.push(c));
    zipfile.outputStream.on("end", () => resolve(Buffer.concat(chunks)));
    zipfile.outputStream.on("error", reject);
    zipfile.end();
  });
}
 
// Raw builder for names yazl itself refuses to create (path traversal,
// absolute paths) — same technique used in zip-slip-guard.test.js.
function crc32(buf) {
  let table = crc32.table;
  if (!table) {
    table = crc32.table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      table[n] = c;
    }
  }
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
 
function buildRawZip(files) {
  const localParts = [], centralParts = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const nameBuf = Buffer.from(name, "utf8");
    const crc = crc32(content);
    const size = content.length;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(0, 8); lh.writeUInt16LE(0, 10); lh.writeUInt16LE(0, 12);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(size, 18); lh.writeUInt32LE(size, 22);
    lh.writeUInt16LE(nameBuf.length, 26); lh.writeUInt16LE(0, 28);
    const localEntry = Buffer.concat([lh, nameBuf, content]);
    localParts.push(localEntry);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0, 8); ch.writeUInt16LE(0, 10); ch.writeUInt16LE(0, 12); ch.writeUInt16LE(0, 14);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(size, 20); ch.writeUInt32LE(size, 24);
    ch.writeUInt16LE(nameBuf.length, 28); ch.writeUInt16LE(0, 30); ch.writeUInt16LE(0, 32);
    ch.writeUInt16LE(0, 34); ch.writeUInt16LE(0, 36); ch.writeUInt32LE(0, 38); ch.writeUInt32LE(offset, 42);
    centralParts.push(Buffer.concat([ch, nameBuf]));
    offset += localEntry.length;
  }
  const localSection = Buffer.concat(localParts);
  const centralSection = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(0, 4); end.writeUInt16LE(0, 6);
  end.writeUInt16LE(centralParts.length, 8); end.writeUInt16LE(centralParts.length, 10);
  end.writeUInt32LE(centralSection.length, 12); end.writeUInt32LE(localSection.length, 16); end.writeUInt16LE(0, 20);
  return Buffer.concat([localSection, centralSection, end]);
}
 
describe("NestedZipInspectorValidator", () => {
  test("has the expected Validator shape", () => {
    expect(NestedZipInspectorValidator.name).toBe("Nested Zip Inspector");
    expect(typeof NestedZipInspectorValidator.validate).toBe("function");
  });
 
  test("a non-zip file produces no findings", async () => {
    const findings = await NestedZipInspectorValidator.validate(
      Buffer.from("just some text, not a zip"),
      { filename: "note.txt" }
    );
    expect(findings).toEqual([]);
  });
 
  test("a plain zip with an ordinary file produces no findings", async () => {
    const zip = await buildZip({ "readme.txt": Buffer.from("hello world") });
    const findings = await NestedZipInspectorValidator.validate(zip, { filename: "outer.zip" });
    expect(findings).toEqual([]);
  });
 
  test("catches a Zip Slip entry hidden inside a nested zip", async () => {
    const innerZip = buildRawZip({ "../../etc/passwd": Buffer.from("evil") });
    const outerZip = await buildZip({ "backup.zip": innerZip });
 
    const validator = createNestedZipInspectorValidator({ guards: [ZipSlipGuardValidator] });
    const findings = await validator.validate(outerZip, { filename: "outer.zip" });
 
    const found = findings.find((f) => f.rule === "zip-slip-path-traversal");
    expect(found).toBeDefined();
    expect(found.details.nestedPath).toBe("outer.zip -> backup.zip");
    expect(found.details.nestedDepth).toBe(1);
  });
 
  test("catches a Zip Slip entry two levels deep (zip -> zip -> zip)", async () => {
    const innermost = buildRawZip({ "/etc/shadow": Buffer.from("evil") });
    const middle = await buildZip({ "inner.zip": innermost });
    const outer = await buildZip({ "middle.zip": middle });
 
    const validator = createNestedZipInspectorValidator({ guards: [ZipSlipGuardValidator] });
    const findings = await validator.validate(outer, { filename: "outer.zip" });
 
    const found = findings.find((f) => f.rule === "zip-slip-path-traversal");
    expect(found).toBeDefined();
    expect(found.details.nestedDepth).toBe(2);
    expect(found.details.nestedPath).toBe("outer.zip -> middle.zip -> inner.zip");
  });
 
  test("stops and flags a chain nested deeper than maxDepth, without hanging", async () => {
    let current = await buildZip({ "leaf.txt": Buffer.from("x") });
    for (let i = 0; i < 8; i++) {
      current = await buildZip({ [`level${i}.zip`]: current });
    }
    const validator = createNestedZipInspectorValidator({ maxDepth: 3, guards: [] });
    const findings = await validator.validate(current, { filename: "outer.zip" });
    const found = findings.find((f) => f.rule === "zip-nested-depth-exceeded");
    expect(found).toBeDefined();
  }, 10_000);
 
  test("aborts extracting a nested entry that exceeds the per-entry byte limit", async () => {
    const bigContent = Buffer.alloc(1024 * 1024, "a"); // 1MB
    const inner = await buildZip({ "big.bin": bigContent });
    const outer = await buildZip({ "payload.zip": inner });
 
    const validator = createNestedZipInspectorValidator({ maxEntryExtractedBytes: 5000, guards: [] });
    const findings = await validator.validate(outer, { filename: "outer.zip" });
 
    const found = findings.find((f) => f.rule === "zip-nested-entry-too-large");
    expect(found).toBeDefined();
    expect(found.details.entryName).toBe("big.bin");
  });
 
  test("stops once total extracted size across entries exceeds the configured limit", async () => {
    const files = {};
    for (let i = 0; i < 5; i++) files[`file${i}.bin`] = Buffer.alloc(300, "x");
    const zip = await buildZip(files);
 
    const validator = createNestedZipInspectorValidator({ maxTotalExtractedBytes: 500, guards: [] });
    const findings = await validator.validate(zip, { filename: "outer.zip" });
 
    const found = findings.find((f) => f.rule === "zip-nested-total-size-exceeded");
    expect(found).toBeDefined();
  });
 
  test("a real decompression bomb hidden inside a nested zip is aborted, not fully decompressed", async () => {
    const hugeZeros = Buffer.alloc(5 * 1024 * 1024); // 5MB of zeros, compresses to ~kb
    const bombZip = await buildZip({ "zeros.bin": hugeZeros });
    const outer = await buildZip({ "payload.zip": bombZip });
 
    const validator = createNestedZipInspectorValidator({ maxEntryExtractedBytes: 100 * 1024, guards: [] });
    const start = Date.now();
    const findings = await validator.validate(outer, { filename: "outer.zip" });
    const elapsed = Date.now() - start;
 
    const found = findings.find((f) => f.rule === "zip-nested-entry-too-large");
    expect(found).toBeDefined();
    expect(elapsed).toBeLessThan(3000);
  });
 
  test("a corrupted/truncated zip produces no findings rather than throwing", async () => {
    const corrupted = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x01, 0x02]);
    const findings = await NestedZipInspectorValidator.validate(corrupted, { filename: "bad.zip" });
    expect(Array.isArray(findings)).toBe(true);
  });
});
 

