import yazl from "yazl";
import { createZipBombGuardValidator, ZipBombGuardValidator } from "../src/zip/before-unzip/zip-bomb-guard.js";

/** Builds a real zip file in memory from { name: contentBuffer } entries. */
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

/**
 * Builds a zip whose directory metadata claims arbitrary compressed /
 * uncompressed sizes, without having to actually create that much data.
 * Used to test malformed size fields that a real archiver never emits.
 */
function buildZipWithClaimedSizes({ name, compressedSize, uncompressedSize, content = Buffer.alloc(0) }) {
  const nameBuf = Buffer.from(name, "utf8");

  const localHeader = Buffer.alloc(30);
  localHeader.writeUInt32LE(0x04034b50, 0);
  localHeader.writeUInt16LE(20, 4);
  localHeader.writeUInt32LE(compressedSize, 18);
  localHeader.writeUInt32LE(uncompressedSize, 22);
  localHeader.writeUInt16LE(nameBuf.length, 26);
  const localEntry = Buffer.concat([localHeader, nameBuf, content]);

  const centralHeader = Buffer.alloc(46);
  centralHeader.writeUInt32LE(0x02014b50, 0);
  centralHeader.writeUInt16LE(20, 4);
  centralHeader.writeUInt16LE(20, 6);
  centralHeader.writeUInt32LE(compressedSize, 20);
  centralHeader.writeUInt32LE(uncompressedSize, 24);
  centralHeader.writeUInt16LE(nameBuf.length, 28);
  centralHeader.writeUInt32LE(0, 42);
  const centralEntry = Buffer.concat([centralHeader, nameBuf]);

  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(centralEntry.length, 12);
  end.writeUInt32LE(localEntry.length, 16);

  return Buffer.concat([localEntry, centralEntry, end]);
}

describe("ZipBombGuardValidator", () => {
  test("has the expected Validator shape", () => {
    expect(ZipBombGuardValidator.name).toBe("Zip Bomb Guard");
    expect(typeof ZipBombGuardValidator.validate).toBe("function");
  });

  test("a non-zip file produces no findings", async () => {
    const findings = await ZipBombGuardValidator.validate(Buffer.from("just plain text, not a zip"));
    expect(findings).toEqual([]);
  });

  test("a normal, everyday zip with ordinary content produces no findings", async () => {
    const normalContent = Buffer.from(
      "This is a perfectly ordinary document with normal, non-repetitive text content in it.".repeat(20)
    );
    const zip = await buildZip({ "readme.txt": normalContent });

    const findings = await ZipBombGuardValidator.validate(zip);
    expect(findings).toEqual([]);
  });

  test("flags an entry with an absurd compression ratio", async () => {
    const zeros = Buffer.alloc(5 * 1024 * 1024); // 5MB of zeros — compresses extremely well
    const zip = await buildZip({ "zeros.bin": zeros });

    const findings = await ZipBombGuardValidator.validate(zip);
    const finding = findings.find((f) => f.rule === "zip-bomb-compression-ratio");
    expect(finding).toBeDefined();
    expect(finding.severity).toBe("extreme");
    expect(finding.details.fileName).toBe("zeros.bin");
    expect(finding.details.ratio).toBeGreaterThan(100);
  });

  test("flags an entry claiming data from zero compressed bytes", async () => {
    const zip = buildZipWithClaimedSizes({
      name: "impossible.bin",
      compressedSize: 0,
      uncompressedSize: 1024,
    });

    const findings = await ZipBombGuardValidator.validate(zip);
    const finding = findings.find((f) => f.rule === "zip-bomb-compression-ratio");
    expect(finding).toBeDefined();
    expect(finding.severity).toBe("extreme");
    expect(finding.details.ratio).toBe(Infinity);
  });

  test("flags total uncompressed size exceeding a configured limit", async () => {
    const validator = createZipBombGuardValidator({ maxTotalUncompressedBytes: 1000 });

    const content = Buffer.from("x".repeat(2000));
    const zip = await buildZip({ "file.txt": content });

    const findings = await validator.validate(zip);
    const finding = findings.find((f) => f.rule === "zip-bomb-total-size");
    expect(finding).toBeDefined();
    expect(finding.details.totalUncompressedBytes).toBe(2000);
  });

  test("a small file under the configured limits produces no size finding", async () => {
    const validator = createZipBombGuardValidator({ maxTotalUncompressedBytes: 1000 });
    const content = Buffer.from("small file");
    const zip = await buildZip({ "file.txt": content });

    const findings = await validator.validate(zip);
    expect(findings.map((f) => f.rule)).not.toContain("zip-bomb-total-size");
  });

  test("sums uncompressed size across multiple entries", async () => {
    const validator = createZipBombGuardValidator({ maxTotalUncompressedBytes: 1000 });
    const zip = await buildZip({
      "a.txt": Buffer.from("x".repeat(600)),
      "b.txt": Buffer.from("x".repeat(600)),
    });

    const findings = await validator.validate(zip);
    const finding = findings.find((f) => f.rule === "zip-bomb-total-size");
    expect(finding).toBeDefined();
    expect(finding.details.totalUncompressedBytes).toBe(1200);
  });

  test("a corrupted/truncated zip produces no findings rather than throwing", async () => {
    const zip = await buildZip({ "file.txt": Buffer.from("hello") });
    const truncated = zip.subarray(0, zip.length - 10);

    await expect(ZipBombGuardValidator.validate(truncated)).resolves.toBeDefined();
  });
});