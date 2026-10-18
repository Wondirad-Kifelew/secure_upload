import { NonRecursiveBombGuardValidator } from "../src/zip/before-unzip/non-recursive-bomb-guard.js";

function crc32(buf) {
  let table = crc32.table;
  if (!table) {
    table = crc32.table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) {
        c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      }
      table[n] = c;
    }
  }
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Builds a ZIP buffer, allowing manual specification of entry offsets
 * so we can simulate shared / overlapping non-recursive bomb structures.
 */
function buildCustomZip(entriesList) {
  // entriesList: array of { name: string, content: Buffer, customOffset?: number }
  const localParts = [];
  const centralParts = [];
  let currentOffset = 0;

  for (const item of entriesList) {
    const nameBuf = Buffer.from(item.name, "utf8");
    const crc = crc32(item.content);
    const size = item.content.length;

    // Local Header
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(size, 18);
    localHeader.writeUInt32LE(size, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);

    const localEntry = Buffer.concat([localHeader, nameBuf, item.content]);
    localParts.push(localEntry);

    const targetOffset = item.customOffset !== undefined ? item.customOffset : currentOffset;

    // Central Directory Header
    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0, 8);
    centralHeader.writeUInt16LE(0, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(size, 20);
    centralHeader.writeUInt32LE(size, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(targetOffset, 42);

    const centralEntry = Buffer.concat([centralHeader, nameBuf]);
    centralParts.push(centralEntry);

    currentOffset += localEntry.length;
  }

  const localSection = Buffer.concat(localParts);
  const centralSection = Buffer.concat(centralParts);

  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(centralParts.length, 8);
  end.writeUInt16LE(centralParts.length, 10);
  end.writeUInt32LE(centralSection.length, 12);
  end.writeUInt32LE(localSection.length, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([localSection, centralSection, end]);
}

describe("NonRecursiveBombGuardValidator", () => {
  test("has expected shape", () => {
    expect(NonRecursiveBombGuardValidator.name).toBe("Non-Recursive Zip Bomb Guard");
    expect(typeof NonRecursiveBombGuardValidator.validate).toBe("function");
  });

  test("non-zip returns no findings", async () => {
    const findings = await NonRecursiveBombGuardValidator.validate(Buffer.from("not a zip"));
    expect(findings).toEqual([]);
  });

  test("clean normal zip produces no findings", async () => {
    const zip = buildCustomZip([
      { name: "file1.txt", content: Buffer.from("hello file 1") },
      { name: "file2.txt", content: Buffer.from("hello file 2") },
    ]);

    const findings = await NonRecursiveBombGuardValidator.validate(zip);
    expect(findings).toEqual([]);
  });

  test("detects identical local header offset reuse across entries", async () => {
    // Both entries point to offset 0 (classic non-recursive bomb signature)
    const zip = buildCustomZip([
      { name: "payload1.bin", content: Buffer.from("compressed shared kernel"), customOffset: 0 },
      { name: "payload2.bin", content: Buffer.from("compressed shared kernel"), customOffset: 0 },
    ]);

    const findings = await NonRecursiveBombGuardValidator.validate(zip);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("zip-non-recursive-bomb-shared-offset");
    expect(findings[0].severity).toBe("extreme");
  });

  test("detects overlapping payload byte ranges", async () => {
    // Entry 1 starts at 0 with 50 bytes data; Entry 2 artificially starts inside Entry 1's range
    const zip = buildCustomZip([
      { name: "fileA.bin", content: Buffer.alloc(50, 0x41), customOffset: 0 },
      { name: "fileB.bin", content: Buffer.alloc(20, 0x42), customOffset: 10 },
    ]);

    const findings = await NonRecursiveBombGuardValidator.validate(zip);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule).toMatch(/^zip-non-recursive-bomb/);
    expect(findings[0].severity).toBe("extreme");
  });
});
