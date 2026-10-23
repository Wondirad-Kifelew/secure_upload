import { ArchiveIntegrityGuardValidator } from "../src/zip/before-unzip/archive-integrity-guard.js";

function crc32(buf) {
  let table = crc32.table;
  if (!table) {
    table = crc32.table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) {
        c = c & 1 ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
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

function buildZip(files) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const [name, content] of Object.entries(files)) {
    const nameBuf = Buffer.from(name, "utf8");
    const crc = crc32(content);
    const size = content.length;

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

    const localEntry = Buffer.concat([localHeader, nameBuf, content]);
    localParts.push(localEntry);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(0, 6);
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
    centralHeader.writeUInt32LE(offset, 42);

    const centralEntry = Buffer.concat([centralHeader, nameBuf]);
    centralParts.push(centralEntry);

    offset += localEntry.length;
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

describe("ArchiveIntegrityGuardValidator", () => {
  test("has the expected Validator shape", () => {
    expect(ArchiveIntegrityGuardValidator.name).toBe("Archive Integrity Guard");
    expect(typeof ArchiveIntegrityGuardValidator.validate).toBe("function");
  });

  test("a valid zip gives no findings", async () => {
    const zip = buildZip({
      "document.txt": Buffer.from("Valid zip content"),
      "folder/file.json": Buffer.from('{"ok":true}'),
    });
    const findings = await ArchiveIntegrityGuardValidator.validate(zip);
    expect(findings).toEqual([]);
  });

  test("a valid zip with its end-of-central-directory record cut off gives archive-unreadable high", async () => {
    const zip = buildZip({
      "document.txt": Buffer.from("Valid zip content"),
    });
    // The EOCD record is the last 22 bytes. Slicing off 22 bytes removes the EOCD record.
    const truncated = zip.subarray(0, zip.length - 22);
    const findings = await ArchiveIntegrityGuardValidator.validate(truncated);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("archive-unreadable");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].details.reason).toBeDefined();
    expect(typeof findings[0].details.reason).toBe("string");
  });

  test("'PK\\x03\\x04' followed by random bytes gives archive-unreadable high", async () => {
    const randomGarbage = Buffer.concat([
      Buffer.from([0x50, 0x4b, 0x03, 0x04]),
      Buffer.from("completely invalid corrupt payload without central directory records"),
    ]);
    const findings = await ArchiveIntegrityGuardValidator.validate(randomGarbage);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("archive-unreadable");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].details.reason).toBeDefined();
  });

  test("a plain text file gives no findings", async () => {
    const textBuffer = Buffer.from("This is a plain text file, not a ZIP archive.");
    const findings = await ArchiveIntegrityGuardValidator.validate(textBuffer);
    expect(findings).toEqual([]);
  });
});
