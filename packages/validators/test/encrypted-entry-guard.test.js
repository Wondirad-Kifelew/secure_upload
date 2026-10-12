import { EncryptedEntryGuardValidator } from "../src/zip/before-unzip/encrypted-entry-guard.js";

// Raw ZIP builder — lets us set the general-purpose bit flag directly
// (bit 0 = "this entry is encrypted"), since yazl's public API has no
// way to mark an entry as encrypted.

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
  // files: { name: { content: Buffer, flags: number } }
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const [name, spec] of Object.entries(files)) {
    const content = spec.content;
    const flags = spec.flags || 0;
    const nameBuf = Buffer.from(name, "utf8");
    const crc = crc32(content);
    const size = content.length;

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(flags, 6);
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
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(flags, 8);
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

describe("EncryptedEntryGuardValidator", () => {
  test("has the expected Validator shape", () => {
    expect(EncryptedEntryGuardValidator.name).toBe("Encrypted Entry Guard");
    expect(typeof EncryptedEntryGuardValidator.validate).toBe("function");
  });

  test("a non-zip file produces no findings", async () => {
    const findings = await EncryptedEntryGuardValidator.validate(
      Buffer.from("just some text, not a zip")
    );
    expect(findings).toEqual([]);
  });

  test("a zip with only ordinary, unencrypted entries produces no findings", async () => {
    const zip = buildZip({
      "readme.txt": { content: Buffer.from("hello"), flags: 0 },
    });
    const findings = await EncryptedEntryGuardValidator.validate(zip);
    expect(findings).toEqual([]);
  });

  test("flags an entry marked as encrypted", async () => {
    const zip = buildZip({
      "secret.docx": { content: Buffer.from("fake encrypted bytes"), flags: 0x0001 },
    });
    const findings = await EncryptedEntryGuardValidator.validate(zip);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("zip-encrypted-entry");
    expect(findings[0].severity).toBe("high");
  });

  test("a corrupted/truncated zip produces no findings rather than throwing", async () => {
    const corrupted = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00]);
    const findings = await EncryptedEntryGuardValidator.validate(corrupted);
    expect(findings).toEqual([]);
  });
});