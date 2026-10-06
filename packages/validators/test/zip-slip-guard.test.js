import { ZipSlipGuardValidator } from "../src/zip/before-unzip/zip-slip-guard.js";

// Raw ZIP builder — bypasses yazl's own path-safety checks so we can
// build "malicious" fixtures (yazl refuses to write dangerous names itself).

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

describe("ZipSlipGuardValidator", () => {
  test("has the expected Validator shape", () => {
    expect(ZipSlipGuardValidator.name).toBe("Zip Slip Guard");
    expect(typeof ZipSlipGuardValidator.validate).toBe("function");
  });

  test("a non-zip file produces no findings", async () => {
    const findings = await ZipSlipGuardValidator.validate(
      Buffer.from("just some text, not a zip")
    );
    expect(findings).toEqual([]);
  });

  test("a normal zip with ordinary entry names produces no findings", async () => {
    const zip = buildZip({
      "readme.txt": Buffer.from("hello"),
      "images/logo.png": Buffer.from("fake png bytes"),
    });
    const findings = await ZipSlipGuardValidator.validate(zip);
    expect(findings).toEqual([]);
  });

  test("flags an entry name containing literal path traversal", async () => {
    const zip = buildZip({ "../../etc/passwd": Buffer.from("evil") });
    const findings = await ZipSlipGuardValidator.validate(zip);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("zip-slip-path-traversal");
  });

  test("flags a traversal sequence buried inside a normal-looking subfolder", async () => {
    const zip = buildZip({ "images/../../../etc/passwd": Buffer.from("evil") });
    const findings = await ZipSlipGuardValidator.validate(zip);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("zip-slip-path-traversal");
  });

  test("flags a Windows-style backslash traversal sequence", async () => {
    const zip = buildZip({ "..\\..\\Windows\\System32\\evil.dll": Buffer.from("evil") });
    const findings = await ZipSlipGuardValidator.validate(zip);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("zip-slip-path-traversal");
  });

  test("flags an entry name that is an absolute Unix path", async () => {
    const zip = buildZip({ "/etc/shadow": Buffer.from("evil") });
    const findings = await ZipSlipGuardValidator.validate(zip);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("zip-slip-path-traversal");
  });

  test("flags an entry name that is an absolute Windows path", async () => {
    const zip = buildZip({ "C:\\Windows\\System32\\evil.dll": Buffer.from("evil") });
    const findings = await ZipSlipGuardValidator.validate(zip);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("zip-slip-path-traversal");
  });

  test("a corrupted/truncated zip produces no findings rather than throwing", async () => {
    const corrupted = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00]);
    const findings = await ZipSlipGuardValidator.validate(corrupted);
    expect(findings).toEqual([]);
  });
});