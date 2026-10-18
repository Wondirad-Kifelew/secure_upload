import { DeviceNameGuardValidator } from "../src/zip/before-unzip/device-name-guard.js";

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

function buildZip(files) {
  // files: { [name: string]: Buffer }
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

describe("DeviceNameGuardValidator", () => {
  test("has expected validator shape", () => {
    expect(DeviceNameGuardValidator.name).toBe("Windows Device Name Guard");
    expect(typeof DeviceNameGuardValidator.validate).toBe("function");
  });

  test("non-zip returns empty findings", async () => {
    const findings = await DeviceNameGuardValidator.validate(Buffer.from("not a zip"));
    expect(findings).toEqual([]);
  });

  test("normal files pass without findings", async () => {
    const zip = buildZip({
      "document.pdf": Buffer.from("pdf content"),
      "subfolder/data.json": Buffer.from("{}"),
    });
    const findings = await DeviceNameGuardValidator.validate(zip);
    expect(findings).toEqual([]);
  });

  test("flags exact DOS device names (CON, NUL, AUX, PRN)", async () => {
    const zip = buildZip({
      "CON": Buffer.from("bad"),
    });
    const findings = await DeviceNameGuardValidator.validate(zip);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("zip-forbidden-device-name");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].details.forbiddenSegment).toBe("CON");
  });

  test("flags DOS device names with extensions (aux.txt, com1.png)", async () => {
    const zip = buildZip({
      "reports/aux.txt": Buffer.from("test"),
      "com1.png": Buffer.from("img"),
    });
    const findings = await DeviceNameGuardValidator.validate(zip);
    expect(findings).toHaveLength(2);
    expect(findings[0].rule).toBe("zip-forbidden-device-name");
    expect(findings[1].rule).toBe("zip-forbidden-device-name");
  });
});
