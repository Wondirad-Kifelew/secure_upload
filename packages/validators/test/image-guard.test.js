import { ImageGuardValidator } from "../src/image-guard.js";

function createMinimalJpeg({
  width = 1,
  height = 1,
  includeSOS = true,
  appSegments = [],
  comSegments = [],
  corruptLength = null,
} = {}) {
  const parts = [];
  // SOI
  parts.push(Buffer.from([0xFF, 0xD8]));

  // Custom APP segments
  for (const app of appSegments) {
    const marker = app.marker || 0xE1;
    const len = app.data.length + 2;
    const header = Buffer.alloc(4);
    header[0] = 0xFF;
    header[1] = marker;
    header.writeUInt16BE(len, 2);
    parts.push(header, app.data);
  }

  // Custom COM segments
  for (const com of comSegments) {
    const len = com.length + 2;
    const header = Buffer.alloc(4);
    header[0] = 0xFF;
    header[1] = 0xFE;
    header.writeUInt16BE(len, 2);
    parts.push(header, com);
  }

  // SOF0
  const sofHeader = Buffer.alloc(4);
  sofHeader[0] = 0xFF;
  sofHeader[1] = 0xC0;
  if (corruptLength !== null) {
    sofHeader.writeUInt16BE(corruptLength, 2);
    parts.push(sofHeader);
    return Buffer.concat(parts);
  }
  sofHeader.writeUInt16BE(11, 2);
  const sofData = Buffer.alloc(9);
  sofData[0] = 8;
  sofData.writeUInt16BE(height, 1);
  sofData.writeUInt16BE(width, 3);
  sofData[5] = 1;
  sofData[6] = 1;
  sofData[7] = 0x11;
  sofData[8] = 0;
  parts.push(sofHeader, sofData);

  if (includeSOS) {
    const sosHeader = Buffer.alloc(4);
    sosHeader[0] = 0xFF;
    sosHeader[1] = 0xDA;
    sosHeader.writeUInt16BE(8, 2);
    const sosData = Buffer.from([1, 1, 0, 0, 63, 0]);
    parts.push(sosHeader, sosData);
    parts.push(Buffer.from([0x00])); // Dummy scan byte
    parts.push(Buffer.from([0xFF, 0xD9])); // EOI
  }

  return Buffer.concat(parts);
}

function createMinimalPng({
  width = 1,
  height = 1,
  includeIend = true,
  metadataChunks = [],
  firstChunkType = "IHDR",
} = {}) {
  const parts = [];
  parts.push(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]));

  const ihdrHeader = Buffer.alloc(8);
  ihdrHeader.writeUInt32BE(13, 0);
  ihdrHeader.write(firstChunkType, 4, 4, "ascii");
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData[8] = 8;
  ihdrData[9] = 2;
  ihdrData[10] = 0;
  ihdrData[11] = 0;
  ihdrData[12] = 0;
  const ihdrCrc = Buffer.alloc(4);
  parts.push(ihdrHeader, ihdrData, ihdrCrc);

  for (const chunk of metadataChunks) {
    const header = Buffer.alloc(8);
    header.writeUInt32BE(chunk.data.length, 0);
    header.write(chunk.type, 4, 4, "ascii");
    const crc = Buffer.alloc(4);
    parts.push(header, chunk.data, crc);
  }

  const idatHeader = Buffer.alloc(8);
  idatHeader.writeUInt32BE(2, 0);
  idatHeader.write("IDAT", 4, 4, "ascii");
  const idatData = Buffer.from([0x78, 0x01]);
  const idatCrc = Buffer.alloc(4);
  parts.push(idatHeader, idatData, idatCrc);

  if (includeIend) {
    const iendHeader = Buffer.alloc(8);
    iendHeader.writeUInt32BE(0, 0);
    iendHeader.write("IEND", 4, 4, "ascii");
    const iendCrc = Buffer.alloc(4);
    parts.push(iendHeader, iendCrc);
  }

  return Buffer.concat(parts);
}

function createMinimalGif({
  width = 1,
  height = 1,
  includeTrailer = true,
  metadataExtensions = [],
  imageDataSubBlocks = null,
  truncateImageDataMidSubBlock = false,
} = {}) {
  const parts = [];
  parts.push(Buffer.from("GIF89a", "ascii"));

  const lsd = Buffer.alloc(7);
  lsd.writeUInt16LE(width, 0);
  lsd.writeUInt16LE(height, 2);
  lsd[4] = 0;
  lsd[5] = 0;
  lsd[6] = 0;
  parts.push(lsd);

  for (const ext of metadataExtensions) {
    parts.push(Buffer.from([0x21, ext.label]));
    for (const sub of ext.subBlocks) {
      parts.push(Buffer.from([sub.length]), sub);
    }
    parts.push(Buffer.from([0x00]));
  }

  const imgDesc = Buffer.alloc(10);
  imgDesc[0] = 0x2C;
  imgDesc.writeUInt16LE(0, 1);
  imgDesc.writeUInt16LE(0, 3);
  imgDesc.writeUInt16LE(width > 65535 ? 65535 : width, 5);
  imgDesc.writeUInt16LE(height > 65535 ? 65535 : height, 7);
  imgDesc[9] = 0;
  parts.push(imgDesc);

  // LZW minimum code size
  parts.push(Buffer.from([0x02]));

  if (truncateImageDataMidSubBlock) {
    // Sub-block length claims 255, but only 10 bytes provided and no trailer
    parts.push(Buffer.from([255]), Buffer.alloc(10));
  } else if (imageDataSubBlocks) {
    for (const sub of imageDataSubBlocks) {
      parts.push(Buffer.from([sub.length]), sub);
    }
    parts.push(Buffer.from([0x00])); // Terminator
  } else {
    parts.push(Buffer.from([0x02, 0x4C, 0x01, 0x00]));
  }

  if (includeTrailer) {
    parts.push(Buffer.from([0x3B]));
  }

  return Buffer.concat(parts);
}

describe("ImageGuardValidator", () => {
  test("valid small JPEG, PNG, GIF produce no findings", async () => {
    const jpeg = createMinimalJpeg({ width: 100, height: 100 });
    const png = createMinimalPng({ width: 100, height: 100 });
    const gif = createMinimalGif({ width: 100, height: 100 });

    expect(await ImageGuardValidator.validate(jpeg)).toEqual([]);
    expect(await ImageGuardValidator.validate(png)).toEqual([]);
    expect(await ImageGuardValidator.validate(gif)).toEqual([]);
  });

  test("PNG with IHDR claiming 60000x60000 and a tiny body triggers image-dimension-bomb", async () => {
    const bombPng = createMinimalPng({ width: 60000, height: 60000 });
    const findings = await ImageGuardValidator.validate(bombPng);

    expect(findings.some((f) => f.rule === "image-dimension-bomb")).toBe(true);
    const bombFinding = findings.find((f) => f.rule === "image-dimension-bomb");
    expect(bombFinding.severity).toBe("high");
    expect(bombFinding.details).toEqual({ width: 60000, height: 60000 });
  });

  test("JPEG with 300 KB total of COM segments triggers image-oversized-metadata; one 6 KB APP1 does not", async () => {
    const comSegments = Array.from({ length: 5 }, () => Buffer.alloc(60 * 1024));
    const oversizedJpeg = createMinimalJpeg({ comSegments });
    const oversizedFindings = await ImageGuardValidator.validate(oversizedJpeg);

    expect(oversizedFindings.some((f) => f.rule === "image-oversized-metadata")).toBe(true);
    const finding = oversizedFindings.find((f) => f.rule === "image-oversized-metadata");
    expect(finding.severity).toBe("medium");
    expect(finding.details.metadataBytes).toBeGreaterThan(256 * 1024);

    const normalJpeg = createMinimalJpeg({
      appSegments: [{ marker: 0xE1, data: Buffer.alloc(6 * 1024) }],
    });
    const normalFindings = await ImageGuardValidator.validate(normalJpeg);
    expect(normalFindings.some((f) => f.rule === "image-oversized-metadata")).toBe(false);
  });

  test("truncated JPEG (no SOS), PNG without IEND, GIF without trailer trigger image-structure-invalid", async () => {
    const noSosJpeg = createMinimalJpeg({ includeSOS: false });
    const jpegFindings = await ImageGuardValidator.validate(noSosJpeg);
    expect(jpegFindings.some((f) => f.rule === "image-structure-invalid")).toBe(true);

    const noIendPng = createMinimalPng({ includeIend: false });
    const pngFindings = await ImageGuardValidator.validate(noIendPng);
    expect(pngFindings.some((f) => f.rule === "image-structure-invalid")).toBe(true);

    const noTrailerGif = createMinimalGif({ includeTrailer: false });
    const gifFindings = await ImageGuardValidator.validate(noTrailerGif);
    expect(gifFindings.some((f) => f.rule === "image-structure-invalid")).toBe(true);
  });

  test("valid single-frame GIF with 5 MB of image data built from 255-byte sub-blocks produces no findings in under 500 ms", async () => {
    // 5 MB of image data built from 255-byte sub-blocks (~20,560 sub-blocks)
    const subBlockData = Buffer.alloc(255, 0x42);
    const count = Math.ceil((5 * 1024 * 1024) / 255);
    const subBlocks = Array.from({ length: count }, () => subBlockData);
    const largeGif = createMinimalGif({
      width: 100,
      height: 100,
      imageDataSubBlocks: subBlocks,
    });

    const start = performance.now();
    const findings = await ImageGuardValidator.validate(largeGif);
    const elapsed = performance.now() - start;

    expect(findings).toEqual([]);
    expect(elapsed).toBeLessThan(500);
  });

  test("GIF whose image data is truncated mid sub-block triggers image-structure-invalid", async () => {
    const truncatedGif = createMinimalGif({
      width: 100,
      height: 100,
      truncateImageDataMidSubBlock: true,
      includeTrailer: false,
    });
    const findings = await ImageGuardValidator.validate(truncatedGif);

    expect(findings.some((f) => f.rule === "image-structure-invalid")).toBe(true);
  });

  test("never throws on empty, 1-byte, corrupt segment length, or 1000 seeded random buffers", async () => {
    expect(Array.isArray(await ImageGuardValidator.validate(Buffer.alloc(0)))).toBe(true);
    expect(Array.isArray(await ImageGuardValidator.validate(Buffer.from([0x42])))).toBe(true);

    const zeroLenJpeg = createMinimalJpeg({ corruptLength: 0 });
    const zeroLenFindings = await ImageGuardValidator.validate(zeroLenJpeg);
    expect(Array.isArray(zeroLenFindings)).toBe(true);
    expect(zeroLenFindings.some((f) => f.rule === "image-structure-invalid")).toBe(true);

    const pastEndJpeg = createMinimalJpeg({ corruptLength: 60000 });
    const pastEndFindings = await ImageGuardValidator.validate(pastEndJpeg);
    expect(Array.isArray(pastEndFindings)).toBe(true);
    expect(pastEndFindings.some((f) => f.rule === "image-structure-invalid")).toBe(true);

    function mulberry32(seed) {
      return function () {
        let t = (seed += 0x6D2B79F5);
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
      };
    }

    const rand = mulberry32(42);
    const signatures = [
      Buffer.from([0xFF, 0xD8, 0xFF]),
      Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
      Buffer.from("GIF89a", "ascii"),
    ];

    for (let i = 0; i < 1000; i++) {
      const sig = signatures[i % signatures.length];
      const randomLen = Math.floor(rand() * 256);
      const randomBytes = Buffer.alloc(randomLen);
      for (let j = 0; j < randomLen; j++) {
        randomBytes[j] = Math.floor(rand() * 256);
      }
      const testBuffer = Buffer.concat([sig, randomBytes]);
      const result = await ImageGuardValidator.validate(testBuffer);
      expect(Array.isArray(result)).toBe(true);
    }
  });

  test("performance: a 10 MB valid-looking buffer finishes in under 500 ms", async () => {
    const jpegHead = createMinimalJpeg({ width: 1920, height: 1080 });
    const largeDummy = Buffer.alloc(10 * 1024 * 1024);
    const largeJpeg = Buffer.concat([jpegHead, largeDummy]);

    const start = performance.now();
    const result = await ImageGuardValidator.validate(largeJpeg);
    const elapsed = performance.now() - start;

    expect(Array.isArray(result)).toBe(true);
    expect(elapsed).toBeLessThan(500);
  });
});
