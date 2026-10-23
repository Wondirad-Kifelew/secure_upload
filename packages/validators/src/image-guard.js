/**
 * ImageGuardValidator
 * -------------------
 * Validates image dimensions, metadata sizes, and structural integrity
 * for JPEG, PNG, and GIF uploads without full image decoding.
 *
 * Implements the Validator contract from core/src/interfaces/validator.js:
 *   { name: string, async validate(buffer, meta) -> Finding[] }
 */

const MAX_PIXELS = 100_000_000;
const MAX_DIMENSION = 30_000;
const MAX_METADATA_BYTES = 256 * 1024;
const MAX_SEGMENTS = 10_000;

function checkJpeg(buffer) {
  const findings = [];
  let offset = 2; // after FF D8
  let segmentCount = 0;
  let foundSOS = false;
  let width = 0;
  let height = 0;
  let foundDimensions = false;
  let metadataBytes = 0;

  while (offset < buffer.length) {
    if (++segmentCount > MAX_SEGMENTS) {
      findings.push({
        rule: "image-structure-invalid",
        severity: "medium",
        message: "Image structure is invalid: exceeded maximum segment count.",
        details: { reason: "exceeded maximum segment count" },
      });
      break;
    }

    if (buffer[offset] !== 0xFF) {
      if (!foundSOS) {
        findings.push({
          rule: "image-structure-invalid",
          severity: "medium",
          message: "Image structure is invalid: expected JPEG marker prefix 0xFF.",
          details: { reason: "expected JPEG marker prefix 0xFF" },
        });
      }
      break;
    }

    // Skip fill bytes 0xFF
    while (offset < buffer.length && buffer[offset] === 0xFF) {
      offset++;
    }

    if (offset >= buffer.length) {
      break;
    }

    const marker = buffer[offset++];

    // Standalone markers without length:
    // 0xD8 (SOI), 0xD9 (EOI), 0x01 (TEM), 0xD0..0xD7 (RST)
    if (marker === 0xD9) {
      // EOI
      break;
    }
    if (marker === 0xD8 || marker === 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
      continue;
    }

    if (offset + 2 > buffer.length) {
      findings.push({
        rule: "image-structure-invalid",
        severity: "medium",
        message: "Image structure is invalid: truncated segment header.",
        details: { reason: "truncated segment header" },
      });
      break;
    }

    const segLength = buffer.readUInt16BE(offset);
    if (segLength < 2) {
      findings.push({
        rule: "image-structure-invalid",
        severity: "medium",
        message: "Image structure is invalid: segment length less than 2.",
        details: { reason: "segment length less than 2" },
      });
      break;
    }

    if (offset + segLength > buffer.length) {
      findings.push({
        rule: "image-structure-invalid",
        severity: "medium",
        message: "Image structure is invalid: segment length extends past buffer end.",
        details: { reason: "segment length extends past buffer end" },
      });
      break;
    }

    // Metadata segments: APP1..APP15 (0xE1..0xEF) and COM (0xFE)
    if ((marker >= 0xE1 && marker <= 0xEF) || marker === 0xFE) {
      metadataBytes += segLength;
    }

    // SOF markers (SOF0..SOF15 except C4, C8, CC)
    if (marker >= 0xC0 && marker <= 0xCF && marker !== 0xC4 && marker !== 0xC8 && marker !== 0xCC) {
      if (segLength >= 7) {
        height = buffer.readUInt16BE(offset + 3);
        width = buffer.readUInt16BE(offset + 5);
        foundDimensions = true;
      }
    }

    // SOS marker (0xDA)
    if (marker === 0xDA) {
      foundSOS = true;
      offset += segLength;
      break;
    }

    offset += segLength;
  }

  if (!foundSOS && !findings.some((f) => f.rule === "image-structure-invalid")) {
    findings.push({
      rule: "image-structure-invalid",
      severity: "medium",
      message: "Image structure is invalid: no SOS marker found in JPEG.",
      details: { reason: "no SOS marker found" },
    });
  }

  if (foundDimensions) {
    if (width * height > MAX_PIXELS || width > MAX_DIMENSION || height > MAX_DIMENSION) {
      findings.push({
        rule: "image-dimension-bomb",
        severity: "high",
        message: `Image dimensions (${width}x${height}) exceed safety limits.`,
        details: { width, height },
      });
    }
  }

  if (metadataBytes > MAX_METADATA_BYTES) {
    findings.push({
      rule: "image-oversized-metadata",
      severity: "medium",
      message: `Oversized image metadata: ${metadataBytes} bytes exceeds limit of 256 KB.`,
      details: { metadataBytes },
    });
  }

  return findings;
}

function checkPng(buffer) {
  const findings = [];
  let offset = 8; // after 8-byte signature
  let chunkCount = 0;
  let firstChunk = true;
  let foundIEND = false;
  let width = 0;
  let height = 0;
  let foundDimensions = false;
  let metadataBytes = 0;

  while (offset < buffer.length) {
    if (++chunkCount > MAX_SEGMENTS) {
      findings.push({
        rule: "image-structure-invalid",
        severity: "medium",
        message: "Image structure is invalid: exceeded maximum chunk count.",
        details: { reason: "exceeded maximum chunk count" },
      });
      break;
    }

    if (offset + 8 > buffer.length) {
      findings.push({
        rule: "image-structure-invalid",
        severity: "medium",
        message: "Image structure is invalid: truncated chunk header.",
        details: { reason: "truncated chunk header" },
      });
      break;
    }

    const length = buffer.readUInt32BE(offset);
    if (offset + 12 + length > buffer.length) {
      findings.push({
        rule: "image-structure-invalid",
        severity: "medium",
        message: "Image structure is invalid: chunk length extends past buffer end.",
        details: { reason: "chunk length extends past buffer end" },
      });
      break;
    }

    const type = buffer.toString("ascii", offset + 4, offset + 8);

    if (firstChunk) {
      if (type !== "IHDR") {
        findings.push({
          rule: "image-structure-invalid",
          severity: "medium",
          message: "Image structure is invalid: first chunk must be IHDR.",
          details: { reason: "first chunk must be IHDR" },
        });
        break;
      }
      firstChunk = false;

      if (length >= 8) {
        width = buffer.readUInt32BE(offset + 8);
        height = buffer.readUInt32BE(offset + 12);
        foundDimensions = true;
      }
    }

    // Metadata chunks: tEXt, zTXt, iTXt, eXIf
    if (type === "tEXt" || type === "zTXt" || type === "iTXt" || type === "eXIf") {
      metadataBytes += length;
    }

    if (type === "IEND") {
      foundIEND = true;
      offset += 12 + length;
      break;
    }

    offset += 12 + length;
  }

  if (firstChunk && !findings.some((f) => f.rule === "image-structure-invalid")) {
    findings.push({
      rule: "image-structure-invalid",
      severity: "medium",
      message: "Image structure is invalid: missing IHDR chunk.",
      details: { reason: "missing IHDR chunk" },
    });
  } else if (!foundIEND && !findings.some((f) => f.rule === "image-structure-invalid")) {
    findings.push({
      rule: "image-structure-invalid",
      severity: "medium",
      message: "Image structure is invalid: no IEND chunk found in PNG.",
      details: { reason: "no IEND chunk found" },
    });
  }

  if (foundDimensions) {
    if (width * height > MAX_PIXELS || width > MAX_DIMENSION || height > MAX_DIMENSION) {
      findings.push({
        rule: "image-dimension-bomb",
        severity: "high",
        message: `Image dimensions (${width}x${height}) exceed safety limits.`,
        details: { width, height },
      });
    }
  }

  if (metadataBytes > MAX_METADATA_BYTES) {
    findings.push({
      rule: "image-oversized-metadata",
      severity: "medium",
      message: `Oversized image metadata: ${metadataBytes} bytes exceeds limit of 256 KB.`,
      details: { metadataBytes },
    });
  }

  return findings;
}

function checkGif(buffer) {
  const findings = [];
  if (buffer.length < 13) {
    findings.push({
      rule: "image-structure-invalid",
      severity: "medium",
      message: "Image structure is invalid: truncated GIF header.",
      details: { reason: "truncated GIF header" },
    });
    return findings;
  }

  const width = buffer.readUInt16LE(6);
  const height = buffer.readUInt16LE(8);
  const packed = buffer[10];
  const hasGct = (packed & 0x80) !== 0;
  const gctSize = hasGct ? 3 * (1 << ((packed & 0x07) + 1)) : 0;
  let offset = 13 + gctSize;

  if (offset > buffer.length) {
    findings.push({
      rule: "image-structure-invalid",
      severity: "medium",
      message: "Image structure is invalid: truncated global color table in GIF.",
      details: { reason: "truncated global color table" },
    });
    return findings;
  }

  let foundTrailer = false;
  let blockCount = 0;
  let metadataBytes = 0;

  while (offset < buffer.length) {
    if (++blockCount > MAX_SEGMENTS) {
      findings.push({
        rule: "image-structure-invalid",
        severity: "medium",
        message: "Image structure is invalid: exceeded maximum block count in GIF.",
        details: { reason: "exceeded maximum block count" },
      });
      break;
    }

    const introducer = buffer[offset++];

    if (introducer === 0x3B) {
      foundTrailer = true;
      break;
    }

    if (introducer === 0x21) {
      if (offset >= buffer.length) {
        findings.push({
          rule: "image-structure-invalid",
          severity: "medium",
          message: "Image structure is invalid: truncated extension block.",
          details: { reason: "truncated extension block" },
        });
        break;
      }
      const label = buffer[offset++];
      const isMetadata = label === 0xFE || label === 0xFF;

      // Sub-block loops need no count cap because every iteration advances
      // offset by at least 1 byte (the length byte), guaranteeing linear
      // progress and natural termination at the buffer boundary.
      let broken = false;
      while (offset < buffer.length) {
        const subLength = buffer[offset++];
        if (subLength === 0) {
          break;
        }
        if (offset + subLength > buffer.length) {
          findings.push({
            rule: "image-structure-invalid",
            severity: "medium",
            message: "Image structure is invalid: sub-block extends beyond buffer.",
            details: { reason: "sub-block extends beyond buffer" },
          });
          broken = true;
          break;
        }
        if (isMetadata) {
          metadataBytes += subLength;
        }
        offset += subLength;
      }
      if (broken) break;
      continue;
    }

    if (introducer === 0x2C) {
      if (offset + 9 > buffer.length) {
        findings.push({
          rule: "image-structure-invalid",
          severity: "medium",
          message: "Image structure is invalid: truncated image descriptor in GIF.",
          details: { reason: "truncated image descriptor" },
        });
        break;
      }

      const imgPacked = buffer[offset + 8];
      offset += 9;

      const hasLct = (imgPacked & 0x80) !== 0;
      if (hasLct) {
        const lctSize = 3 * (1 << ((imgPacked & 0x07) + 1));
        if (offset + lctSize > buffer.length) {
          findings.push({
            rule: "image-structure-invalid",
            severity: "medium",
            message: "Image structure is invalid: truncated local color table in GIF.",
            details: { reason: "truncated local color table" },
          });
          break;
        }
        offset += lctSize;
      }

      if (offset >= buffer.length) {
        findings.push({
          rule: "image-structure-invalid",
          severity: "medium",
          message: "Image structure is invalid: truncated LZW code size in GIF.",
          details: { reason: "truncated LZW code size" },
        });
        break;
      }
      offset++; // Skip LZW min code size

      // Image data sub-blocks need no count cap because every iteration
      // advances offset by at least 1 byte (the length byte), guaranteeing linear
      // progress and natural termination at the buffer boundary.
      let broken = false;
      while (offset < buffer.length) {
        const subLength = buffer[offset++];
        if (subLength === 0) {
          break;
        }
        if (offset + subLength > buffer.length) {
          findings.push({
            rule: "image-structure-invalid",
            severity: "medium",
            message: "Image structure is invalid: image data sub-block extends beyond buffer.",
            details: { reason: "image data sub-block extends beyond buffer" },
          });
          broken = true;
          break;
        }
        offset += subLength;
      }
      if (broken) break;
      continue;
    }

    findings.push({
      rule: "image-structure-invalid",
      severity: "medium",
      message: `Image structure is invalid: unexpected byte 0x${introducer.toString(16)} in GIF.`,
      details: { reason: `unexpected byte 0x${introducer.toString(16)}` },
    });
    break;
  }

  if (!foundTrailer && !findings.some((f) => f.rule === "image-structure-invalid")) {
    findings.push({
      rule: "image-structure-invalid",
      severity: "medium",
      message: "Image structure is invalid: missing trailer 0x3B in GIF.",
      details: { reason: "missing trailer 0x3B" },
    });
  }

  if (width * height > MAX_PIXELS || width > MAX_DIMENSION || height > MAX_DIMENSION) {
    findings.push({
      rule: "image-dimension-bomb",
      severity: "high",
      message: `Image dimensions (${width}x${height}) exceed safety limits.`,
      details: { width, height },
    });
  }

  if (metadataBytes > MAX_METADATA_BYTES) {
    findings.push({
      rule: "image-oversized-metadata",
      severity: "medium",
      message: `Oversized image metadata: ${metadataBytes} bytes exceeds limit of 256 KB.`,
      details: { metadataBytes },
    });
  }

  return findings;
}

export const ImageGuardValidator = {
  name: "Image Guard",

  /**
   * @param {Buffer} buffer
   * @param {{ filename?: string, declaredMimeType?: string }} meta
   * @returns {Promise<import('@secureupload/core').ValidationFinding[]>}
   */
  async validate(buffer, meta = {}) {
    console.log("Running image guard validator...");
    try {
      if (!Buffer.isBuffer(buffer) || buffer.length < 3) {
        return [];
      }

      // JPEG: FF D8 FF
      if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
        return checkJpeg(buffer);
      }

      // PNG: 89 50 4E 47 0D 0A 1A 0A
      if (
        buffer.length >= 8 &&
        buffer[0] === 0x89 &&
        buffer[1] === 0x50 &&
        buffer[2] === 0x4E &&
        buffer[3] === 0x47 &&
        buffer[4] === 0x0D &&
        buffer[5] === 0x0A &&
        buffer[6] === 0x1A &&
        buffer[7] === 0x0A
      ) {
        return checkPng(buffer);
      }

      // GIF: "GIF87a" or "GIF89a"
      if (
        buffer.length >= 6 &&
        buffer[0] === 0x47 &&
        buffer[1] === 0x49 &&
        buffer[2] === 0x46 &&
        buffer[3] === 0x38 &&
        (buffer[4] === 0x37 || buffer[4] === 0x39) &&
        buffer[5] === 0x61
      ) {
        return checkGif(buffer);
      }

      return [];
    } catch {
      return [];
    }
  },
};
