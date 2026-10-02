import { tokenizer } from "acorn";
import { fileTypeFromBuffer } from "file-type";

/**
 * PolyglotDetectorValidator
 * ---------------------------
 * A polyglot is a file that's simultaneously valid under two unrelated
 * format interpretations — e.g. a file that's a genuinely valid GIF
 * AND, read as text, also valid, runnable JavaScript. Every other
 * validator in this package only ever asks "is this ONE claimed type
 * consistent" — none of them ask "does this ALSO validate as something
 * completely different." That's this validator's whole job.
 *
 * SCOPE, DELIBERATELY NARROW: this only checks the GIF/PNG/JPEG-style
 * "binary media that's also valid JS" combination, proven to work
 * reliably with low false positives (see the test file). It does NOT
 * attempt a PDF/ZIP-style "valid archive appended after a fake header"
 * check — that requires an offset-correcting zip parser (most strict
 * zip readers, including the yauzl library used elsewhere in this
 * project, don't auto-adjust for prepended bytes the way some more
 * permissive tools do), which is a genuinely harder, unverified
 * problem left for a future iteration rather than shipped untested.
 *
 * Why gate on "has a concrete detected type" first: JS's grammar is
 * very permissive — plain text files (CSV, config files, etc.) can
 * easily happen to ALSO parse as syntactically valid JS by pure
 * coincidence, which would make this validator noisy if run against
 * everything. Restricting it to files that file-type already
 * confidently identified as a concrete BINARY format (image, PDF,
 * etc.) makes a coincidental JS-parse essentially impossible — real
 * compressed pixel/binary data does not by chance form valid JS
 * syntax. See the sandbox verification: a genuine, non-crafted PNG's
 * real pixel data reliably throws a SyntaxError when parsed as JS.
 *
 * SAFETY NOTE: this only ever CONSTRUCTS a Function from the buffer's
 * text — it never CALLS it. Constructing parses/compiles the code but
 * does not execute the function body, so no attacker-controlled code
 * ever actually runs during detection.
 *
 * Implements the Validator contract from core/src/interfaces/validator.js.
 */

const DEFAULT_MAX_BUFFER_SIZE_TO_CHECK = 5 * 1024 * 1024;
const MIN_NON_WHITESPACE_LENGTH = 10;
const METADATA_REGION_SIZE = 64 * 1024;
const TRAILING_PAYLOAD_TOLERANCE = 64;
const MAX_TOKENS_TO_SCAN = 10000;

// Magic byte signatures
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const JPEG_SIGNATURE = Buffer.from([0xff, 0xd8, 0xff]);
const JPEG_EOI = Buffer.from([0xff, 0xd9]);
const PDF_SIGNATURE = Buffer.from("%PDF-");
const PDF_EOF = Buffer.from("%%EOF");

const ZIP_LOCAL_SIG = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
const ZIP_EOCD_SIG = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
const SEVEN_ZIP_SIG = Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);
const RAR_SIG = Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]);
const ELF_SIG = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
const JAVA_MACHO_SIG = Buffer.from([0xca, 0xfe, 0xba, 0xbe]);
const PE_DOS_MAGIC = Buffer.from([0x4d, 0x5a]);

const EXECUTABLE_JS_TOKEN = /\b(?:function|eval|var|let|const|window|document|console|globalThis|fetch|process|XMLHttpRequest|Function|setTimeout|setInterval)\b|=>/;
const EXECUTABLE_JS_NAMES = new Set([
  "eval",
  "let",
  "window",
  "document",
  "globalThis",
  "console",
  "fetch",
  "process",
  "XMLHttpRequest",
  "Function",
  "setTimeout",
  "setInterval",
]);
const EXECUTABLE_JS_KEYWORDS = new Set([
  "function",
  "var",
  "const",
  "class",
  "return",
  "throw",
  "import",
  "export",
  "new",
  "async",
]);

const SCRIPT_WRAPPERS = [
  { type: "PHP", opening: /<\?php(?=[\s?])/i, closing: /\?>/, html: false },
  { type: "PHP", opening: /<\?=(?=[\s\S])/i, closing: /\?>/, html: false },
  { type: "HTML script", opening: /<script(?=[\s/>])/i, closing: /<\/script\s*>/i, html: true },
  { type: "XML stylesheet", opening: /<\?xml-stylesheet(?=[\s?])/i, closing: /\?>/, html: false },
  { type: "ASP / JSP", opening: /<%(?:[^%>]{0,512}?(?:eval|execute|runtime|request|response|cmd)|=)/i, closing: /%>/i, html: false },
];

function startsWith(buffer, signature) {
  if (buffer.length < signature.length) return false;
  return buffer.subarray(0, signature.length).equals(signature);
}

function isPrimaryZipContainer(buffer, detectedMime, declaredMime) {
  if (startsWith(buffer, ZIP_LOCAL_SIG)) {
    return true;
  }
  const isZipMime = (m) => {
    if (!m) return false;
    return (
      m === "application/zip" ||
      m === "application/x-zip" ||
      m === "application/x-zip-compressed" ||
      m === "application/java-archive" ||
      m === "application/epub+zip" ||
      m === "application/vnd.android.package-archive" ||
      m.startsWith("application/vnd.openxmlformats-officedocument.") ||
      m.startsWith("application/vnd.oasis.opendocument.") ||
      m === "application/x-cfb" ||
      m === "application/msword" ||
      m === "application/vnd.ms-excel" ||
      m === "application/vnd.ms-powerpoint"
    );
  };
  return isZipMime(detectedMime) || isZipMime(declaredMime);
}

function isScriptableDocument(detectedMime, declaredMime) {
  const isDoc = (m) => {
    if (!m) return false;
    return (
      m === "text/html" ||
      m === "application/xhtml+xml" ||
      m === "image/svg+xml" ||
      m === "application/xml" ||
      m === "text/xml"
    );
  };
  return isDoc(detectedMime) || isDoc(declaredMime);
}

function isWindowsPE(buffer, offset) {
  // Must have at least DOS header size (64 bytes)
  if (offset + 64 > buffer.length) return false;
  // Check DOS magic 'MZ'
  if (buffer[offset] !== 0x4d || buffer[offset + 1] !== 0x5a) return false;

  // Read e_lfanew at 0x3c (little endian 32-bit unsigned offset)
  const peOffset = buffer.readUInt32LE(offset + 0x3c);
  if (peOffset < 64 || peOffset > 1024 * 1024) return false;

  const peStart = offset + peOffset;
  if (peStart + 4 > buffer.length) return false;

  // Check PE signature 'PE\0\0' (0x50, 0x45, 0x00, 0x00)
  return (
    buffer[peStart] === 0x50 &&
    buffer[peStart + 1] === 0x45 &&
    buffer[peStart + 2] === 0x00 &&
    buffer[peStart + 3] === 0x00
  );
}

function findWindowsPE(buffer) {
  let offset = 0;
  while ((offset = buffer.indexOf(PE_DOS_MAGIC, offset + 1)) !== -1) {
    if (isWindowsPE(buffer, offset)) {
      return offset;
    }
  }
  return -1;
}

function detectSecondaryContainers(buffer, detectedMimeType, declaredMimeType, findings) {
  // 1. ZIP Containers
  if (!isPrimaryZipContainer(buffer, detectedMimeType, declaredMimeType)) {
    const zipOffset = buffer.indexOf(ZIP_LOCAL_SIG, 1);
    if (zipOffset !== -1) {
      findings.push({
        rule: "polyglot-secondary-container",
        severity: "extreme",
        message: "An embedded ZIP signature was found after the file start.",
        details: { detectedMimeType, containerType: "ZIP", offset: zipOffset },
      });
    } else {
      const eocdOffset = buffer.indexOf(ZIP_EOCD_SIG, 1);
      if (eocdOffset !== -1) {
        findings.push({
          rule: "polyglot-secondary-container",
          severity: "extreme",
          message: "An embedded ZIP (EOCD) signature was found after the file start.",
          details: { detectedMimeType, containerType: "ZIP", offset: eocdOffset },
        });
      }
    }
  }

  // 2. Windows PE Executable
  const peOffset = findWindowsPE(buffer);
  if (peOffset !== -1) {
    findings.push({
      rule: "polyglot-secondary-container",
      severity: "extreme",
      message: "An embedded Windows PE signature was found after the file start.",
      details: { detectedMimeType, containerType: "Windows PE", offset: peOffset },
    });
  }

  // 3. Linux / BSD ELF Executable
  const elfOffset = buffer.indexOf(ELF_SIG, 1);
  if (elfOffset !== -1) {
    findings.push({
      rule: "polyglot-secondary-container",
      severity: "extreme",
      message: "An embedded ELF signature was found after the file start.",
      details: { detectedMimeType, containerType: "ELF", offset: elfOffset },
    });
  }

  // 4. Java Class / Mach-O Fat Binary
  const javaOffset = buffer.indexOf(JAVA_MACHO_SIG, 1);
  if (javaOffset !== -1) {
    findings.push({
      rule: "polyglot-secondary-container",
      severity: "extreme",
      message: "An embedded Java Class / Mach-O signature was found after the file start.",
      details: { detectedMimeType, containerType: "Java Class / Mach-O", offset: javaOffset },
    });
  }

  // 5. 7-Zip Archive
  const is7z =
    startsWith(buffer, SEVEN_ZIP_SIG) ||
    detectedMimeType === "application/x-7z-compressed" ||
    declaredMimeType === "application/x-7z-compressed";
  if (!is7z) {
    const sevenZipOffset = buffer.indexOf(SEVEN_ZIP_SIG, 1);
    if (sevenZipOffset !== -1) {
      findings.push({
        rule: "polyglot-secondary-container",
        severity: "extreme",
        message: "An embedded 7-Zip signature was found after the file start.",
        details: { detectedMimeType, containerType: "7-Zip", offset: sevenZipOffset },
      });
    }
  }

  // 6. RAR Archive
  const isRar =
    startsWith(buffer, RAR_SIG) ||
    detectedMimeType === "application/x-rar-compressed" ||
    declaredMimeType === "application/x-rar-compressed";
  if (!isRar) {
    const rarOffset = buffer.indexOf(RAR_SIG, 1);
    if (rarOffset !== -1) {
      findings.push({
        rule: "polyglot-secondary-container",
        severity: "extreme",
        message: "An embedded RAR signature was found after the file start.",
        details: { detectedMimeType, containerType: "RAR", offset: rarOffset },
      });
    }
  }
}

function detectEmbeddedScripts(buffer, detectedMimeType, declaredMimeType, findings) {
  if (isScriptableDocument(detectedMimeType, declaredMimeType)) {
    return;
  }
  const regions =
    buffer.length <= METADATA_REGION_SIZE * 2
      ? [{ offset: 0, bytes: buffer }]
      : [
          { offset: 0, bytes: buffer.subarray(0, METADATA_REGION_SIZE) },
          { offset: buffer.length - METADATA_REGION_SIZE, bytes: buffer.subarray(-METADATA_REGION_SIZE) },
        ];
  const texts = regions.map(({ offset, bytes }) => ({ offset, text: bytes.toString("latin1") }));

  for (const wrapper of SCRIPT_WRAPPERS) {
    for (const region of texts) {
      const opening = wrapper.opening.exec(region.text);
      if (!opening) continue;
      let contentStart = opening.index + opening[0].length;
      if (wrapper.html) {
        const tagEnd = region.text.indexOf(">", contentStart);
        if (tagEnd === -1) continue;
        contentStart = tagEnd + 1;
      }

      if (!wrapper.closing.test(region.text.slice(contentStart))) continue;
      findings.push({
        rule: "polyglot-embedded-script",
        severity: "high",
        message: `An embedded ${wrapper.type} wrapper was found in the file header or trailer.`,
        details: { detectedMimeType, scriptType: wrapper.type, offset: region.offset + opening.index },
      });
      break;
    }
  }
}

function pngEndOffset(buffer) {
  let offset = PNG_SIGNATURE.length;
  while (offset + 12 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const end = offset + 12 + length;
    if (end > buffer.length || end <= offset) return undefined;
    if (buffer.toString("latin1", offset + 4, offset + 8) === "IEND") {
      return length === 0 ? end : undefined;
    }
    offset = end;
  }
  return undefined;
}

function detectTrailingPayload(buffer, detectedMimeType, findings, tolerance = TRAILING_PAYLOAD_TOLERANCE) {
  let endOffset;
  if (startsWith(buffer, PNG_SIGNATURE)) {
    endOffset = pngEndOffset(buffer);
  } else if (startsWith(buffer, JPEG_SIGNATURE)) {
    const marker = buffer.lastIndexOf(JPEG_EOI);
    if (marker !== -1) {
      endOffset = marker + JPEG_EOI.length;
    }
  } else if (startsWith(buffer, PDF_SIGNATURE)) {
    const marker = buffer.lastIndexOf(PDF_EOF);
    if (marker !== -1) {
      endOffset = marker + PDF_EOF.length;
    }
  }

  if (endOffset === undefined || buffer.length - endOffset <= tolerance) {
    return;
  }

  findings.push({
    rule: "polyglot-trailing-payload",
    severity: "medium",
    message: "Excessive data follows the file's canonical format terminator.",
    details: {
      detectedMimeType,
      endOffset,
      trailingBytes: buffer.length - endOffset,
      toleranceBytes: tolerance,
    },
  });
}

function hasExecutableJavaScriptToken(text) {
  if (!EXECUTABLE_JS_TOKEN.test(text)) return false;
  try {
    let consolePrefix = 0;
    let tokenCount = 0;
    for (const token of tokenizer(text, { ecmaVersion: "latest" })) {
      if (++tokenCount > MAX_TOKENS_TO_SCAN) break;
      const name = token.type.label === "name" ? text.slice(token.start, token.end) : undefined;
      if (token.type.label === "=>") return true;
      if (token.type.keyword && EXECUTABLE_JS_KEYWORDS.has(token.type.keyword)) return true;
      if (name !== undefined && EXECUTABLE_JS_NAMES.has(name)) return true;
      if (consolePrefix === 2 && (name === "log" || name === "warn" || name === "error")) {
        return true;
      }
      consolePrefix =
        name === "console" ? 1 : consolePrefix === 1 && token.type.label === "." ? 2 : 0;
    }
  } catch {
    // Malformed binary text is not a reason to invoke the engine's compiler.
  }
  return false;
}

function detectDualFormat(buffer, detectedMimeType, findings) {
  if (
    !detectedMimeType ||
    !(
      detectedMimeType.startsWith("image/") ||
      detectedMimeType === "application/pdf" ||
      detectedMimeType.startsWith("audio/") ||
      detectedMimeType.startsWith("video/")
    )
  ) {
    return;
  }
  const text = buffer.toString("utf8");
  if (text.trim().length < MIN_NON_WHITESPACE_LENGTH || !hasExecutableJavaScriptToken(text)) {
    return;
  }
  try {
    new Function(text);
  } catch {
    return;
  }
  findings.push({
    rule: "polyglot-dual-format",
    severity: "extreme",
    message:
      `File is detected as "${detectedMimeType}" but the same content also parses as ` +
      `syntactically valid JavaScript — a dual-format polyglot, a known technique for ` +
      `smuggling executable content past checks that only look at the declared/sniffed type.`,
    details: { detectedMimeType },
  });
}

export function createPolyglotDetectorValidator({
  maxBufferSizeToCheck = DEFAULT_MAX_BUFFER_SIZE_TO_CHECK,
  trailingToleranceBytes = TRAILING_PAYLOAD_TOLERANCE,
} = {}) {
  return {
    name: "Polyglot Detector",
    async validate(buffer, meta = {}) {
      console.log("Running polyglot detector validator...");
      const findings = [];
      if (!buffer || !Buffer.isBuffer(buffer) || buffer.length === 0) {
        return findings;
      }
      if (buffer.length > maxBufferSizeToCheck) {
        return findings;
      }
      let detectedMimeType;
      try {
        detectedMimeType = (await fileTypeFromBuffer(buffer))?.mime;
      } catch {
      }
      const declaredMimeType = meta?.declaredMimeType;

      detectSecondaryContainers(buffer, detectedMimeType, declaredMimeType, findings);
      detectEmbeddedScripts(buffer, detectedMimeType, declaredMimeType, findings);
      detectTrailingPayload(buffer, detectedMimeType, findings, trailingToleranceBytes);
      detectDualFormat(buffer, detectedMimeType, findings);
      return findings;
    },
  };
}

export const PolyglotDetectorValidator = createPolyglotDetectorValidator();

