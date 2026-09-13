/**
 * FilenameSanitizerValidator
 * ---------------------------
 * Checks the filename itself, not the file's content — this catches
 * a different family of attacks than magic-byte.js does. Covers:
 *
 *   1. Null-byte injection      — "shell.php\0.png" (classic technique
 *      used to trick naive parsers/extension checks into stopping at
 *      the null byte and treating this as a .png).
 *   2. Path traversal            — "../../etc/passwd" style filenames,
 *      which could write outside the intended upload directory if a
 *      filename is ever used to build a filesystem path directly.
 *   3. Un-normalized Unicode     — flags filenames not already in NFKC
 *      normalized form, since comparisons (like extension checks)
 *      done BEFORE normalizing can be bypassed by visually-identical
 *      characters that compare as different strings.
 *   4. Mixed-script filenames    — e.g. a filename mixing Latin and
 *      Cyrillic letters, a common homoglyph technique (a Cyrillic "а"
 *      looks identical to a Latin "a" but is a different character).
 *
 * Implements the Validator contract from core/src/interfaces/validator.js.
 * Note this one only needs `meta.filename` — it never looks at `buffer`,
 * unlike magic-byte.js. Both still take (buffer, meta) so every
 * validator has the same shape and can sit in the same pipeline.
 */

const PATH_TRAVERSAL_PATTERN = /\.\.[\\/]/;
const WINDOWS_DRIVE_PATTERN = /^[a-zA-Z]:\\/;

// Unicode characters that visually resemble a slash but aren't the real
// ASCII / or \ — a way to sneak ".." past a check that only looks for
// the literal characters. Division slash, fraction slash, fullwidth
// solidus, fullwidth reverse solidus.
const SLASH_LOOKALIKES = ["\u2215", "\u2044", "\uFF0F", "\uFF3C"];
//  try it out node -e "console.log('\u2215', '\u2044', '\uFF0F', '\uFF3C', '  vs real slash:', '/')"

/**
 * Looks for ".." + slash across three forms: the literal string, the
 * string with lookalike Unicode slashes swapped for real ones, and the
 * string percent-decoded (up to twice, to catch double-encoding like
 * "%252e%252e%252f"). Returns which method caught it, or null.
 */
function detectPathTraversal(filename) {
  if (PATH_TRAVERSAL_PATTERN.test(filename)) {
    return { method: "literal" };
  }

  let swapped = filename;
  for (const lookalike of SLASH_LOOKALIKES) {
    swapped = swapped.split(lookalike).join("/");
  }

  if (swapped !== filename && PATH_TRAVERSAL_PATTERN.test(swapped)) {
    return { method: "unicode-slash-lookalike" };
  }

  let decoded = filename;
  for (let i = 0; i < 2; i++) {
    let next;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      break; // not valid percent-encoding — stop, don't guess
    }
    if (next === decoded) break; // nothing left to decode
    decoded = next;
    if (PATH_TRAVERSAL_PATTERN.test(decoded)) {
      return { method: "percent-encoded", decodedValue: decoded };
    }
  }

  return null;
}

export const FilenameSanitizerValidator = {
  name: "Filename Sanitizer",

  /**
   * @param {Buffer} _buffer - unused by this validator
   * @param {{ filename?: string }} meta
   * @returns {Promise<import('@secureupload/core').ValidationFinding[]>}
   */
  async validate(_buffer, meta = {}) {
    console.log("Running FilenameSanitizerValidator ...")
    const findings = [];
    const { filename } = meta;

    if (!filename) {
      return findings;
    }

    if (filename.includes("\0")) {
      findings.push({
        rule: "filename-null-byte",
        severity: "extreme",
        message:
          "Filename contains a null byte — a technique used to truncate " +
          "filenames and bypass extension checks in naive parsers.",
        details: { filename },
      });
    }

    const traversal = detectPathTraversal(filename);
    
    if (traversal || filename.startsWith("/") || WINDOWS_DRIVE_PATTERN.test(filename)) {
      findings.push({
        rule: "filename-path-traversal",
        severity: "extreme",
        message:
          "Filename contains a path traversal sequence or an absolute path, " +
          "which could write outside the intended upload directory.",
        details: { filename, detectionMethod: traversal?.method ?? "absolute-path" },
      });
    }

    const normalized = filename.normalize("NFKC");
    if (normalized !== filename) {
      findings.push({
        rule: "filename-not-normalized",
        severity: "low",
        message:
          "Filename is not in normalized Unicode form (NFKC). Any comparison " +
          "against this filename (e.g. an extension check) should normalize " +
          "first, or it can be bypassed by visually-identical characters.",
        details: { filename, normalized },
      });
    }

    const scripts = detectScripts(normalized);
    if (scripts.size > 1) {
      findings.push({
        rule: "filename-mixed-script",
        severity: "medium",
        message:
          `Filename mixes multiple writing scripts (${[...scripts].join(", ")}), ` +
          `a common technique used to disguise a filename with lookalike characters.`,
        details: { filename, scripts: [...scripts] },
      });
    }

    return findings;
  }
};

/**
 * Very small script-detection heuristic — not a full Unicode confusables
 * database, just enough to catch the common case (mixing Latin with
 * Cyrillic/Greek/etc lookalike letters). Digits, punctuation, and spaces
 * are treated as script-neutral and ignored, since e.g. "invoice-2.pdf"
 * shouldn't trigger this on the hyphen or digit.
 */
function detectScripts(str) {
  const scripts = new Set();

  for (const ch of str) {
    const cp = ch.codePointAt(0);

    if (/[a-zA-Z]/.test(ch)) {
      scripts.add("Latin");
    } else if (cp >= 0x0400 && cp <= 0x04ff) {
      scripts.add("Cyrillic");
    } else if (cp >= 0x0370 && cp <= 0x03ff) {
      scripts.add("Greek");
    } else if (cp >= 0x4e00 && cp <= 0x9fff) {
      scripts.add("Han");
    } else if (cp >= 0x3040 && cp <= 0x30ff) {
      scripts.add("Japanese Kana");
    } else if (cp >= 0xac00 && cp <= 0xd7a3) {
      scripts.add("Hangul");
    }
    // digits, punctuation, whitespace, symbols: script-neutral, ignored
  }

  return scripts;
}