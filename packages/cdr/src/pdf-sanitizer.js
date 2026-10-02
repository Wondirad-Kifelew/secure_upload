import { WasmPdfDocument } from "pdf-oxide-wasm";

/**
 * PdfSanitizer
 * -------------
 * Unlike ImageSanitizer (decode-to-pixels, re-encode from scratch), a
 * PDF can't be flattened to a pixel grid without destroying the whole
 * point of it being a document — selectable text, working forms,
 * clickable links all need to survive. So this uses the OTHER real
 * CDR strategy: parse the document's actual internal structure and
 * selectively strip the dangerous object types, leaving everything
 * else untouched. Same strategy DocBleach uses for Office/PDF files.
 *
 * This is built on `pdf_oxide`'s own purpose-built method,
 * `sanitizeDocument(scrubMetadata, removeJavascript,
 * removeEmbeddedFiles)` — NOT hand-rolled parsing. Verified in the
 * sandbox before writing this file: built a real PDF with a genuine
 * auto-run JavaScript action AND a real embedded file, confirmed both
 * were present as raw bytes, ran sanitizeDocument(true, true, true),
 * confirmed BOTH were completely gone afterward — and confirmed the
 * document's real, legitimate text content survived character-for-
 * character, unlike a blunt strip-and-hope approach.
 *
 * VERIFIED QUIRK, WORTH KNOWING: unlike removeJavascript (which genuinely
 * toggles), removeEmbeddedFiles was tested across all four true/false
 * combinations in the sandbox and embedded files were stripped in
 * EVERY case, regardless of that flag's value — likely a real behavior
 * of pdf-oxide-wasm 0.3.77 itself, not something in this file. Exposed
 * here anyway (for forward-compatibility if a future library version
 * fixes it), but don't rely on setting it to false to actually
 * preserve an embedded file today — it won't.
 *
 * HONEST GAP, NOT YET RESOLVED: the project's task list also calls
 * for stripping "launch actions" specifically. sanitizeDocument()'s
 * three parameters don't include an explicit fourth flag for these,
 * and no way was found through pdf_oxide's own public API to
 * construct a real launch-action PDF to test against directly. It's
 * unknown whether removeJavascript incidentally also catches launch
 * actions, or whether this is a real remaining gap. Flagging this
 * honestly rather than claiming coverage that wasn't verified.
 *
 * Same principle as ImageSanitizer: this does NOT detect anything —
 * it unconditionally rebuilds every time, regardless of whether the
 * input looked malicious. The `findings` returned are informational
 * (what was actually stripped, per the library's own report), not a
 * verdict.
 *
 * Implements the Sanitizer contract: sanitize(buffer, meta) ->
 * { buffer, findings } — see core/src/interfaces/sanitizer.js.
 */

export function createPdfSanitizer({
  scrubMetadata = true,
  removeJavascript = true,
  removeEmbeddedFiles = true,
} = {}) {
  return {
    name: "PDF Sanitizer",

    async sanitize(buffer) {
      let doc;
      try {
        doc = new WasmPdfDocument(buffer);
      } catch (err) {
        throw new Error(`Could not parse PDF for sanitization: ${err.message}`);
      }

      const report = doc.sanitizeDocument(scrubMetadata, removeJavascript, removeEmbeddedFiles);
      const sanitizedBuffer = Buffer.from(doc.saveToBytes());

      const findings = [];
      if (report?.annotations_removed > 0) {
        findings.push({
          rule: "pdf-annotations-removed",
          severity: "medium",
          message: `${report.annotations_removed} annotation(s) were removed during sanitization (this includes active/JS-bearing annotations).`,
          details: { count: report.annotations_removed },
        });
      }
      if (report?.bytes_removed > 0) {
        findings.push({
          rule: "pdf-content-stripped",
          severity: "low",
          message: `${report.bytes_removed} byte(s) of active or embedded content were removed during sanitization.`,
          details: { bytesRemoved: report.bytes_removed },
        });
      }

      return { buffer: sanitizedBuffer, findings };
    },
  };
}

export const PdfSanitizer = createPdfSanitizer();