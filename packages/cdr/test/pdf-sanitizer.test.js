import { WasmDocumentBuilder, WasmPdfDocument } from "pdf-oxide-wasm";
import { createPdfSanitizer, PdfSanitizer } from "../src/pdf-sanitizer.js";

function buildPdfWithJsAction() {
  const builder = new WasmDocumentBuilder();
  builder.title("Test Document");
  builder.onOpen('app.alert("this simulates a malicious auto-run script");');
  const page = builder.a4Page();
  page.text("This is the real, legitimate visible content of the document.");
  page.done(builder);
  return Buffer.from(builder.build());
}

function buildPdfWithJsAndEmbeddedFile() {
  const pdfBytes = buildPdfWithJsAction();
  const doc = new WasmPdfDocument(pdfBytes);
  doc.embedFile("hidden-payload.txt", Buffer.from("this simulates a malicious embedded file"));
  return Buffer.from(doc.saveToBytes());
}

function buildPlainPdf() {
  const builder = new WasmDocumentBuilder();
  const page = builder.a4Page();
  page.text("Just an ordinary document.");
  page.done(builder);
  return Buffer.from(builder.build());
}

describe("PdfSanitizer", () => {
  test("has the expected Sanitizer shape", () => {
    expect(PdfSanitizer.name).toBe("PDF Sanitizer");
    expect(typeof PdfSanitizer.sanitize).toBe("function");
  });

  test("strips a real JS auto-run action", async () => {
    const original = buildPdfWithJsAction();
    expect(original.toString("latin1")).toContain("this simulates a malicious auto-run script");

    const result = await PdfSanitizer.sanitize(original);

    expect(result.buffer.toString("latin1")).not.toContain(
      "this simulates a malicious auto-run script"
    );
  });

  test("strips a real embedded file", async () => {
    const original = buildPdfWithJsAndEmbeddedFile();
    expect(original.toString("latin1")).toContain("this simulates a malicious embedded file");

    const result = await PdfSanitizer.sanitize(original);

    expect(result.buffer.toString("latin1")).not.toContain(
      "this simulates a malicious embedded file"
    );
  });

  test("preserves the real, legitimate visible text content", async () => {
    const original = buildPdfWithJsAction();
    const result = await PdfSanitizer.sanitize(original);

    const check = new WasmPdfDocument(result.buffer);
    expect(check.extractAllText()).toBe(
      "This is the real, legitimate visible content of the document."
    );
  });

  test("the sanitized output is still a valid, readable PDF", async () => {
    const original = buildPdfWithJsAndEmbeddedFile();
    const result = await PdfSanitizer.sanitize(original);

    const check = new WasmPdfDocument(result.buffer);
    expect(check.pageCount()).toBe(1);
  });

  test("a plain PDF with nothing to strip still produces a valid output", async () => {
    const original = buildPlainPdf();
    const result = await PdfSanitizer.sanitize(original);

    const check = new WasmPdfDocument(result.buffer);
    expect(check.extractAllText()).toBe("Just an ordinary document.");
  });

  test("throws a clear error for a buffer that isn't a real PDF", async () => {
    await expect(PdfSanitizer.sanitize(Buffer.from("not a pdf at all"))).rejects.toThrow(
      /Could not parse PDF/
    );
  });

  test("createPdfSanitizer can selectively disable JS removal", async () => {
    const original = buildPdfWithJsAction();
    const noJsStripSanitizer = createPdfSanitizer({ removeJavascript: false });

    const result = await noJsStripSanitizer.sanitize(original);

    expect(result.buffer.toString("latin1")).toContain(
      "this simulates a malicious auto-run script"
    );
  });

  test("embedded files are stripped regardless of the removeEmbeddedFiles flag", async () => {
    // VERIFIED QUIRK (pdf-oxide-wasm 0.3.77): unlike removeJavascript, which
    // genuinely toggles JS removal, removeEmbeddedFiles was tested across
    // all four true/false combinations and the embedded file was removed
    // in every single case. Documenting the REAL, observed behavior here
    // rather than the behavior the parameter name implies.
    const original = buildPdfWithJsAndEmbeddedFile();
    const sanitizer = createPdfSanitizer({ removeEmbeddedFiles: false });

    const result = await sanitizer.sanitize(original);

    expect(result.buffer.toString("latin1")).not.toContain(
      "this simulates a malicious embedded file"
    );
  });
});