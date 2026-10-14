import yauzl from "yauzl";
import yazl from "yazl";

/**
 * OoxmlSanitizer
 * ---------------
 * Covers .docx/.xlsx/.pptx (Office Open XML) — the one documented CDR
 * gap this project shipped without. Legacy binary Office formats
 * (.doc/.xls/.ppt, the pre-2007 OLE2 compound-file format) are a
 * completely different file format and are NOT handled here.
 *
 * An OOXML file is a zip archive of XML parts. Like PdfSanitizer, this
 * uses the real CDR strategy — parse the actual internal structure and
 * selectively strip known-dangerous part types — rather than the
 * decode/re-encode strategy ImageSanitizer uses (there's no equivalent
 * "flatten to pixels" operation for a document that needs to keep its
 * real text, tables, and formatting intact).
 *
 * Three things get stripped:
 *
 * 1. VBA macro projects — `vbaProject.bin` parts (and their matching
 *    signature part, `vbaProjectSignature.bin`), wherever they live
 *    (word/, xl/, ppt/). This is the classic macro-malware vector.
 *
 * 2. Embedded OLE objects — anything under an `embeddings/` folder.
 *    This is the "double-click this embedded icon to run a payload"
 *    vector (embedded .exe/.scr/packager objects disguised as an
 *    innocuous-looking embedded file icon).
 *
 * 3. ActiveX controls — anything under an `activeX/` folder.
 *
 * Each of these three also has a matching entry in some `.rels`
 * relationship file (e.g. `word/_rels/document.xml.rels`) that points
 * at it. Removing the part but leaving a relationship pointing at a
 * now-missing part would leave a dangling reference, so this also
 * rewrites every `.rels` file to drop any <Relationship> whose Target
 * resolves to a part this sanitizer removed.
 *
 * A FOURTH thing gets stripped independently of part removal: external
 * relationships of specific dangerous types — `attachedTemplate`
 * (remote template injection — the "document silently fetches and
 * loads a remote .dotm template on open" technique) and external
 * `oleObject`/`package` relationships (same idea, for an embedded
 * object instead of a template: the reference is to a REMOTE resource
 * rather than an embedded part, so nothing local needs removing, but
 * the relationship itself is the attack and gets cut).
 *
 * DELIBERATELY NOT touched, and this is important: ordinary external
 * hyperlinks (Type ends in `/hyperlink`, TargetMode="External") are
 * extremely common and completely benign — a document with a link to
 * a website is normal, not an attack. Only the specific dangerous
 * relationship Types below are targeted; hyperlinks are left alone.
 *
 * VERIFIED IN THE SANDBOX before writing this: built a real .docx
 * containing a genuine vbaProject.bin, a real embedded-object part, an
 * external attachedTemplate relationship pointing at a remote URL, and
 * an ordinary external hyperlink — ran this sanitizer — confirmed all
 * three dangerous things were gone, the hyperlink relationship
 * survived untouched, and the document's actual paragraph text
 * (word/document.xml's real content) came back byte-identical.
 *
 * HONEST GAP, NOT VERIFIED: this environment has no copy of Word,
 * Excel, PowerPoint, or LibreOffice to actually open the sanitized
 * output in. What's verified is zip/XML structural correctness (the
 * output is a valid, readable OOXML package with the targeted parts
 * gone and everything else byte-identical) — NOT that Word itself is
 * guaranteed to open the result without complaint. [Content_Types].xml
 * is also left untouched even when it still declares a content type
 * for a part that no longer exists (e.g. the macro-enabled content
 * type after vbaProject.bin is stripped) — this is a known, deliberate
 * scope limit, not an oversight: rewriting that file correctly needs
 * real understanding of its Override/Default election rules, and doing
 * it wrong risks a worse outcome (a package Word refuses to open at
 * all) than leaving one stale declaration in place.
 *
 * Implements the Sanitizer contract: sanitize(buffer, meta) ->
 * { buffer, findings } — see core/src/interfaces/sanitizer.js.
 */

const VBA_PROJECT_PATTERN = /(^|\/)vbaProject(Signature)?\.bin$/i;
const EMBEDDINGS_PATTERN = /(^|\/)embeddings\//i;
const ACTIVEX_PATTERN = /(^|\/)activeX\//i;
const RELS_PATH_PATTERN = /(^|\/)_rels\/[^/]+\.rels$/i;

const DANGEROUS_EXTERNAL_RELATIONSHIP_TYPE_SUFFIXES = [
  "/attachedTemplate",
  "/oleObject",
  "/package",
];

function isRemovedPart(fileName) {
  return (
    VBA_PROJECT_PATTERN.test(fileName) ||
    EMBEDDINGS_PATTERN.test(fileName) ||
    ACTIVEX_PATTERN.test(fileName)
  );
}

/** Resolve a Relationship's Target against the folder its .rels file describes. */
function resolveRelationshipTarget(relsPath, target) {
  if (target.startsWith("/")) {
    return target.slice(1);
  }
  const partsDir = relsPath.replace(/\/_rels\/[^/]+\.rels$/i, "");
  const combined = partsDir ? `${partsDir}/${target}` : target;
  const segments = [];
  for (const segment of combined.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") segments.pop();
    else segments.push(segment);
  }
  return segments.join("/");
}

function readZipEntries(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
      if (err) return reject(err);
      const entries = [];
      zipfile.readEntry();
      zipfile.on("entry", (entry) => {
        if (/\/$/.test(entry.fileName)) {
          // Directory entry — no content to read, just record it so the
          // rebuilt archive preserves empty-folder entries if present.
          entries.push({ fileName: entry.fileName, isDirectory: true });
          zipfile.readEntry();
          return;
        }
        zipfile.openReadStream(entry, (streamErr, readStream) => {
          if (streamErr) return reject(streamErr);
          const chunks = [];
          readStream.on("data", (chunk) => chunks.push(chunk));
          readStream.on("end", () => {
            entries.push({ fileName: entry.fileName, isDirectory: false, data: Buffer.concat(chunks) });
            zipfile.readEntry();
          });
          readStream.on("error", (e) => reject(e));
        });
      });
      zipfile.on("end", () => resolve(entries));
      zipfile.on("error", (e) => reject(e));
    });
  });
}

function buildZip(entries) {
  return new Promise((resolve, reject) => {
    const zipfile = new yazl.ZipFile();
    for (const entry of entries) {
      if (entry.isDirectory) {
        zipfile.addEmptyDirectory(entry.fileName);
      } else {
        zipfile.addBuffer(entry.data, entry.fileName);
      }
    }
    const chunks = [];
    zipfile.outputStream.on("data", (chunk) => chunks.push(chunk));
    zipfile.outputStream.on("end", () => resolve(Buffer.concat(chunks)));
    zipfile.outputStream.on("error", (e) => reject(e));
    zipfile.end();
  });
}

/** Strip dangling/dangerous <Relationship> elements from one .rels file's XML text. */
function cleanRelationshipsXml(relsPath, xmlText, removedPartPaths) {
  let removedCount = 0;
  const cleaned = xmlText.replace(/<Relationship\b[^>]*\/>/g, (tag) => {
    const typeMatch = tag.match(/\bType="([^"]*)"/);
    const targetMatch = tag.match(/\bTarget="([^"]*)"/);
    const targetModeMatch = tag.match(/\bTargetMode="([^"]*)"/);
    const type = typeMatch?.[1] ?? "";
    const target = targetMatch?.[1] ?? "";
    const targetMode = targetModeMatch?.[1] ?? "Internal";

    const pointsAtRemovedPart =
      targetMode !== "External" &&
      removedPartPaths.has(resolveRelationshipTarget(relsPath, target));

    const isDangerousExternal =
      targetMode === "External" &&
      DANGEROUS_EXTERNAL_RELATIONSHIP_TYPE_SUFFIXES.some((suffix) => type.endsWith(suffix));

    if (pointsAtRemovedPart || isDangerousExternal) {
      removedCount += 1;
      return "";
    }
    return tag;
  });
  return { cleaned, removedCount };
}

export function createOoxmlSanitizer() {
  return {
    name: "OOXML Sanitizer",

    async sanitize(buffer) {
      let entries;
      try {
        entries = await readZipEntries(buffer);
      } catch (err) {
        throw new Error(`Could not read this file as an OOXML (zip) package: ${err.message}`);
      }

      const removedPartPaths = new Set(
        entries.filter((e) => !e.isDirectory && isRemovedPart(e.fileName)).map((e) => e.fileName)
      );

      let macroCount = 0;
      let embeddingCount = 0;
      let activeXCount = 0;
      for (const path of removedPartPaths) {
        if (VBA_PROJECT_PATTERN.test(path)) macroCount += 1;
        else if (EMBEDDINGS_PATTERN.test(path)) embeddingCount += 1;
        else if (ACTIVEX_PATTERN.test(path)) activeXCount += 1;
      }

      let externalRelationshipCount = 0;
      const rebuiltEntries = [];
      for (const entry of entries) {
        if (entry.isDirectory) {
          rebuiltEntries.push(entry);
          continue;
        }
        if (removedPartPaths.has(entry.fileName)) {
          continue; // dropped: macro, embedded object, or ActiveX control
        }
        if (RELS_PATH_PATTERN.test(entry.fileName)) {
          const xmlText = entry.data.toString("utf8");
          const { cleaned, removedCount } = cleanRelationshipsXml(entry.fileName, xmlText, removedPartPaths);
          externalRelationshipCount += removedCount;
          rebuiltEntries.push({ ...entry, data: Buffer.from(cleaned, "utf8") });
          continue;
        }
        rebuiltEntries.push(entry);
      }

      let sanitizedBuffer;
      try {
        sanitizedBuffer = await buildZip(rebuiltEntries);
      } catch (err) {
        throw new Error(`Could not rebuild sanitized OOXML package: ${err.message}`);
      }

      const findings = [];
      if (macroCount > 0) {
        findings.push({
          rule: "ooxml-macro-removed",
          severity: "high",
          message: `${macroCount} VBA macro project part(s) were removed during sanitization.`,
          details: { count: macroCount },
        });
      }
      if (embeddingCount > 0) {
        findings.push({
          rule: "ooxml-embedded-object-removed",
          severity: "medium",
          message: `${embeddingCount} embedded OLE object part(s) were removed during sanitization.`,
          details: { count: embeddingCount },
        });
      }
      if (activeXCount > 0) {
        findings.push({
          rule: "ooxml-activex-removed",
          severity: "medium",
          message: `${activeXCount} ActiveX control part(s) were removed during sanitization.`,
          details: { count: activeXCount },
        });
      }
      if (externalRelationshipCount > 0) {
        findings.push({
          rule: "ooxml-external-relationship-removed",
          severity: "high",
          message: `${externalRelationshipCount} dangerous external relationship(s) were removed (remote template injection or external OLE/package references). Ordinary external hyperlinks are left untouched.`,
          details: { count: externalRelationshipCount },
        });
      }

      return { buffer: sanitizedBuffer, findings };
    },
  };
}

export const OoxmlSanitizer = createOoxmlSanitizer();