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

const DEFAULT_MAX_ENTRY_BYTES = 50 * 1024 * 1024; // 50 MB
const DEFAULT_MAX_TOTAL_BYTES = 250 * 1024 * 1024; // 250 MB

const VBA_PROJECT_PATTERN = /(^|\/)vbaProject(Signature)?\.bin$/i;
const EMBEDDINGS_PATTERN = /(^|\/)embeddings\//i;
const ACTIVEX_PATTERN = /(^|\/)activeX\//i;
const RELS_PATH_PATTERN = /(^|\/)_rels\/[^/]+\.rels$/i;

// Relationship types that must be removed even when their target is external.
const DANGEROUS_EXTERNAL_RELATIONSHIP_TYPE_SUFFIXES = [
  "/attachedTemplate",
  "/oleObject",
  "/package",
];

// Relationship types whose target part is dangerous regardless of where the
// part lives in the package. The path-based checks above catch the common
// layouts, but a crafted file can place a macro/OLE/ActiveX part elsewhere
// (e.g. word/media/) and reference it by relationship type.
const DANGEROUS_INTERNAL_RELATIONSHIP_TYPE_SUFFIXES = [
  "/vbaProject",
  "/oleObject",
  "/package",
  "/control",
  "/activeXControl",
];

const RELATIONSHIP_TAG_PATTERN =
  /<(?:(?:\w+):)?Relationship\b[^>]*(?:\/>|>[\s\S]*?<\/(?:(?:\w+):)?Relationship\s*>)/gi;

function normalizeEntryPath(fileName) {
  return fileName.replace(/\\/g, "/");
}

function isRemovedPart(fileName) {
  const normalized = normalizeEntryPath(fileName);
  return (
    VBA_PROJECT_PATTERN.test(normalized) ||
    EMBEDDINGS_PATTERN.test(normalized) ||
    ACTIVEX_PATTERN.test(normalized)
  );
}

/** Read one XML attribute, accepting either single or double quotes. */
function getXmlAttribute(tag, name) {
  const pattern = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`, "i");
  const match = tag.match(pattern);
  return match ? match[1] ?? match[2] ?? null : null;
}

function decodeXmlValue(value) {
  return value
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&apos;/gi, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(Number(dec)));
}

function decodeTarget(target) {
  const decodedXml = decodeXmlValue(target);
  try {
    return decodeURIComponent(decodedXml);
  } catch {
    return decodedXml;
  }
}

function relationshipTypeMatches(type, suffixes) {
  const lowerType = type.trim().toLowerCase();
  return suffixes.some((suffix) => lowerType.endsWith(suffix.toLowerCase()));
}

/** Resolve a Relationship's Target against the folder its .rels file describes. */
function resolveRelationshipTarget(relsPath, target) {
  const normalizedRelsPath = normalizeEntryPath(relsPath);
  const normalizedTarget = normalizeEntryPath(decodeTarget(target).split("#")[0]);
  if (normalizedTarget.startsWith("/")) {
    return normalizedTarget.slice(1);
  }
  const partsDir = normalizedRelsPath.replace(/\/_rels\/[^/]+\.rels$/i, "");
  const combined = partsDir ? `${partsDir}/${normalizedTarget}` : normalizedTarget;
  const segments = [];
  for (const segment of combined.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") segments.pop();
    else segments.push(segment);
  }
  return segments.join("/");
}

function readZipEntries(buffer, { maxEntryBytes, maxTotalBytes }) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(
      buffer,
      { lazyEntries: true, decodeStrings: false, validateEntrySizes: false },
      (err, zipfile) => {
        if (err) return reject(err);

        const entries = [];
        let totalBytes = 0;
        let settled = false;

        const fail = (error) => {
          if (settled) return;
          settled = true;
          try {
            zipfile.close();
          } catch {
            // The archive may already be closed; the original error is what matters.
          }
          reject(error);
        };

        zipfile.on("error", fail);
        zipfile.on("end", () => {
          if (settled) return;
          settled = true;
          resolve(entries);
        });
        zipfile.on("entry", (entry) => {
          const fileName = entry.fileName.toString("utf8");
          if (/\/$/.test(fileName)) {
            // Directory entry — no content to read, just record it so the
            // rebuilt archive preserves empty-folder entries if present.
            entries.push({ fileName, isDirectory: true });
            zipfile.readEntry();
            return;
          }
          zipfile.openReadStream(entry, (streamErr, readStream) => {
            if (streamErr) return fail(streamErr);

            const chunks = [];
            let entryBytes = 0;
            readStream.on("data", (chunk) => {
              entryBytes += chunk.length;
              if (entryBytes > maxEntryBytes) {
                readStream.destroy();
                fail(
                  new Error(
                    `OOXML part "${fileName}" exceeds the ${maxEntryBytes}-byte extraction limit.`
                  )
                );
                return;
              }
              chunks.push(chunk);
            });
            readStream.on("end", () => {
              if (settled) return;
              totalBytes += entryBytes;
              if (totalBytes > maxTotalBytes) {
                fail(
                  new Error(
                    `OOXML package exceeds the ${maxTotalBytes}-byte total extraction limit.`
                  )
                );
                return;
              }
              entries.push({ fileName, isDirectory: false, data: Buffer.concat(chunks) });
              zipfile.readEntry();
            });
            readStream.on("error", fail);
          });
        });

        zipfile.readEntry();
      }
    );
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

/**
 * Find internal relationship targets whose relationship TYPE is dangerous.
 * These parts are removed even if they are not in an embeddings/ or activeX/
 * folder, and their relationship entries are dropped as dangling references.
 */
function collectDangerousRelationshipTargets(entries) {
  const targets = new Set();
  for (const entry of entries) {
    if (entry.isDirectory || !RELS_PATH_PATTERN.test(normalizeEntryPath(entry.fileName))) continue;
    const xmlText = entry.data.toString("utf8");
    for (const match of xmlText.matchAll(RELATIONSHIP_TAG_PATTERN)) {
      const tag = match[0];
      const type = getXmlAttribute(tag, "Type") ?? "";
      const target = getXmlAttribute(tag, "Target") ?? "";
      const targetMode = getXmlAttribute(tag, "TargetMode") ?? "Internal";
      if (targetMode.toLowerCase() === "external") continue;
      if (!relationshipTypeMatches(type, DANGEROUS_INTERNAL_RELATIONSHIP_TYPE_SUFFIXES)) continue;
      targets.add(resolveRelationshipTarget(entry.fileName, target));
    }
  }
  return targets;
}

/** Strip dangling/dangerous <Relationship> elements from one .rels file's XML text. */
function cleanRelationshipsXml(relsPath, xmlText, removedPartPaths) {
  let removedCount = 0;
  const cleaned = xmlText.replace(RELATIONSHIP_TAG_PATTERN, (tag) => {
    const type = getXmlAttribute(tag, "Type") ?? "";
    const target = getXmlAttribute(tag, "Target") ?? "";
    const targetMode = getXmlAttribute(tag, "TargetMode") ?? "Internal";
    const isExternal = targetMode.toLowerCase() === "external";

    const pointsAtRemovedPart =
      !isExternal && removedPartPaths.has(resolveRelationshipTarget(relsPath, target));

    const isDangerousInternal =
      !isExternal && relationshipTypeMatches(type, DANGEROUS_INTERNAL_RELATIONSHIP_TYPE_SUFFIXES);

    const isDangerousExternal =
      isExternal && relationshipTypeMatches(type, DANGEROUS_EXTERNAL_RELATIONSHIP_TYPE_SUFFIXES);

    if (pointsAtRemovedPart || isDangerousInternal || isDangerousExternal) {
      removedCount += 1;
      return "";
    }
    return tag;
  });
  return { cleaned, removedCount };
}

export function createOoxmlSanitizer({
  maxEntryBytes = DEFAULT_MAX_ENTRY_BYTES,
  maxTotalBytes = DEFAULT_MAX_TOTAL_BYTES,
} = {}) {
  return {
    name: "OOXML Sanitizer",

    async sanitize(buffer) {
      let entries;
      try {
        entries = await readZipEntries(buffer, { maxEntryBytes, maxTotalBytes });
      } catch (err) {
        throw new Error(`Could not read this file as an OOXML (zip) package: ${err.message}`);
      }

      const removedPartPaths = new Set(
        entries.filter((e) => !e.isDirectory && isRemovedPart(e.fileName)).map((e) => normalizeEntryPath(e.fileName))
      );

      // Parts referenced by a dangerous relationship type are just as unsafe
      // as the conventional embeddings/ and activeX/ folders.
      for (const target of collectDangerousRelationshipTargets(entries)) {
        removedPartPaths.add(target);
      }

      let macroCount = 0;
      let embeddingCount = 0;
      let activeXCount = 0;
      for (const path of removedPartPaths) {
        if (VBA_PROJECT_PATTERN.test(path)) macroCount += 1;
        else if (/^embeddings\//i.test(path)) embeddingCount += 1;
        else if (/^activeX\//i.test(path)) activeXCount += 1;
        else if (/\/oleObject|(^|\/)embeddings\//i.test(path)) embeddingCount += 1;
        else if (/\/control$|activeX/i.test(path)) activeXCount += 1;
      }

      let externalRelationshipCount = 0;
      const rebuiltEntries = [];
      for (const entry of entries) {
        if (entry.isDirectory) {
          rebuiltEntries.push(entry);
          continue;
        }
        const entryPath = normalizeEntryPath(entry.fileName);
        if (removedPartPaths.has(entryPath)) {
          continue; // dropped: macro, embedded object, or ActiveX control
        }
        if (RELS_PATH_PATTERN.test(entryPath)) {
          const xmlText = entry.data.toString("utf8");
          const { cleaned, removedCount } = cleanRelationshipsXml(entryPath, xmlText, removedPartPaths);
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