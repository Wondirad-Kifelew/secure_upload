import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import { fileTypeFromBuffer } from "file-type";
import { UploadSecurityService } from "./upload-service.js";
import { QuarantineStore } from "@secureupload/quarantine";
import { SandboxManager, DryRunSandboxAdapter } from "@secureupload/sandbox";
import {
  MagicByteValidator,
  FilenameSanitizerValidator,
  MimeMismatchValidator,
  PolyglotDetectorValidator,
  ZipBombGuardValidator,
  ZipSlipGuardValidator,
  EntryCountGuardValidator,
  DuplicateEntryGuardValidator,
  NestedArchiveGuardValidator,
  SymlinkEntryGuardValidator,
  EncryptedEntryGuardValidator,
  NonRecursiveBombGuardValidator,
  DeviceNameGuardValidator,
  UnicodeControlGuardValidator,
  TrailingCharacterGuardValidator,
  ArchiveIntegrityGuardValidator,
  DangerousExtensionGuardValidator,
  NestedZipInspectorValidator,
} from "@secureupload/validators";
import { createClamAVScanner, createYaraScanner, FakeScanner } from "@secureupload/scanners";

/**
 * http-server.js
 * ---------------
 * Thin HTTP wrapper around UploadSecurityService (wire format only).
 *
 * POST /clean   Body: raw file bytes. Headers: Authorization, X-Filename,
 *               Content-Type (optional - detected from the bytes if missing).
 *               200 + cleaned file bytes  when the verdict is "allow"
 *               422 + { verdict, findings } otherwise
 * POST /scan    Same request; always returns JSON (verdict, findings, risk...)
 * GET /files/:id  Download the cleaned file of an approved scan
 * GET /health   { status: "ok" } (no auth)
 *
 * No multipart parsing on purpose: a raw-body POST is enough for one file.
 */

const MAX_UPLOAD_BYTES = Number(process.env.MAX_UPLOAD_MB || 10) * 1024 * 1024; // rejects oversized bodies before buffering them fully
const MAX_CONCURRENT_SCANS = Number(process.env.MAX_CONCURRENT_SCANS || 4);
let activeScans = 0;

/**
 * allow  -> safe to use (the cleaned file can be downloaded)
 * review -> a person should look at it first
 * block  -> reject
 * Findings from a CDR step that SUCCEEDED describe what was removed from the
 * file, so the cleaned output is fine; only a failed sanitization counts.
 */
function decideVerdict(findings) {
  const relevant = findings.filter((f) => f.stage !== "cdr" || f.rule === "cdr-sanitization-failed");
  const severities = new Set(relevant.map((f) => f.severity));
  if (severities.has("extreme") || severities.has("high")) return "block";
  if (severities.has("medium")) return "review";
  return "allow";
}

// Types that tell us nothing about the real file (curl and many HTTP clients
// send these by default). For them we detect the type from the bytes instead.
const GENERIC_TYPES = new Set(["application/octet-stream", "application/x-www-form-urlencoded", "binary/octet-stream"]);

const MIME_ALIASES = new Map([
  ["application/x-zip-compressed", "application/zip"],
  ["application/x-zip", "application/zip"],
  ["multipart/x-zip", "application/zip"],
]);
async function resolveDeclaredType(header, buffer) {
  const declared = header ? header.split(";")[0].trim().toLowerCase() : "";
  if (declared && !GENERIC_TYPES.has(declared)) return MIME_ALIASES.get(declared) ?? declared;
  const detected = await fileTypeFromBuffer(buffer);
  return detected?.mime ?? null;
}

function isAuthorized(req) {
  const apiKey = process.env.API_KEY;
  if (!apiKey) return true; // only reachable in DEV_MODE (startup refuses otherwise)
  const given = Buffer.from(String(req.headers.authorization ?? ""));
  const expected = Buffer.from(`Bearer ${apiKey}`);
  return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;

    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > MAX_UPLOAD_BYTES) {
        reject(Object.assign(new Error("Upload exceeds maximum allowed size."), { statusCode: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function sendJson(res, statusCode, body) {
  const payload = JSON.stringify(body);
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

/**
 * Builds the default UploadSecurityService wired for this process.
 * Scanners default to ClamAV + YARA when their connection details are
 * present in the environment (the Docker Compose setup provides them);
 * otherwise falls back to FakeScanner so the server still runs for
 * local development without a real clamd/YARA install.
 */
export function createDefaultService() {
  const scanners = [];

  if (process.env.CLAMD_HOST && process.env.CLAMD_PORT) {
    scanners.push(
      createClamAVScanner({ host: process.env.CLAMD_HOST, port: Number(process.env.CLAMD_PORT) })
    );
  } else if (process.env.CLAMD_SOCKET_PATH) {
    scanners.push(createClamAVScanner({ socketPath: process.env.CLAMD_SOCKET_PATH }));
  } else {
    scanners.push(createFakeScannerFallback());
  }

  if (process.env.YARA_RULES_PATH) {
    scanners.push(createYaraScanner({ rulesPath: process.env.YARA_RULES_PATH }));
  }

  return new UploadSecurityService({
    validators: [
      MagicByteValidator,
      FilenameSanitizerValidator,
      MimeMismatchValidator,
      PolyglotDetectorValidator,
      ZipBombGuardValidator,
      ZipSlipGuardValidator,
      EntryCountGuardValidator,
      DuplicateEntryGuardValidator,
      NestedArchiveGuardValidator,
      SymlinkEntryGuardValidator,
      EncryptedEntryGuardValidator,
      NonRecursiveBombGuardValidator,
      DeviceNameGuardValidator,
      UnicodeControlGuardValidator,
      TrailingCharacterGuardValidator,
      ArchiveIntegrityGuardValidator,
      DangerousExtensionGuardValidator,
      NestedZipInspectorValidator,
    ],
    scanners,
    quarantineStore: new QuarantineStore({
      rootDirectory: process.env.QUARANTINE_ROOT || "./quarantine-data",
    }),
    sandboxManager: new SandboxManager({
      adapter: new DryRunSandboxAdapter(), // no real sandbox backend exists yet — see packages/sandbox
      threshold: Number(process.env.SANDBOX_THRESHOLD || 60),
    }),
  });
}

function createFakeScannerFallback() {
  // No clamd configured — don't silently skip scanning, and don't crash
  // either. Logs loudly once at startup; FakeScanner always reports clean,
  // which is correct for local dev but must never be what a real
  // deployment relies on.
  console.warn(
    "[http-server] No CLAMD_HOST/CLAMD_PORT or CLAMD_SOCKET_PATH set — falling back to " +
      "FakeScanner. This process is NOT actually scanning uploads for malware. " +
      "Set clamd connection details before deploying."
  );
  return FakeScanner;
}

export function createServer(service = createDefaultService()) {
  const server = http.createServer(async (req, res) => {
    try {
      if (req.method === "GET" && req.url === "/health") {
        return sendJson(res, 200, { status: "ok" });
      }

      if (!isAuthorized(req)) {
        return sendJson(res, 401, { error: "Missing or invalid API key." });
      }

      // GET /files/:id — download the cleaned file, only if it was approved.
      const fileMatch = req.method === "GET" && req.url.match(/^\/files\/([0-9a-fA-F-]{36})$/);
      if (fileMatch) {
        let record;
        try {
          record = await service.quarantineStore.get(fileMatch[1]);
        } catch {
          return sendJson(res, 404, { error: "File not found." });
        }
        if (record.verdict !== "allow") {
          return sendJson(res, 403, { error: "File was not approved, so it cannot be downloaded." });
        }
        const bytes = await fs.readFile(record.samplePath);
        res.writeHead(200, {
          "Content-Type": "application/octet-stream",
          "Content-Length": bytes.length,
          "Content-Disposition": `attachment; filename="cleaned-${record.id}"`,
          "X-Content-Type-Options": "nosniff",
        });
        return res.end(bytes);
      }

      if (req.method !== "POST" || (req.url !== "/scan" && req.url !== "/clean")) {
        return sendJson(res, 404, { error: "Not found. POST a file to /scan or /clean." });
      }

      const filename = req.headers["x-filename"];
      const typeHeader = req.headers["content-type"] || null;

      if (!filename) {
        return sendJson(res, 400, { error: "Missing required X-Filename header." });
      }

      if (activeScans >= MAX_CONCURRENT_SCANS) {
        return sendJson(res, 503, { error: "Server busy, retry shortly." });
      }
      activeScans += 1;
      try {
        let buffer;
        try {
          buffer = await readBody(req);
        } catch (error) {
          return sendJson(res, error.statusCode || 400, { error: error.message });
        }

        if (buffer.length === 0) {
          return sendJson(res, 400, { error: "Empty request body — no file content received." });
        }

        const declaredMimeType = await resolveDeclaredType(typeHeader, buffer);
        const result = await service.analyze({ buffer, filename, declaredMimeType });
        const findings = result.context.findings;
        const verdict = decideVerdict(findings);
        await service.quarantineStore.annotate(result.quarantine.id, { verdict });

        // POST /clean: one request in, the cleaned file out.
        if (req.url === "/clean") {
          if (verdict !== "allow") {
            return sendJson(res, 422, { verdict, findings });
          }
          const bytes = await fs.readFile(result.quarantine.samplePath);
          res.writeHead(200, {
            "Content-Type": "application/octet-stream",
            "Content-Length": bytes.length,
            "X-Verdict": verdict,
            "X-Quarantine-Id": result.quarantine.id,
            "X-Content-Type-Options": "nosniff",
          });
          return res.end(bytes);
        }

        return sendJson(res, 200, {
          verdict,
          cleaned:
            Boolean(service.resolveSanitizer(declaredMimeType)) &&
            !findings.some((f) => f.rule === "cdr-sanitization-failed"),
          downloadUrl: verdict === "allow" ? `/files/${result.quarantine.id}` : null,
          scanners: service.scanPipeline.scanners.map((s) => s.name),
          quarantine: {
            id: result.quarantine.id,
            status: result.quarantine.status,
            sha256: result.quarantine.sha256,
          },
          findings,
          risk: result.risk,
          ml: { status: result.ml.status, anomalyScore: result.ml.anomalyScore, isAnomalous: result.ml.isAnomalous },
          sandbox: { triggered: result.sandbox.triggered, status: result.sandbox.status },
          ai: result.ai ? { provider: result.ai.provider, explanation: result.ai.explanation } : null,
        });
      } finally {
        activeScans -= 1;
      }
    } catch (error) {
      console.error("[http-server] Unhandled error while processing request:", error);
      return sendJson(res, 500, { error: "Internal error while analyzing the upload." });
    }
  });
  server.requestTimeout = 60_000;
  return server;
}

// Only start listening when this file is run directly (`node http-server.js`),
// not when it's imported by a test.
if (import.meta.url === `file://${process.argv[1]}`) {
  const devMode = process.env.DEV_MODE === "true";
  const hasClamd = Boolean(
    (process.env.CLAMD_HOST && process.env.CLAMD_PORT) || process.env.CLAMD_SOCKET_PATH
  );
  if (!devMode && (!process.env.API_KEY || !hasClamd)) {
    console.error(
      "[http-server] Refusing to start. Production mode needs API_KEY and a clamd connection " +
        "(CLAMD_HOST + CLAMD_PORT, or CLAMD_SOCKET_PATH). For local demos only, set DEV_MODE=true."
    );
    process.exit(1);
  }
  const port = Number(process.env.PORT || 3000);
  const server = createServer();
  server.listen(port, () => {
    console.log(`[http-server] SecureUpload service listening on port ${port}${devMode ? " (DEV_MODE)" : ""}`);
  });
}