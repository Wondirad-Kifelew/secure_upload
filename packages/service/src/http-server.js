import http from "node:http";
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
  DangerousExtensionGuardValidator,
  NestedZipInspectorValidator,
} from "@secureupload/validators";
import { createClamAVScanner, createYaraScanner, FakeScanner } from "@secureupload/scanners";

/**
 * http-server.js
 * ---------------
 * Thin HTTP wrapper around UploadSecurityService. This file does no
 * security logic of its own — it only handles the wire format (reading
 * the request body into a Buffer, pulling filename/mime-type out of
 * headers, writing the JSON response) and delegates everything else to
 * the service layer, which is fully testable without any of this.
 *
 * POST /scan
 *   Headers: X-Filename, Content-Type (the file's declared mime type)
 *   Body:    raw file bytes
 *   Returns: 200 { quarantine, risk, ml, ai, sandbox, findings }
 *
 * GET /health
 *   Returns: 200 { status: "ok" }
 *
 * No multipart/form-data parsing — deliberately. This repo has never
 * added an HTTP framework or body-parser dependency, and adding one
 * just for this route would make the service package heavier than the
 * rest of the project's "thin wrapper" design calls for. A raw-body
 * POST is enough for a single-file upload endpoint.
 */

const MAX_UPLOAD_BYTES = 50 * 1024 * 1024; // 50 MB — rejects oversized bodies before buffering them fully

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
  return http.createServer(async (req, res) => {
    try {
      if (req.method === "GET" && req.url === "/health") {
        return sendJson(res, 200, { status: "ok" });
      }

      if (req.method !== "POST" || req.url !== "/scan") {
        return sendJson(res, 404, { error: "Not found. POST a file to /scan." });
      }

      const filename = req.headers["x-filename"];
      const declaredMimeType = req.headers["content-type"] || null;

      if (!filename) {
        return sendJson(res, 400, { error: "Missing required X-Filename header." });
      }

      let buffer;
      try {
        buffer = await readBody(req);
      } catch (error) {
        return sendJson(res, error.statusCode || 400, { error: error.message });
      }

      if (buffer.length === 0) {
        return sendJson(res, 400, { error: "Empty request body — no file content received." });
      }

      const result = await service.analyze({ buffer, filename, declaredMimeType });

      return sendJson(res, 200, {
        quarantine: {
          id: result.quarantine.id,
          status: result.quarantine.status,
          sha256: result.quarantine.sha256,
        },
        findings: result.context.findings,
        risk: result.risk,
        ml: { status: result.ml.status, anomalyScore: result.ml.anomalyScore, isAnomalous: result.ml.isAnomalous },
        sandbox: { triggered: result.sandbox.triggered, status: result.sandbox.status },
        ai: result.ai ? { provider: result.ai.provider, explanation: result.ai.explanation } : null,
      });
    } catch (error) {
      console.error("[http-server] Unhandled error while processing /scan:", error);
      return sendJson(res, 500, { error: "Internal error while analyzing the upload." });
    }
  });
}

// Only start listening when this file is run directly (`node http-server.js`),
// not when it's imported by a test.
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT || 3000);
  const server = createServer();
  server.listen(port, () => {
    console.log(`[http-server] SecureUpload service listening on port ${port}`);
  });
}