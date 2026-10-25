# SecureUpload

## Group Members

| Name | Student ID |
|---|---|
| Wondirad Abebe | CTC-3999-26 |
| Bisrat Mengesha | CTC-581-26 |
| Robel Bayelign | CTC-1448-26 |
| Daniel Tumay | CTC-132-26 |
| Yitbarek Mengistu | CTC-662-26 |
| Betselot Melaku | CTC-3772-26 |

## Video Walkthrough

[Watch the project walkthrough](docs/secure_upload_walkthrough.mp4)

An open-source, self-hostable pipeline that checks untrusted file uploads **before** they reach your app.
Send a file over HTTP; get back a verdict and, when it is safe, a **cleaned copy** of the file.
Works from any language — it is just a `POST` request.

```
your app ──POST /clean──▶ SecureUpload ──▶ validate → scan (ClamAV/YARA) → clean (CDR) → quarantine → risk
         ◀── cleaned file (200)  or  verdict + reasons (422)
```

## What it does

| Step | What happens |
|---|---|
| **Validate** | Detects the real file type from the bytes (not the name or declared type). Catches spoofed types, polyglots, dangerous extensions, tricky filenames (null bytes, Unicode tricks, device names) and ZIP attacks (zip bombs, zip slip, symlinks, nested/encrypted archives). |
| **Scan** | ClamAV (antivirus) and optional YARA rules. |
| **Clean (CDR)** | Rebuilds the file without active content: images (metadata stripped, re-encoded), PDFs, and Office files (`.docx/.xlsx/.pptx` — macros, embedded objects, ActiveX and dangerous external links removed). |
| **Quarantine** | Every upload is stored under an ID with a SHA-256 manifest and an audit trail. |
| **Risk** | Deterministic risk score plus an advisory anomaly model and optional AI explanation. |

Every request ends in one **verdict**: `allow`, `review` (a person should look first) or `block`.

## Quick start (Docker)

You need Docker. This starts the service and the ClamAV antivirus together.

```bash
git clone https://github.com/Wondirad-Kifelew/secure_upload
cd secure_upload
echo "API_KEY=$(openssl rand -hex 16)" > .env     # your secret key
docker compose up --build
```

The first start can take a few minutes while ClamAV downloads its virus definitions.
The service then listens on `http://localhost:3000`.

Check it is up: `curl localhost:3000/health` → `{"status":"ok"}`

## Using it

### `POST /clean` — send a file, get the cleaned file back

```bash
curl -X POST http://localhost:3000/clean \
  -H "Authorization: Bearer $API_KEY" \
  -H "X-Filename: photo.jpg" \
  --data-binary @photo.jpg \
  -o cleaned.jpg
```

- **`200`** — approved. The body is the cleaned file (headers `X-Verdict: allow`, `X-Quarantine-Id`).
- **`422`** — not approved. The body is JSON: `{ "verdict": "block" | "review", "findings": [...] }`.
  **Do not accept the upload.**

### `POST /scan` — same request, but you get a JSON report

Useful for logging or showing the user why a file was rejected.

```json
{
  "verdict": "allow",
  "cleaned": true,
  "downloadUrl": "/files/<id>",
  "findings": [],
  "risk": { "...": "..." },
  "quarantine": { "id": "...", "status": "quarantined", "sha256": "..." }
}
```

### `GET /files/:id` — download an approved file

Returns the cleaned file of an earlier scan (`403` unless its verdict was `allow`).

### Request details

| Header | Required | Notes |
|---|---|---|
| `Authorization: Bearer <API_KEY>` | yes | Every endpoint except `/health`. |
| `X-Filename` | yes | The original file name. |
| `Content-Type` | no | The file's MIME type. If missing (or generic, like `application/octet-stream`), it is detected from the bytes. If you send it and it does not match the bytes, the file is blocked. |

Body: the raw file bytes (no multipart). Default size limit: 10 MB.

Status codes: `200` ok · `400` bad request · `401` bad/missing key · `404` unknown route/file · `413` too large · `422` rejected · `503` busy or unavailable · `500` internal error.

### From your app

**Node.js**
```js
const res = await fetch("http://localhost:3000/clean", {
  method: "POST",
  headers: {
    Authorization: `Bearer ${process.env.SECUREUPLOAD_API_KEY}`,
    "X-Filename": file.originalname,
    "Content-Type": file.mimetype,
  },
  body: file.buffer,
});
if (res.status === 200) save(Buffer.from(await res.arrayBuffer())); // save the CLEANED file
else reject(await res.json());                                      // verdict + findings
```

**Python**
```python
r = requests.post(
    "http://localhost:3000/clean",
    headers={"Authorization": f"Bearer {API_KEY}", "X-Filename": name, "Content-Type": mime},
    data=file_bytes,
)
if r.status_code == 200:
    save(r.content)          # the CLEANED file
else:
    reject(r.json())         # verdict + findings
```

**Always:** store the *cleaned* file, not the original upload, and **reject the upload if the service
is unreachable or returns anything other than `200`** (fail closed).

## Configuration

Environment variables (set them in `docker-compose.yml` or your shell):

| Variable | Default | Purpose |
|---|---|---|
| `API_KEY` | — | **Required.** Callers must send `Authorization: Bearer <API_KEY>`. |
| `CLAMD_HOST`, `CLAMD_PORT` | set by compose | Where ClamAV (`clamd`) is. Or use `CLAMD_SOCKET_PATH`. |
| `PORT` | `3000` | Port the service listens on. |
| `MAX_UPLOAD_MB` | `10` | Largest accepted upload. |
| `MAX_CONCURRENT_SCANS` | `4` | More simultaneous requests get `503`. |
| `QUARANTINE_ROOT` | `./quarantine-data` | Where uploads and manifests are stored (mounted as a volume in compose). |
| `YARA_RULES_PATH` | — | Path to a YARA rules file to enable YARA scanning. |
| `SANDBOX_THRESHOLD` | `60` | Risk score above which the sandbox step triggers. |
| `OPENAI_API_KEY` / `OPENAI_MODEL` / `AI_PROVIDER` | — | Optional AI explanations (`AI_PROVIDER=disabled` turns them off). |
| `ANOMALY_MODEL_PATH` | — | Trained anomaly model (see below). |
| `DEV_MODE` | — | `true` lets the service run **without** `API_KEY`/ClamAV. Local demos only. |

Without `DEV_MODE=true`, the service refuses to start unless `API_KEY` and ClamAV are configured.

## Run without Docker (development)

Requires Node.js 22+.

```bash
npm install
DEV_MODE=true API_KEY=test PORT=3001 node packages/service/src/http-server.js
```

In `DEV_MODE` with no ClamAV configured, a fake scanner is used and **no antivirus scanning happens**.
Run tests with `npm test` (use `npm test -- --runInBand` on slow machines).

## Project layout

```text
packages/
  core/          Shared pipeline context, interfaces, and validation runner
  validators/    Filename, magic-byte, MIME, archive, and polyglot checks
  scanners/      ClamAV, YARA, and test scanner adapters
  cdr/           Image, PDF and Office (OOXML) content sanitization
  quarantine/    Isolated storage, SHA-256 manifest, and lifecycle
  sandbox/       Sandbox policy, manager, and safe dry-run backend
  risk-engine/   Static feature extraction, Isolation Forest, and risk scoring
  ai/            Local explanations and optional OpenAI adapter
  service/       Orchestration + the HTTP server (http-server.js)
attack-suite/    Malicious / edge-case samples run against the full pipeline in CI
```

`node check-file.js <file> <mime-type>` runs one file through the pipeline from the command line
(it expects a local clamd socket; see the script header).

## Anomaly model and AI explanations (optional)

`packages/risk-engine` runs a dependency-free Isolation Forest. A small bootstrap baseline is used by
default; for deployment, train it on a trusted benign corpus:

```bash
npm run train:anomaly -- ./data/benign-vectors.example.json ./storage/models/anomaly-model.json
```

then set `ANOMALY_MODEL_PATH`. An anomaly is one piece of evidence — not proof of malware.
AI explanations receive structured findings only, never the file bytes, and are advisory: they cannot
override validation, risk scoring or the verdict.

## Limitations — read before production use

- **The sandbox is simulated.** `DryRunSandboxAdapter` never executes uploaded content. Behavioural
  detonation is not implemented.
- **No TLS.** Run the service on a private network or behind a reverse proxy that terminates HTTPS.
- **Antivirus needs ClamAV.** Without it (DEV_MODE) nothing is scanned for malware.
- **CDR coverage:** images, PDFs and OOXML only. Legacy `.doc/.xls/.ppt`, archives and other types are
  validated and scanned but not rebuilt.
- **A missing/generic `Content-Type` is detected from the bytes;** types with no signature (plain text,
  CSV…) cannot be identified that way.
- **Quarantine is never cleaned up automatically.** Plan disk usage and retention.
- A single API key is the only access control. Keep it secret and rotate it if leaked.

## Contributing & license

Add a validator, scanner or sanitizer by implementing the contracts in `packages/core/src/interfaces/`.
A "bad" file is a normal outcome: record it as a **finding**, don't throw. Add a sample to
`attack-suite/samples/` for every new bypass you defend against.

MIT — see [LICENSE](LICENSE).
