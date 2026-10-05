# SecureUpload

Open-source, self-hostable file upload security pipeline.

## Architecture

The repository includes independent validation, malware scanning, and content
disarm/reconstruction (CDR) packages, plus an application-facing upload
security service:

```text
validation -> quarantine -> static features -> ML anomaly detection
           -> deterministic risk scoring -> AI explanation (optional)
           -> sandbox when policy requires
```

`packages/service/` orchestrates validation, quarantine, ML risk analysis,
optional AI explanations, and conditional sandbox analysis. The existing
`check-file.js` command remains available for validation, ClamAV/YARA scanning,
and image/PDF sanitization.

## Packages

```text
packages/
  core/          Shared pipeline context, interfaces, and validation runner
  validators/    Filename, magic-byte, MIME, archive, and polyglot checks
  scanners/      ClamAV, YARA, and test scanner adapters
  cdr/           Image and PDF content sanitization
  quarantine/    Isolated storage, SHA-256 manifest, and lifecycle
  sandbox/       Sandbox policy, manager, and safe dry-run backend
  risk-engine/   Static feature extraction, Isolation Forest, and risk scoring
  ai/            Local explanations and optional OpenAI Responses API adapter
  service/       Application-facing orchestration
```

## Getting started

```bash
npm install
npm test
npm run demo:ml-ai
```

Focused test commands are available for each package, including
`npm run test:core`, `npm run test:validators`, `npm run test:scanners`,
`npm run test:cdr`, `npm run test:quarantine`, `npm run test:sandbox`,
`npm run test:risk`, `npm run test:ai`, and `npm run test:service`.

To inspect a file with the existing scanner/CDR workflow:

```bash
node check-file.js <path-to-file> <declared-mime-type>
```

## ML anomaly detection

`packages/risk-engine/` extracts a fixed numeric feature vector from safe
static evidence and runs a dependency-free Isolation Forest. A small
development bootstrap baseline is used by default so the workflow runs
immediately. For deployment, train the model on a trusted benign corpus:

```bash
npm run train:anomaly -- ./data/benign-vectors.example.json ./storage/models/anomaly-model.json
```

Set `ANOMALY_MODEL_PATH` to the trained model file to load it. An anomaly is
one evidence source; an anomalous file is not automatically malware.

## AI explanations

`packages/ai/` provides a local offline provider and an optional OpenAI
Responses API adapter. The remote provider receives structured security
evidence only; raw uploaded bytes are not sent to the AI layer.

Set `OPENAI_API_KEY` to enable remote explanations. Without a key, the local
provider is used. Set `AI_PROVIDER=disabled` to turn explanations off.
AI is advisory and cannot override deterministic validation, risk scoring,
or policy.

## Quarantine and sandbox

Every upload analyzed by `UploadSecurityService` is stored under a generated
quarantine ID before deeper analysis or release. Samples use the stored name
`sample.bin`; original filenames are metadata. The development sandbox backend
is `DryRunSandboxAdapter` and intentionally never executes uploaded content.

A production sandbox adapter should use a disposable isolated environment,
with restricted networking and cleanup/revert after each run.

Findings should never be thrown as errors. A "bad" file is a normal,
expected outcome — record it as a finding on the context, don't throw.

## Quarantine flow

Use `QuarantinePipeline` as the final upload runner. It executes the supplied
stages, evaluates all findings, and stores every upload under a generated
quarantine ID with a private sample and manifest. A stored object starts in
`quarantined` state and can then transition to `sandboxing`, `manual-review`,
`released`, or `blocked` according to the quarantine policy.
