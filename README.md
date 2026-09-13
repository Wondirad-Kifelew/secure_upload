# SecureUpload

Open-source, self-hostable file upload security pipeline.

## Structure

npm workspaces monorepo. Each phase of the project is its own package
under `packages/`, so people can work on different phases without
stepping on each other.

```
packages/
  core/          Shared contracts (Validator, Scanner, Sanitizer interfaces)
                 + the PipelineContext (findings + zip-bomb recursion guard)
                 + stage runners (ValidationPipeline today; ScanPipeline,
                 CdrPipeline etc. follow the same shape later).

  validators/    Phase 1 — file-type/content validators.
                 Currently just magic-byte.js. More get added here.

  (scanners/, cdr/, quarantine/, service/ — not built yet)
```

**Rule of thumb:** every other package depends only on `core`, never on
each other. That's what keeps this scalable — `cdr` doesn't need to know
`scanners` exists.

## Getting started

```bash
npm install       # installs everything for every workspace
npm test          # runs all tests, across all packages
npm run test:core # just the core package
npm run test:validators
```

## Adding a new validator

1. Add `packages/validators/src/your-validator.js`. It must match the
   `Validator` shape documented in
   `packages/core/src/interfaces/validator.js`:
   `{ name: string, validate(buffer, meta) -> Finding[] }`.
2. Export it from `packages/validators/src/index.js`.
3. Add `packages/validators/test/your-validator.test.js`.
4. Wire it into a `ValidationPipeline` wherever validators get assembled
   (not built yet — will live in `service/` once that exists).

Findings should never be thrown as errors. A "bad" file is a normal,
expected outcome — record it as a finding on the context, don't throw.
