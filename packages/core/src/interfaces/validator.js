/**
 * Contract every Phase 1 validator must follow.
 *
 * This file has no executable logic — it exists purely to document the
 * shape validators must have. Nothing enforces this at runtime yet
 * (deliberately, for this first slice); if the team wants runtime checks
 * later (e.g. "throw if a registered validator is missing `.validate`"),
 * that check belongs in core/src/pipeline.js.
 *
 * @typedef {"low"|"medium"|"high"|"extreme"} FindingSeverity
 *
 * @typedef {Object} ValidationFinding
 * @property {string} rule        - Short machine-readable id, e.g. "magic-byte-mismatch"
 * @property {FindingSeverity} severity
 * @property {string} message     - Human-readable explanation, for logs/audit trail
 * @property {Object} [details]   - Optional structured extra info (e.g. { declared, detected })
 *
 * @typedef {Object} FileMeta
 * @property {string} [filename]
 * @property {string} [declaredMimeType]  - MIME type the client claimed, if any
 *
 * @typedef {Object} Validator
 * @property {string} name
 *   Human-readable name, used in logs and the audit trail (e.g. "Magic Byte Sniffer").
 * @property {(buffer: Buffer, meta: FileMeta) => ValidationFinding[]} validate
 *   Inspects the raw file buffer and returns zero or more findings.
 *   Must not throw for "this file looks bad" — that's what findings are for.
 *   Reserve thrown errors for genuine failures (e.g. buffer is not readable).
 */

// Nothing to export yet — this file is documentation-as-code.
// Kept as a real file (not a .md) so it lives next to the code it describes
// and shows up in the same place teammates look for source.
export {};
