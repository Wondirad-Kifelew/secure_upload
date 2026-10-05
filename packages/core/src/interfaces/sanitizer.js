/**
 * Contract every Phase 3 sanitizer (CDR) must follow.
 *
 * IMPORTANT DIFFERENCE FROM Validator AND Scanner: a Sanitizer doesn't
 * just report — it PRODUCES a new artifact. sanitize() returns the
 * rebuilt buffer alongside findings, because CDR's whole point is
 * "here is a clean version of your file," not just "here's what's
 * wrong with it."
 *
 *   sanitize(buffer, meta) -> { buffer: Buffer, findings: Finding[] }
 *
 * The findings a Sanitizer returns are informational (what got
 * stripped/rebuilt), not a verdict — a Sanitizer has no concept of
 * "clean vs infected" the way a Scanner does. It unconditionally
 * rebuilds every time, regardless of whether the input was malicious.
 */
export {};