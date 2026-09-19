/**
 * @typedef {"low"|"medium"|"high"|"extreme"} FindingSeverity
 * @typedef {Object} ScanFinding
 * @property {string} rule
 * @property {FindingSeverity} severity
 * @property {string} message
 * @property {Object} [details]
 * @typedef {Object} FileMeta
 * @property {string} [filename]
 * @property {string} [declaredMimeType]
 * @typedef {Object} ScanResult
 * @property {boolean} clean
 * @property {ScanFinding[]} findings
 * @typedef {Object} Scanner
 * @property {string} name
 * @property {(buffer: Buffer, meta: FileMeta) => Promise<ScanResult>} scan
 */
export {};