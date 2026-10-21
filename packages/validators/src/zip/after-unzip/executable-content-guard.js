/**
 * NOTE FOR DEVELOPERS: this guard is strict on purpose. Do not enable it for
 * apps that accept code or software (project submissions, installers, mods,
 * plugins, scripts, web projects), or relax it first. See
 * packages/validators/src/zip/README.md.
 */

/**
 * ExecutableContentGuardValidator
 * --------------------------------
 * An "after-unzip" / entry-level validator that inspects each extracted
 * file's initial magic bytes to detect executable content disguised
 * under innocuous filenames (e.g. notes.txt or readme.txt containing
 * a Windows PE, Linux ELF, Mach-O binary, or script with a shebang).
 *
 * Scope:
 * Runs on individual extracted entries in `after-unzip`.
 */

function isWindowsPE(buffer) {
  if (buffer.length < 64) return false;
  if (buffer[0] !== 0x4d || buffer[1] !== 0x5a) return false;
  const peOffset = buffer.readUInt32LE(60);
  if (peOffset + 4 > buffer.length) return false;
  return (
    buffer[peOffset] === 0x50 &&
    buffer[peOffset + 1] === 0x45 &&
    buffer[peOffset + 2] === 0x00 &&
    buffer[peOffset + 3] === 0x00
  );
}

export function createExecutableContentGuardValidator() {
  return {
    name: "Executable Content Guard",

    /**
     * @param {Buffer} buffer
     * @param {{ filename?: string }} [meta]
     * @returns {Promise<import('@secureupload/core').ValidationFinding[]>}
     */
    async validate(buffer, meta = {}) {
      const findings = [];
      if (!buffer || buffer.length < 2) {
        return findings;
      }

      const filename = meta?.filename ?? "";
      let detectedType = null;
      let severity = "high";

      const b0 = buffer[0];
      const b1 = buffer[1];

      // Windows PE: starts with "MZ", >= 64 bytes, and uint32LE at offset 60 points
      // to "PE\0\0" (50 45 00 00) inside the buffer.
      if (isWindowsPE(buffer)) {
        detectedType = "Windows PE executable";
        severity = "high";
      }
      // Linux ELF: starts with 7F 45 4C 46
      else if (
        buffer.length >= 4 &&
        b0 === 0x7f &&
        b1 === 0x45 &&
        buffer[2] === 0x4c &&
        buffer[3] === 0x46
      ) {
        detectedType = "Linux ELF executable";
        severity = "high";
      }
      // Mach-O: starts with FE ED FA CE, FE ED FA CF, CE FA ED FE or CF FA ED FE
      else if (
        buffer.length >= 4 &&
        ((b0 === 0xfe && b1 === 0xed && buffer[2] === 0xfa && (buffer[3] === 0xce || buffer[3] === 0xcf)) ||
          ((b0 === 0xce || b0 === 0xcf) && b1 === 0xfa && buffer[2] === 0xed && buffer[3] === 0xfe))
      ) {
        detectedType = "Mach-O binary";
        severity = "high";
      }
      // Script with a shebang: starts with "#!"
      else if (b0 === 0x23 && b1 === 0x21) {
        detectedType = "script with shebang";
        severity = "medium";
      }

      if (detectedType) {
        findings.push({
          rule: "zip-executable-content",
          severity,
          message:
            `Extracted archive file "${filename}" contains ${detectedType} content; ` +
            `the content is an executable even though the filename does not say so.`,
          details: { filename, detectedType },
        });
      }

      return findings;
    },
  };
}

export const ExecutableContentGuardValidator = createExecutableContentGuardValidator();
