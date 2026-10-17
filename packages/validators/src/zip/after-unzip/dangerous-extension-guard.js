import path from "node:path";

/**
 * DangerousExtensionGuardValidator
 * ---------------------------------
 * An "after-unzip" / entry-level validator that inspects each extracted
 * file's extension to catch dangerous executable or script formats
 * smuggled inside an archive (e.g. .exe, .bat, .cmd, .ps1, .sh, .vbs, .js, .hta, .dll).
 *
 * Scope:
 * Runs on individual extracted entries in `after-unzip`.
 */

const DEFAULT_BLOCKED_EXTENSIONS = new Set([
  // Windows executables & binaries
  ".exe", ".dll", ".scr", ".sys", ".drv", ".cpl", ".ocx",
  // Scripts & batch files
  ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
  // Shell scripts & Unix binaries
  ".sh", ".bash", ".bin", ".elf",
  // Installers & packages
  ".msi", ".msp", ".hta", ".jar",
]);

export function createDangerousExtensionGuardValidator(options = {}) {
  const blocked = options.blockedExtensions
    ? new Set([...options.blockedExtensions].map((ext) => (ext.startsWith(".") ? ext.toLowerCase() : `.${ext.toLowerCase()}`)))
    : DEFAULT_BLOCKED_EXTENSIONS;

  return {
    name: "Dangerous Extension Guard",

    /**
     * @param {Buffer} buffer
     * @param {{ filename?: string }} [meta]
     * @returns {Promise<import('@secureupload/core').ValidationFinding[]>}
     */
    async validate(buffer, meta = {}) {
      const findings = [];
      const filename = meta.filename || "";
      if (!filename) return findings;

      const ext = path.extname(filename).toLowerCase();
      if (blocked.has(ext)) {
        findings.push({
          rule: "zip-extracted-dangerous-extension",
          severity: "high",
          message:
            `Extracted archive file "${filename}" has a dangerous executable or script extension ` +
            `("${ext}"). Allowing executable files inside user archives poses a high code-execution risk.`,
          details: { filename, extension: ext },
        });
      }

      return findings;
    },
  };
}

export const DangerousExtensionGuardValidator = createDangerousExtensionGuardValidator();
