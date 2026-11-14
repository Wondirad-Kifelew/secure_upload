export class ScanPipeline {
  constructor(scanners = []) {
    this.scanners = scanners;
  }

  async run(buffer, context) {
    for (const scanner of this.scanners) {
      const meta = { filename: context.filename, declaredMimeType: context.declaredMimeType };

      let result;
      try {
        result = await scanner.scan(buffer, meta);
      } catch (error) {
        // One scanner being unavailable must not stop the remaining scanners.
        // Losing YARA findings because ClamAV is down would be a security hole.
        context.addFinding({
          rule: "scanner-failed",
          severity: "medium",
          message:
            `A scanner failed to run: ${error.message}. ` +
            `The file was not fully scanned, so it cannot be released as clean.`,
          stage: "scanning",
          source: scanner.name,
          details: { reason: error.message, scanner: scanner.name },
        });
        continue;
      }

      if (result.findings && result.findings.length > 0) {
        for (const finding of result.findings) {
          context.addFinding({ ...finding, stage: "scanning", source: scanner.name });
        }
      } else if (!result.clean) {
        context.addFinding({
          rule: "scanner-reported-unclean",
          severity: "high",
          message: `${scanner.name} reported this file as not clean, but provided no specific findings.`,
          stage: "scanning",
          source: scanner.name,
        });
      }
    }
 
    return context;
  }
}