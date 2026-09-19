export class ScanPipeline {
  constructor(scanners = []) {
    this.scanners = scanners;
  }

  async run(buffer, context) {
    for (const scanner of this.scanners) {
      const meta = { filename: context.filename, declaredMimeType: context.declaredMimeType };
      const result = await scanner.scan(buffer, meta);

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