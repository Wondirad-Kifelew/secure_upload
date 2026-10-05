/**
 * Sandbox adapter contract.
 *
 * The security pipeline deliberately does not execute an uploaded sample by
 * itself. A real adapter is responsible for talking to an isolated VM,
 * disposable container, or external sandbox service.
 *
 * analyze({ samplePath, timeoutMs, metadata }) must return normalized behavior
 * observations and must guarantee that the sample is not run on the host.
 */
export class SandboxAdapter {
  async analyze(_input) {
    throw new Error("SandboxAdapter.analyze() must be implemented by a safe sandbox backend.");
  }
}

/**
 * Safe local implementation for unit tests and development wiring.
 * It deliberately does NOT execute or open the sample.
 */
export class DryRunSandboxAdapter extends SandboxAdapter {
  async analyze({ samplePath }) {
    return {
      mode: "dry-run",
      executed: false,
      samplePath,
      processes: [],
      filesCreated: [],
      filesModified: [],
      dnsQueries: [],
      networkConnections: [],
      suspiciousBehaviors: [],
    };
  }
}
