import net from "node:net";

/**
 * ClamAVScanner
 * --------------
 * Connects to a running `clamd` daemon (the ClamAV background process —
 * see the project notes on why clamd rather than shelling out to
 * `clamscan` per-file) and streams the file buffer to it directly using
 * clamd's INSTREAM protocol, rather than writing to a temp file and
 * asking clamd to scan a path. Streaming the buffer directly means
 * clamd never needs filesystem access to the caller's files at all.
 *
 * The INSTREAM wire protocol, exactly as implemented below and
 * verified against a real running clamd:
 *   1. Send the literal bytes "zINSTREAM\0" (tells clamd a stream is coming)
 *   2. Send the buffer in one chunk: a 4-byte big-endian length prefix,
 *      then that many bytes of the actual file content
 *   3. Send a zero-length chunk (4 zero bytes) to signal end-of-stream
 *   4. Read back a text response — "stream: OK" for clean, or
 *      "stream: <SignatureName> FOUND" for a match
 *
 * This module does NOT install, start, or manage clamd — same
 * relationship as a database client library and a database server.
 * The caller is responsible for having a clamd reachable somewhere
 * (locally via socketPath, or over the network via host/port — e.g.
 * the Phase 5 Docker Compose setup, which starts clamd and the
 * service together). Configurable via a factory, same pattern as
 * every other configurable piece in this project.
 *
 * Implements the Scanner contract from core/src/interfaces/scanner.js.
 */

export function createClamAVScanner({ socketPath, host, port } = {}) {
  if (!socketPath && !(host && port)) {
    throw new Error(
      "createClamAVScanner requires either { socketPath } (a local clamd socket) " +
        "or { host, port } (a TCP-reachable clamd) to know where to connect."
    );
  }

  return {
    name: "ClamAV Scanner",

    /**
     * @param {Buffer} buffer
     * @returns {Promise<import('@secureupload/core').ScanResult>}
     */
    async scan(buffer) {
      const response = await streamToClamd(buffer, { socketPath, host, port });
      return interpretResponse(response);
    },
  };
}

function streamToClamd(buffer, { socketPath, host, port }) {
  return new Promise((resolve, reject) => {
    const connectionOptions = socketPath ? { path: socketPath } : { host, port };
    const socket = net.createConnection(connectionOptions);
    let response = "";

    socket.on("connect", () => {
      socket.write("zINSTREAM\0");

      const sizeHeader = Buffer.alloc(4);
      sizeHeader.writeUInt32BE(buffer.length, 0);
      socket.write(sizeHeader);
      socket.write(buffer);

      const endMarker = Buffer.alloc(4); // zero-length chunk = end of stream
      socket.write(endMarker);
    });

    socket.on("data", (chunk) => {
      response += chunk.toString();
    });
    socket.on("end", () => resolve(response.replace(/\0+$/, "").trim()));
    socket.on("error", (err) => {
      // A connection failure is a genuine failure (clamd unreachable),
      // not a normal "file is unclean" outcome — this should throw,
      // per the Scanner contract's rule about reserving thrown errors
      // for real infrastructure problems.
      reject(new Error(`Could not reach clamd: ${err.message}`));
    });
  });
}

function interpretResponse(response) {
  // Clean: "stream: OK"
  if (response.endsWith("OK")) {
    return { clean: true, findings: [] };
  }

  // Infected: "stream: <SignatureName> FOUND"
  const foundMatch = response.match(/stream:\s*(.+)\s+FOUND$/);
  if (foundMatch) {
    const virusName = foundMatch[1];
    return {
      clean: false,
      findings: [
        {
          rule: "clamav-match",
          severity: "extreme",
          message: `ClamAV identified this file as "${virusName}".`,
          details: { virusName },
        },
      ],
    };
  }

  // Anything else (an ERROR response, unexpected format) is a genuine
  // failure to interpret — throw rather than silently guessing.
  throw new Error(`Unexpected response from clamd: "${response}"`);
}