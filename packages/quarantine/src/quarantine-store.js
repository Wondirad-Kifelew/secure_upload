import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const QUARANTINE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const ALLOWED_TRANSITIONS = {
  quarantined: new Set(["sandboxing", "released", "blocked", "manual-review"]),
  sandboxing: new Set(["sandboxed", "blocked", "manual-review"]),
  sandboxed: new Set(["released", "blocked", "manual-review"]),
  "manual-review": new Set(["released", "blocked"]),
  released: new Set(),
  blocked: new Set(),
};

async function createUniqueDirectory(root) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const id = crypto.randomUUID();
    const dir = path.join(root, id);
    try {
      await fs.mkdir(dir, { mode: 0o700 });
      return { id, dir };
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
  }

  throw new Error("Unable to allocate a unique quarantine object ID.");
}

export class QuarantineStore {
  constructor({ rootDirectory = "./storage/quarantine" } = {}) {
    this.rootDirectory = path.resolve(rootDirectory);
  }

  async initialize() {
    await fs.mkdir(this.rootDirectory, { recursive: true, mode: 0o700 });
    await fs.chmod(this.rootDirectory, 0o700);
  }

  async put(buffer, meta = {}, decision = {}) {
    if (!Buffer.isBuffer(buffer)) {
      throw new TypeError("QuarantineStore.put expects a Buffer.");
    }

    await this.initialize();

    const { id, dir } = await createUniqueDirectory(this.rootDirectory);
    const samplePath = path.join(dir, "sample.bin");
    const manifestPath = path.join(dir, "manifest.json");
    const sha256 = crypto.createHash("sha256").update(buffer).digest("hex");
    const now = new Date().toISOString();

    const manifest = {
      id,
      originalName: meta.filename ?? null,
      declaredMimeType: meta.declaredMimeType ?? null,
      sizeBytes: buffer.length,
      sha256,
      status: "quarantined",
      suspicious: Boolean(decision.suspicious),
      requiresSandbox: Boolean(decision.requiresSandbox),
      suspicionScore: decision.suspicionScore ?? 0,
      findings: decision.evidence ?? [],
      createdAt: now,
      updatedAt: now,
    };

    await fs.writeFile(samplePath, buffer, { mode: 0o600 });
    await fs.chmod(samplePath, 0o600);
    await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2), { mode: 0o600 });
    await fs.chmod(manifestPath, 0o600);

    return {
      ...manifest,
      samplePath,
      manifestPath,
    };
  }

  async get(id) {
    if (typeof id !== "string" || !QUARANTINE_ID.test(id)) {
      throw new TypeError("Invalid quarantine object ID.");
    }

    const dir = path.join(this.rootDirectory, id);
    const manifestPath = path.join(dir, "manifest.json");
    const raw = await fs.readFile(manifestPath, "utf8");
    const manifest = JSON.parse(raw);

    // Paths are derived from the trusted quarantine root and object ID. They
    // are runtime values, not persisted metadata.
    return {
      ...manifest,
      samplePath: path.join(dir, "sample.bin"),
      manifestPath,
    };
  }

  async transition(id, nextStatus, details = {}) {
    const current = await this.get(id);
    const allowed = ALLOWED_TRANSITIONS[current.status] ?? new Set();

    if (!allowed.has(nextStatus)) {
      throw new Error(`Invalid quarantine transition: ${current.status} -> ${nextStatus}`);
    }

    const updated = {
      ...current,
      ...details,
      status: nextStatus,
      updatedAt: new Date().toISOString(),
    };

    const { samplePath: _samplePath, manifestPath: _manifestPath, ...persisted } = updated;

    await fs.writeFile(current.manifestPath, JSON.stringify(persisted, null, 2), {
      mode: 0o600,
    });
    await fs.chmod(current.manifestPath, 0o600);

    return updated;
  }
}
