# SecureUpload service image.
#
# Only the service and its dependency graph run in this image — ClamAV's
# clamd runs in its own container (see docker-compose.yml) and is reached
# over the network via CLAMD_HOST/CLAMD_PORT. YARA is the one scanner that
# genuinely needs installing here: yara-scanner.js shells out to the `yara`
# CLI binary rather than talking to a daemon, so it must exist inside this
# image or YARA scanning silently has nothing to run.
FROM node:22-slim

# `yara` is in Debian's default repos — no extra source needed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends yara \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests first so `npm install` is cached as its own Docker layer —
# only re-runs when a package.json actually changes, not on every source edit.
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/package.json
COPY packages/validators/package.json packages/validators/package.json
COPY packages/scanners/package.json packages/scanners/package.json
COPY packages/cdr/package.json packages/cdr/package.json
COPY packages/quarantine/package.json packages/quarantine/package.json
COPY packages/sandbox/package.json packages/sandbox/package.json
COPY packages/risk-engine/package.json packages/risk-engine/package.json
COPY packages/ai/package.json packages/ai/package.json
COPY packages/service/package.json packages/service/package.json

RUN npm install --omit=dev --no-audit --no-fund

# Now bring in the actual source.
COPY packages ./packages

ENV NODE_ENV=production
ENV PORT=3000
ENV QUARANTINE_ROOT=/app/quarantine-data

# Quarantine storage needs to survive container restarts — mount a volume
# at this path in production; docker-compose.yml does this for local dev.
RUN mkdir -p /app/quarantine-data

EXPOSE 3000

CMD ["node", "packages/service/src/http-server.js"]