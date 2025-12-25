#!/bin/sh
# Generate/update package-lock.json using stagex container

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

docker build -t stagex-npm-temp -f - . <<'EOF'
FROM stagex/pallet-nodejs@sha256:1f705b58321b17e87ea68c04431ad83be6e6b64253d0443be4c61501902d57c3 AS nodejs
FROM stagex/core-npm@sha256:72fef63138244c9314e6cb4f72d3dcb335a68f255c629b8436bd5089dfeace72 AS npm
FROM stagex/core-git@sha256:6b3e0055f6aeaa8465f207a871db2c63a939cd7406113e9d769ff3b37239f3d0 AS git
FROM stagex/core-curl@sha256:bc8bab43d96a9167fbb85022ea773644a45ef335e7a9b747f203078973fa988e AS curl
FROM stagex/core-busybox@sha256:637b1e0d9866807fac94c22d6dc4b2e1f45c8a5ca1113c88172e0324a30c7283 AS busybox

FROM nodejs
COPY --from=npm . /
COPY --from=git . /
COPY --from=curl . /
COPY --from=busybox . /
ENTRYPOINT []
EOF

docker run --rm \
  -v "$SCRIPT_DIR:/app" \
  -w /app \
  stagex-npm-temp \
  /usr/bin/npm install --package-lock-only

echo "package-lock.json updated"
