#!/bin/sh
# Generate/update package-lock.json using stagex container

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE="caution-lockfile-builder"

docker build -t "$IMAGE" -f "$SCRIPT_DIR/../containerfiles/Containerfile.lockfile" "$SCRIPT_DIR"

docker run --rm \
  -v "$SCRIPT_DIR:/app" \
  -w /app \
  "$IMAGE" \
  /usr/bin/npm install --package-lock-only

echo "package-lock.json updated"
