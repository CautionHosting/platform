#!/bin/bash
# Run the containerized caution CLI against the current directory.
#
# Build the image first:
#   docker build -t caution-cli:runtime -f containerfiles/Containerfile.cli --target runtime .
#
# Usage: scripts/caution-docker.sh <caution-cli-args...>

set -euo pipefail

IMAGE="${CAUTION_CLI_IMAGE:-caution-cli:runtime}"

# /var/run/docker.sock is root-owned, and matching our own uid via --group-add
# turned out to be unreliable on Docker Desktop's containerd runtime (fails
# with "failed to change group ID: operation not permitted"). Running the
# container as root sidesteps that entirely — root always has socket access
# regardless of its group, on both Docker Desktop and native Linux.
#
# Build cache is a named volume, not a bind mount: on Docker Desktop, bind-mounted
# build contexts round-trip host->VM->daemon through the file-sharing layer and can
# drop recently-written files, corrupting `caution verify` PCRs. A named volume lives
# in-VM with the daemon, so it's always coherent. Inspect with:
#   docker run --rm -v caution-cli-cache:/c alpine ls -R /c
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/caution-cli-docker"
CACHE_VOLUME="${CAUTION_CLI_CACHE_VOLUME:-caution-cli-cache}"
mkdir -p "$CONFIG_DIR"

docker run --rm -it \
  --user root \
  -v "$PWD:/workspace" \
  -w /workspace \
  -v "$CONFIG_DIR:/home/user/.config/caution-cli" \
  -v "$CACHE_VOLUME:/home/user/.cache/caution" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  "$IMAGE" "$@"
