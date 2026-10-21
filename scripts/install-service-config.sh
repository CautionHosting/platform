#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
HELPER_DIR="$HOME/.local/lib/caution"

mkdir -p "$UNIT_DIR" "$HELPER_DIR"
install -m 0644 "$REPO_ROOT/scripts/platform_env.py" "$HELPER_DIR/platform_env.py"
install -m 0644 "$REPO_ROOT"/systemd/*.service "$UNIT_DIR/"
systemctl --user daemon-reload
