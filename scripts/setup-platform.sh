#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="$HOME/.config/caution"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

if [[ "$(uname -s)" != Linux ]]; then
    printf 'Error: platform services require Linux with a systemd user manager.\n' >&2
    exit 1
fi
if ! systemctl --user show-environment >/dev/null 2>&1; then
    printf 'Error: cannot reach the systemd user manager. Run setup from a login session for this user (not sudo).\n' >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    printf 'Error: Docker must be installed and its daemon accessible to this user without sudo.\n' >&2
    exit 1
fi

mkdir -p "$CONFIG_DIR" "$UNIT_DIR"
for file in .env prices.json config.json; do
    if [[ -e "$CONFIG_DIR/$file" || -L "$CONFIG_DIR/$file" ]]; then
        if [[ ! -f "$CONFIG_DIR/$file" || ! -r "$CONFIG_DIR/$file" ]]; then
            printf 'Error: %s must be a readable regular file; left unchanged.\n' "$CONFIG_DIR/$file" >&2
            exit 1
        fi
        if [[ "$file" == prices.json ]]; then
            if [[ -L "$CONFIG_DIR/$file" || "$(stat -c %h "$CONFIG_DIR/$file")" != 1 ]]; then
                printf 'Warning: %s is linked; permissions left unchanged. Verify container readability separately.\n' "$CONFIG_DIR/$file" >&2
            else
                chmod 0644 "$CONFIG_DIR/$file"
            fi
        fi
        continue
    fi
    example="$file.example"
    [[ "$file" != .env ]] || example=env.example
    mode=0600
    [[ "$file" != prices.json ]] || mode=0644
    install -m "$mode" "$REPO_ROOT/$example" "$CONFIG_DIR/$file"
done
install -m 0644 "$REPO_ROOT"/systemd/*.service "$UNIT_DIR/"
systemctl --user daemon-reload
printf 'Setup complete; no services started. Review %s/{.env,prices.json,config.json}, then run make up.\n' "$CONFIG_DIR"
