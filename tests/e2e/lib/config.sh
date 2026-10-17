#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial

# Read only the Docker env-file setting, never execute .env or overwrite the
# caller's isolated HOME, endpoints, or AWS credentials. Match managed_dns.rs.
resolve_apps_dns_suffix() {
    python3 - <<'PY'
import os
from pathlib import Path
import re
import sys

value = os.environ.get("CAUTION_APPS_DNS_SUFFIX")
if value is None:
    value = "apps.caution.sh"
    path = Path.home() / ".config" / "caution" / ".env"
    if path.exists():
        for line in path.read_text().splitlines():
            key, separator, setting = line.lstrip().partition("=")
            if key == "CAUTION_APPS_DNS_SUFFIX" and separator:
                value = setting
suffix = value.strip().rstrip(".")
valid = (suffix.isascii() and len(suffix) <= 253 and "." in suffix
         and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                 for label in suffix.split(".")))
if not valid:
    sys.exit("CAUTION_APPS_DNS_SUFFIX must be a valid DNS suffix")
print(suffix.lower())
PY
}

# Check the mounted catalog before a suite can mutate billing state. Comparing
# canonical JSON also accepts harmless whitespace/key-order differences.
require_prices_fixture() {
    local fixture=$1 expected actual service
    shift
    expected=$(jq -eS . "$fixture") || return 1
    [ -n "$expected" ] || return 1
    for service in "$@"; do
        # Docker streams the file as tar; no tools are needed inside the image.
        if ! actual=$(set -o pipefail; docker cp "$service:/app/prices.json" - | tar -xOf - | jq -eS .) || [ "$actual" != "$expected" ]; then
            printf 'ERROR: %s pricing must match %s; start this suite with its Make target.\n' "$service" "$fixture" >&2
            return 1
        fi
    done
}
