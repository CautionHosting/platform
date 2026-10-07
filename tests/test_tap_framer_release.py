#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Rebuild the host helper using its production recipe and verify the release pin.

Requires Docker/BuildKit. No publication or pin update is performed. Run on an
isolated build host; this intentionally bypasses the helper's build-layer cache.
"""
import hashlib
import pathlib
import subprocess
import tempfile


def main():
    root = pathlib.Path(__file__).resolve().parents[1]
    containerfile = root / "containerfiles/Containerfile.tap-framer"
    expected = (root / "src/tap-framer/host.sha256").read_text().strip()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise SystemExit("invalid reviewed host.sha256")
    with tempfile.TemporaryDirectory(prefix="tap-framer-release-") as directory:
        output = pathlib.Path(directory) / "output"
        subprocess.run(["docker", "buildx", "build", "--progress=plain", "--no-cache",
            "--platform", "linux/amd64", "--target", "tap-framer-export",
            "--output", f"type=local,dest={output}",
            "-f", str(containerfile), str(root)], check=True)
        actual = hashlib.sha256((output / "tap-framer").read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"host release pin mismatch: expected {expected}, rebuilt {actual}; "
                "review the source/recipe change and update the trusted release pin before deployment")
        print(f"host release pin verified: {actual}")


if __name__ == "__main__":
    main()
