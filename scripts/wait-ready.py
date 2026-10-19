#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Bounded startup probes only; callers own diagnostics and container cleanup."""
import argparse
import math
import re
import subprocess
import sys
import time
from urllib.parse import urlsplit


def wait_ready(probe, timeout=60.0):
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be finite and positive")
    deadline = time.monotonic() + timeout
    while (remaining := deadline - time.monotonic()) > 0:
        try:
            ready = probe(min(2.0, remaining))
        except subprocess.TimeoutExpired:
            ready = False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        if ready:
            return True
        time.sleep(min(0.2, remaining))
    return False


def http_ready(url, budget):
    result = subprocess.run(
        ["curl", "--disable", "--silent", "--noproxy", "*", "--proto", "=http,https",
         "--output", "/dev/null", "--write-out", "%{http_code}",
         "--max-time", format(budget, ".17f"), "--url", url],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=budget)
    if result.returncode in (2, 3, 4):
        raise ValueError(f"curl invocation failed (exit {result.returncode})")
    return result.returncode == 0 and result.stdout == b"200"


def postgres_ready(container, database, budget):
    result = subprocess.run(
        ["docker", "exec", container, "pg_isready", "-h", "127.0.0.1",
         "-U", "postgres", "-d", database, "-t", "1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=budget)
    if result.returncode in (126, 127):
        raise OSError(f"cannot execute pg_isready (exit {result.returncode})")
    if result.returncode in (3, 125):
        raise ValueError(f"Postgres probe invocation failed (exit {result.returncode})")
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=60.0, help="total seconds (default: 60)")
    commands = parser.add_subparsers(dest="kind", required=True)
    http = commands.add_parser("http")
    http.add_argument("url")
    postgres = commands.add_parser("postgres")
    postgres.add_argument("container")
    postgres.add_argument("database")
    args = parser.parse_args()
    try:
        if args.kind == "http":
            url = urlsplit(args.url)
            if (url.scheme not in ("http", "https") or not url.hostname
                    or any(c.isspace() for c in args.url)):
                raise ValueError("HTTP readiness requires an http(s) URL with a host")
            _ = url.port
            probe = lambda budget: http_ready(args.url, budget)
        else:
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", args.container):
                raise ValueError("invalid Postgres container name")
            if not args.database.strip():
                raise ValueError("Postgres database must not be empty")
            probe = lambda budget: postgres_ready(args.container, args.database, budget)
        if wait_ready(probe, args.timeout):
            return 0
    except ValueError as error:
        parser.error(str(error))
    except OSError as error:
        print(f"Readiness probe unavailable: {error}", file=sys.stderr)
        return 127
    print(f"{args.kind} readiness timed out after {args.timeout:g}s", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
