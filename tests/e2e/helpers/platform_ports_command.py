#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Strict stdlib-only command doubles for the offline ports lifecycle contracts."""
import json
import os
from pathlib import Path
import sys

RESOURCE = "11111111-1111-4111-8111-111111111111"


def fake_command():
    name = Path(sys.argv[0]).name
    args = sys.argv[1:]
    root = Path(os.environ["FAKE_ROOT"])
    with (root / "calls.jsonl").open("a") as stream:
        stream.write(json.dumps([name, args]) + "\n")

    if name == "git":
        if args == ["push", "caution", "main"]:
            print("mock push result")
            return int(os.environ.get("PUSH_STATUS", "0"))
        return 0
    if name == "ssh-keygen":
        key = Path(args[args.index("-f") + 1])
        key.write_text("offline private key fixture")
        key.with_suffix(".pub").write_text("ssh-ed25519 offline")
        (root / "work-dir").write_text(str(key.parent))
        return 0
    if name == "ssh-agent":
        if args == ["-s"]:
            if os.environ.get("AGENT_START_STATUS"):
                return int(os.environ["AGENT_START_STATUS"])
            print("SSH_AUTH_SOCK=/offline/owned; export SSH_AUTH_SOCK; "
                  "SSH_AGENT_PID=424242; export SSH_AGENT_PID;")
            return 0
        if args == ["-k"]:
            assert os.environ["SSH_AGENT_PID"] == "424242"
            assert os.environ["SSH_AUTH_SOCK"] == "/offline/owned"
            return int(os.environ.get("AGENT_KILL_STATUS", "0"))
    if name == "ssh-add":
        return int(os.environ.get("SSH_ADD_STATUS", "0"))
    if name == "sleep":
        return 0
    if name == "caution":
        assert args[:2] == ["-u", "http://gateway.invalid"]
        action = args[2:]
        if action[0] == "init":
            Path(".caution").mkdir()
            Path(".caution/deployment.json").write_text(json.dumps({"resource_id": RESOURCE}))
            return 0
        if action == ["apps", "get", RESOURCE]:
            print("App Details:\n  State: " + os.environ.get("APP_STATE", "running"))
            return 0
        if action == ["apps", "destroy", RESOURCE, "--force"]:
            counter = root / "destroy-count"
            count = int(counter.read_text()) + 1 if counter.exists() else 1
            counter.write_text(str(count))
            mode = os.environ.get("DESTROY_MODE", "success")
            if mode == "pending" or (mode == "settles" and count < 3):
                print("failed to destroy app (status 409 Conflict): resource is deploying [fixture]", file=sys.stderr)
                return 1
            if mode in ("timeout", "killed", "interrupted"):
                print("failed to destroy app (status 409 Conflict): resource is deploying [partial output]", file=sys.stderr)
                return {"timeout": 124, "killed": 137, "interrupted": 143}[mode]
            if mode == "auth":
                print("failed to fetch app (status 401 Unauthorized)", file=sys.stderr)
                return 1
            if mode == "lookalike":
                print("failed to destroy app (status 503 Service Unavailable): resource is deploying", file=sys.stderr)
                return 1
            if mode == "failed":
                print("failed to destroy app (status 503 Service Unavailable): app destroy failed [fixture]", file=sys.stderr)
                return 23
            print("App destroyed")
            return 0
    if name == "docker":
        if args[:1] == ["logs"]:
            print("offline service diagnostic")
            return 0
        if args[:2] == ["exec", "postgres-test"]:
            sql = args[-1]
            if "SELECT organization_id" in sql:
                print("offline-org")
            elif "SELECT provider_resource_id" in sql:
                print("i-offline|192.0.2.1|us-west-2")
            else:
                assert "UPDATE users" in sql or "INSERT INTO credit_ledger" in sql
            return 0
    if name == "aws":
        if args[:2] == ["ec2", "describe-instances"]:
            print("sg-offline")
            return 0
        if args[:2] == ["ec2", "describe-security-groups"]:
            print(json.dumps({"SecurityGroups": [{"IpPermissions": [{
                "IpProtocol": "tcp", "FromPort": 49500, "ToPort": 49500,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }]}]}))
            return 0
        if args[:2] == ["ec2", "describe-instance-attribute"]:
            print("")  # Empty user-data has no forbidden application proxy.
            return 0
    if name == "curl":
        url = next(arg for arg in args if arg.startswith("http://"))
        body, status = "", "200"
        if url.endswith("/auth/e2e-login"):
            body = json.dumps({"session_id": "offline-session", "user_id": "offline-user", "expires_at": "2099-01-01"})
        elif url.endswith("/ssh-keys"):
            body = '{"fingerprint":"offline-fingerprint"}'
        elif url.endswith("/e2p/v2/session"):
            body, status = '{"error":"protocol_error"}', "400"
        elif url.endswith("/attestation"):
            body = '{"document":"offline-not-real-attestation"}'
        elif "plaintext-probe" in url:
            body, status = '{"error":"e2e_required"}', "403"
        elif not (url.endswith("/health") or url.endswith("/user/username") or url.endswith("/resources")):
            raise AssertionError("Unexpected URL " + url)
        if "-o" in args:
            output = args[args.index("-o") + 1]
            if output != "/dev/null":
                Path(output).write_text(body)
        else:
            print(body, end="")
        if "-D" in args:
            Path(args[args.index("-D") + 1]).write_text("Cache-Control: no-store\r\n")
        if "-w" in args:
            print(status, end="")
        return 0
    raise AssertionError(f"Unexpected external command: {name} {args}")


if __name__ == "__main__":
    sys.exit(fake_command())
