#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial
"""Tiny JSON mocks for opt-in org-user quorum e2e tests."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os

SERVICE = os.environ.get("MOCK_SERVICE", "keymaker")


def read_json(handler):
    length = int(handler.headers.get("content-length", "0"))
    body = handler.rfile.read(length) if length else b"{}"
    return json.loads(body.decode("utf-8"))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print("%s - %s" % (self.address_string(), format % args), flush=True)

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        try:
            body = read_json(self)
            if SERVICE == "public-cert":
                if self.path != "/v1/public-certificates" or body.get("version") != "V1":
                    raise ValueError(f"unexpected public-cert request: {self.path} {body}")
                count = int(body["certificate_count"])
                response = {
                    "data": {
                        "version": "V1",
                        "organization_id": body["organization_id"],
                        "bundle_id": [0] * 15 + [1],
                        "certificates": [f"mock-cert-{i}" for i in range(count)],
                    },
                    "necroproof": [1, 2, 3],
                }
            else:
                if self.path != "/generate_quorum" or body.get("version") != "V1":
                    raise ValueError(f"unexpected keymaker request: {self.path} {body}")
                response = {
                    "data": {
                        "version": "V1",
                        "bundle_id": body["bundle_id"],
                        "label": body.get("label", {}),
                        "keyring": body["keyring"],
                        "shardfile": "mock-shardfile",
                        "public_key": "mock-public-key",
                    },
                    "necroproof": [9, 8, 7],
                }
            payload = json.dumps(response).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception as exc:
            payload = str(exc).encode("utf-8")
            self.send_response(500)
            self.send_header("content-type", "text/plain")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)


if __name__ == "__main__":
    addr = ("0.0.0.0", int(os.environ.get("PORT", "8080")))
    print(f"starting {SERVICE} mock on {addr[0]}:{addr[1]}", flush=True)
    ThreadingHTTPServer(addr, Handler).serve_forever()
