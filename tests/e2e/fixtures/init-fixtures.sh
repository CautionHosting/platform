#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# Generates e2e test fixture git repos in tests/e2e/fixtures/.
# Each fixture mirrors the content of codeberg.org/caution/demo-hello-world-enclave
# but uses caution.hcl directly (no Procfile).
#
# Run from repo root to regenerate:
#   bash tests/e2e/fixtures/init-fixtures.sh

set -euo pipefail

FIXTURES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
init_repo() {
  local dir="$1"
  local caution_hcl="$2"

  rm -rf "$dir"
  mkdir -p "$dir"

  # .gitignore
  printf '%s\n' '.caution/' > "$dir/.gitignore"

  # Containerfile
  cat > "$dir/Containerfile" << 'CONTAINERFILE_EOF'
FROM stagex/pallet-rust@sha256:9c38bf1066dd9ad1b6a6b584974dd798c2bf798985bf82e58024fbe0515592ca as builder

WORKDIR /app

WORKDIR /app/hello

RUN echo '[package]\nname = "hello"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nwarp = "0.3"\ntokio = { version = "1", features = ["full"] }' > Cargo.toml

RUN mkdir -p src

RUN cat > src/main.rs <<'EOF'
use warp::Filter;

#[tokio::main]
async fn main() {
    let hello = warp::path::end()
        .map(|| "Hello from Caution.co! Deployment successful!");

    println!("Server starting on port 8083...");
    warp::serve(hello)
        .run(([0, 0, 0, 0], 8083))
        .await;
}
EOF

RUN cat > Cargo.toml <<'EOF'
[package]
name = "hello"
version = "0.0.0"
edition = "2021"

[dependencies]
warp = "0.3"
tokio = { version = "1", features = ["full"] }
EOF

RUN RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-musl

FROM scratch

COPY --from=builder /app/hello/target/x86_64-unknown-linux-musl/release/hello /usr/local/bin/hello

EXPOSE 8080

CMD ["hello"]
CONTAINERFILE_EOF

  # README.md
  cat > "$dir/README.md" << 'README_EOF'
# Hello World Enclave

This is a test repo that can be used to deploy a simple enclave using the Caution platform.
README_EOF

  # caution.hcl
  printf '%s\n' "$caution_hcl" > "$dir/caution.hcl"
}

CAUTION_HCL_STANDARD='enclave "default" {
  build {
    binary = "/usr/local/bin/hello"
    app_sources = ["git@codeberg.org:caution/demo-hello-world-enclave.git"]
  }
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8083
      ip_protocol = "tcp"
    }
  }
  unit "default" {
    command = "/usr/local/bin/hello"
  }
}'

CAUTION_HCL_E2E='enclave "default" {
  build {
    binary = "/usr/local/bin/hello"
    app_sources = ["git@codeberg.org:caution/demo-hello-world-enclave.git"]
  }
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8083
      ip_protocol = "tcp"
    }
    http {
      domain = "app.example.com"
      port = 8083
      e2e_encryption {
        enabled = true
        cors_origins = ["*"]
      }
    }
  }
  unit "default" {
    command = "/usr/local/bin/hello"
  }
}'

echo "Generating e2e test fixtures..."

init_repo "$FIXTURES_DIR/demo-app-happy-path" "$CAUTION_HCL_STANDARD"
echo "  Created demo-app-happy-path"

init_repo "$FIXTURES_DIR/demo-app-platform-ports" "$CAUTION_HCL_E2E"
echo "  Created demo-app-platform-ports"

init_repo "$FIXTURES_DIR/demo-app-byoc" "$CAUTION_HCL_STANDARD"
echo "  Created demo-app-byoc"

init_repo "$FIXTURES_DIR/demo-app-dedicated-builder" "$CAUTION_HCL_STANDARD"
echo "  Created demo-app-dedicated-builder"

echo "Done! 4 fixtures generated in $FIXTURES_DIR"
