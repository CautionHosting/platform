// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tokio::fs;
use sha2::{Sha256, Digest};

use crate::EifFile;
use crate::manifest::EnclaveManifest;

pub async fn stage_eif_components(
    user_fs_path: &Path,
    enclave_source_path: &Path,
    work_dir: &Path,
    run_command: Option<String>,
    manifest: Option<EnclaveManifest>,
) -> Result<PathBuf> {
    let stage_dir = work_dir.join("eif-stage");
    fs::create_dir_all(&stage_dir).await?;

    tracing::info!("Staging EIF components in: {}", stage_dir.display());

    let app_dir = stage_dir.join("app");
    let enclave_dir = stage_dir.join("enclave");
    let output_dir = stage_dir.join("output");

    fs::create_dir_all(&app_dir).await?;
    fs::create_dir_all(&enclave_dir).await?;
    fs::create_dir_all(&output_dir).await?;

    tracing::info!("Staging user application from: {}", user_fs_path.display());
    copy_dir_recursive(user_fs_path, &app_dir).await?;

    tracing::info!("Staging enclave source from: {}", enclave_source_path.display());
    copy_dir_recursive(enclave_source_path, &enclave_dir).await?;

    if let Some(manifest) = manifest {
        let manifest_path = stage_dir.join("manifest.json");
        manifest.write_to_file(&manifest_path).await
            .context("Failed to write manifest.json")?;
        tracing::info!("Wrote manifest to: {}", manifest_path.display());
    }

    generate_run_sh(&stage_dir, run_command).await?;

    generate_containerfile_eif(&stage_dir).await?;

    tracing::info!("EIF components staged successfully in: {}", stage_dir.display());
    Ok(stage_dir)
}

async fn generate_run_sh(stage_dir: &Path, run_command: Option<String>) -> Result<()> {
    let user_cmd = if let Some(cmd) = run_command {
        let basename = std::path::Path::new(&cmd)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&cmd);

        let enclave_cmd = format!("/app/{}", basename);

        let escaped_cmd = enclave_cmd.replace("'", "'\\''");
        format!("exec sh -c '{}'", escaped_cmd)
    } else {
        r#"for exe in $(/bin/busybox find /app -type f -executable 2>/dev/null); do
    echo "Executing: $exe"
    exec "$exe"
done
echo "ERROR: No executable found in /app"
exit 1"#.to_string()
    };

    let run_sh_content = format!(r#"#!/bin/sh
set -e

echo "=== Caution Enclave Startup ==="

echo "Setting up network loopback..."
/bin/busybox ip addr add 127.0.0.1/8 dev lo
/bin/busybox ip link set dev lo up
/bin/busybox ip link show lo

echo "127.0.0.1   localhost" > /etc/hosts

echo "Network loopback configured"

echo "Setting up vsock network tunnel to parent..."
/bin/socat TUN,tun-type=tap,iff-no-pi,iff-up,tun-name=eth0 VSOCK-CONNECT:3:3 &
SOCAT_PID=$!
echo "VSock tunnel started (PID: $SOCAT_PID)"

/bin/busybox sleep 2

if /bin/busybox ip link show eth0 2>/dev/null; then
    echo "eth0 interface created successfully"

    echo "Requesting IP via DHCP..."
    /bin/busybox udhcpc -i eth0 -n -q -s /bin/udhcpc-script 2>&1 | grep -E "Lease|obtained" || true

    echo "Network configuration:"
    /bin/busybox ip addr show eth0
    /bin/busybox ip route show

    echo "nameserver 10.0.100.1" > /etc/resolv.conf

    echo "Network tunnel established successfully"
else
    echo "WARNING: Failed to create eth0 interface, running without internet access"
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
fi

echo "Loading NSM kernel module..."
if [ -f /nsm.ko ]; then
    insmod /nsm.ko && echo "NSM module loaded successfully" || echo "Failed to load NSM module"
else
    echo "WARNING: NSM module not found at /nsm.ko"
fi

export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

echo "Starting Attestation Service on port 5000..."
/attestation-service &

echo "Starting VSOCK-to-TCP proxies..."
/bin/socat VSOCK-LISTEN:5000,reuseaddr,fork TCP:localhost:5000 &
/bin/socat VSOCK-LISTEN:8080,reuseaddr,fork TCP:localhost:8080 &

/bin/busybox sleep 2

echo "Looking for user application..."
cd /app || cd /

echo "=== /app directory structure ==="
/bin/busybox find /app -type f 2>/dev/null | /bin/busybox head -20
echo "=== Attempting to run user application ==="

{user_cmd}
"#);

    let run_sh_path = stage_dir.join("run.sh");
    fs::write(&run_sh_path, run_sh_content).await?;

    tracing::info!("Generated run.sh at: {}", run_sh_path.display());
    Ok(())
}

async fn generate_containerfile_eif(stage_dir: &Path) -> Result<()> {
    let containerfile_content = r#"
FROM stagex/pallet-rust@sha256:9c38bf1066dd9ad1b6a6b584974dd798c2bf798985bf82e58024fbe0515592ca AS pallet-rust
FROM stagex/core-busybox@sha256:637b1e0d9866807fac94c22d6dc4b2e1f45c8a5ca1113c88172e0324a30c7283 AS busybox
FROM stagex/core-musl@sha256:d9af23284cca2e1002cd53159ada469dfe6d6791814e72d6163c7de18d4ae701 AS musl
FROM stagex/core-gcc@sha256:964ffd3793c5a38ca581e9faefd19918c259f1611c4cbf5dc8be612e3a8b72f5 AS gcc
FROM stagex/core-libunwind@sha256:eb66122d8fc543f5e2f335bb1616f8c3a471604383e2c0a9df4a8e278505d3bc AS libunwind
FROM stagex/core-openssl@sha256:d6487f0cb15f4ee02b420c717cb9abd85d73043c0bb3a2c6ce07688b23c1df07 AS openssl
FROM stagex/core-zlib@sha256:06f5168e20d85d1eb1d19836cdf96addc069769b40f8f0f4a7a70b2f49fc18f8 AS zlib
FROM stagex/core-ca-certificates@sha256:d135f1189e9b232eb7316626bf7858534c5540b2fc53dced80a4c9a95f26493e AS ca-certificates
FROM stagex/core-libzstd@sha256:5382c221194b6d0690eb65ccca01c720a6bd39f92e610dbc0e99ba43f38f3094 AS libzstd
FROM stagex/user-cpio@sha256:9c8bf39001eca8a71d5617b46f8c9b4f7426db41a052f198d73400de6f8a16df AS cpio
FROM stagex/user-socat@sha256:4d1b7a403eba65087a3f69200d2644d01b63f0ea81ef171cedc17de490c8c9a0 AS socat
FROM stagex/user-eif_build@sha256:935032172a23772ea1a35c6334aa98aa7b0c46f9e34a040347c7b2a73496ef8a AS eif-build
FROM stagex/user-linux-nitro@sha256:aa1006d91a7265b33b86160031daad2fdf54ec2663ed5ccbd312567cc9beff2c AS linux-nitro
FROM stagex/user-nit@sha256:60b6eef4534ea6ea78d9f29e4c7feb27407b615424f20ad8943d807191688be7 AS nit

FROM pallet-rust AS enclave-builder

ENV SOURCE_DATE_EPOCH=1
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTFLAGS="-C codegen-units=1 -C target-feature=+crt-static -C link-arg=-Wl,--build-id=none"
ENV TARGET_ARCH="x86_64-unknown-linux-musl"

WORKDIR /build-enclave

COPY enclave/ /build-enclave/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo fetch --locked --target $TARGET_ARCH

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build-enclave/target \
    cargo build --release --locked --target ${TARGET_ARCH} -p attestation-service \
      && install -D -m 0755 /build-enclave/target/${TARGET_ARCH}/release/attestation-service /binaries/attestation-service

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build-enclave/target \
    cargo build --release --locked --target ${TARGET_ARCH} -p init \
      && install -D -m 0755 /build-enclave/target/${TARGET_ARCH}/release/init /binaries/init

FROM busybox AS eif-builder

COPY --from=musl . /
COPY --from=gcc . /
COPY --from=libunwind . /
COPY --from=openssl . /
COPY --from=zlib . /
COPY --from=ca-certificates . /
COPY --from=libzstd . /
COPY --from=cpio . /
COPY --from=socat . /
COPY --from=eif-build . /
COPY --from=nit . /

WORKDIR /build

COPY --from=enclave-builder /binaries/ /build/binaries/

COPY --from=linux-nitro /bzImage /build/kernel/bzImage
COPY --from=linux-nitro /linux.config /build/kernel/linux.config

COPY app/ /build/app/

COPY run.sh /build/run.sh

COPY enclave/udhcpc-script.sh /build/udhcpc-script.sh

COPY manifest.json /build/manifest.json

RUN mkdir -p /build/initramfs/bin && \
    mkdir -p /build/initramfs/lib && \
    mkdir -p /build/initramfs/etc/ssl/certs && \
    mkdir -p /build/initramfs/app

RUN cp /bin/init /build/initramfs/init && \
    chmod +x /build/initramfs/init

RUN cp /build/run.sh /build/initramfs/run.sh && \
    chmod +x /build/initramfs/run.sh

RUN cp /build/udhcpc-script.sh /build/initramfs/bin/udhcpc-script && \
    chmod +x /build/initramfs/bin/udhcpc-script

RUN cp /build/binaries/attestation-service /build/initramfs/attestation-service && \
    chmod +x /build/initramfs/attestation-service

RUN if [ -f /build/manifest.json ]; then \
        cp /build/manifest.json /build/initramfs/manifest.json; \
    fi

RUN if [ -f /bin/busybox ]; then \
        cp /bin/busybox /build/initramfs/bin/busybox && \
        cd /build/initramfs/bin && \
        ln -s busybox sh && \
        ln -s busybox sleep && \
        ln -s busybox find && \
        ln -s busybox cat && \
        ln -s busybox ls && \
        ln -s busybox mkdir && \
        ln -s busybox mount && \
        ln -s busybox chmod && \
        ln -s busybox ip && \
        ln -s busybox udhcpc; \
    fi

RUN if [ -f /usr/bin/socat ]; then \
        cp /usr/bin/socat /build/initramfs/bin/socat && \
        chmod +x /build/initramfs/bin/socat; \
    elif [ -f /bin/socat ]; then \
        cp /bin/socat /build/initramfs/bin/socat && \
        chmod +x /build/initramfs/bin/socat; \
    fi

RUN if [ -f /lib/ld-musl-x86_64.so.1 ]; then \
        cp /lib/ld-musl-x86_64.so.1 /build/initramfs/lib/ld-musl-x86_64.so.1; \
    fi

RUN if [ -f /etc/ssl/certs/ca-certificates.crt ]; then \
        cp /etc/ssl/certs/ca-certificates.crt /build/initramfs/etc/ssl/certs/ca-certificates.crt; \
    fi

RUN cp -r /build/app/* /build/initramfs/app/ 2>/dev/null || true

RUN find /build/initramfs -exec touch -hcd "@0" "{}" +

RUN cd /build/initramfs && \
    find . -print0 | sort -z | cpio --null --create --format=newc --reproducible | gzip --best > /build/rootfs.cpio.gz

RUN eif_build \
    --kernel /build/kernel/bzImage \
    --kernel_config /build/kernel/linux.config \
    --ramdisk /build/rootfs.cpio.gz \
    --output /build/enclave.eif \
    --pcrs_output /build/enclave.pcrs \
    --cmdline "reboot=k panic=1 pci=off nomodules console=ttyS0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd nit.target=/run.sh"

FROM scratch AS output
COPY --from=eif-builder /build/enclave.eif /enclave.eif
COPY --from=eif-builder /build/enclave.pcrs /enclave.pcrs
COPY --from=eif-builder /build/rootfs.cpio.gz /rootfs.cpio.gz
"#;

    let containerfile_path = stage_dir.join("Containerfile.eif");
    fs::write(&containerfile_path, containerfile_content).await?;

    tracing::info!("Generated Containerfile.eif at: {}", containerfile_path.display());
    Ok(())
}

pub async fn build_eif_from_filesystems(
    user_fs_path: &Path,
    _attestation_service_path: &Path,
    _init_path: &Path,
    enclave_source_path: &Path,
    output_path: PathBuf,
    work_dir: &Path,
    run_command: Option<String>,
    manifest: Option<EnclaveManifest>,
) -> Result<EifFile> {
    tracing::info!("Building EIF using transparent Containerfile approach");

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).await?;
    }

    let stage_dir = stage_eif_components(user_fs_path, enclave_source_path, work_dir, run_command, manifest).await?;

    tracing::info!("Building EIF using Docker and Containerfile.eif");
    let output_dir = stage_dir.join("output");

    fs::create_dir_all(&output_dir).await?;

    let output_dir_absolute = std::fs::canonicalize(&output_dir)
        .context("Failed to get absolute path for output directory")?;

    tracing::info!("Output directory (absolute): {}", output_dir_absolute.display());
    eprintln!("Output directory: {}", output_dir_absolute.display());

    let output = Command::new("docker")
        .args([
            "build",
            "--progress=plain",
            "--target", "output",
            "--output", &format!("type=local,rewrite-timestamp=true,dest={}", output_dir_absolute.to_str().unwrap()),
            "-f", "Containerfile.eif",
            ".",
        ])
        .env("DOCKER_BUILDKIT", "1")
        .env("SOURCE_DATE_EPOCH", "1")
        .current_dir(&stage_dir)
        .output()
        .await
        .context("Failed to execute docker build")?;

    let build_log_path = stage_dir.join("build.log");
    let mut log_content = String::new();
    log_content.push_str("=== STDOUT ===\n");
    log_content.push_str(&String::from_utf8_lossy(&output.stdout));
    log_content.push_str("\n=== STDERR ===\n");
    log_content.push_str(&String::from_utf8_lossy(&output.stderr));
    fs::write(&build_log_path, &log_content).await?;

    tracing::info!("Build log saved to: {}", build_log_path.display());
    eprintln!("Build log saved to: {}", build_log_path.display());

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        eprintln!("=== Docker Build Failed ===");
        eprintln!("STDOUT:\n{}", stdout);
        eprintln!("STDERR:\n{}", stderr);
        anyhow::bail!(
            "Docker build failed. See {} for full output",
            build_log_path.display()
        );
    }

    tracing::info!("Docker build completed successfully");
    eprintln!("Docker build completed successfully");

    let built_eif = output_dir_absolute.join("enclave.eif");
    if !built_eif.exists() {
        eprintln!("EIF file not found at: {}", built_eif.display());
        eprintln!("Checking output directory contents...");
        if output_dir_absolute.exists() {
            match std::fs::read_dir(&output_dir_absolute) {
                Ok(entries) => {
                    eprintln!("Files in output directory:");
                    for entry in entries.flatten() {
                        eprintln!("  - {}", entry.path().display());
                    }
                }
                Err(e) => {
                    eprintln!("Could not read output directory: {}", e);
                }
            }
        } else {
            eprintln!("Output directory does not exist: {}", output_dir_absolute.display());
        }
        anyhow::bail!("EIF file was not created at: {}. Check build log: {}",
            built_eif.display(), build_log_path.display());
    }

    fs::copy(&built_eif, &output_path).await
        .with_context(|| format!("Failed to copy EIF from {} to {}", built_eif.display(), output_path.display()))?;

    let built_pcrs = output_dir_absolute.join("enclave.pcrs");
    let pcrs_path = output_path.with_extension("pcrs");
    if built_pcrs.exists() {
        fs::copy(&built_pcrs, &pcrs_path).await
            .with_context(|| format!("Failed to copy PCRs from {} to {}", built_pcrs.display(), pcrs_path.display()))?;
    }

    let metadata = fs::metadata(&output_path)
        .await
        .context("Failed to read EIF metadata")?;

    let file_data = fs::read(&output_path)
        .await
        .context("Failed to read EIF for hashing")?;

    let mut hasher = Sha256::new();
    hasher.update(&file_data);
    let hash_result = hasher.finalize();
    let sha256 = hex::encode(hash_result);

    tracing::info!(
        "EIF built successfully: {} ({} bytes, SHA256: {})",
        output_path.display(),
        metadata.len(),
        sha256
    );
    tracing::info!(
        "Staging directory preserved at: {} (inspect Containerfile.eif to see exact build process)",
        stage_dir.display()
    );

    Ok(EifFile {
        path: output_path,
        size: metadata.len(),
        sha256,
    })
}

async fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    use walkdir::WalkDir;

    fs::create_dir_all(dst).await?;

    for entry in WalkDir::new(src) {
        let entry = entry?;
        let path = entry.path();
        let rel_path = path.strip_prefix(src)?;
        let dst_path = dst.join(rel_path);

        if entry.file_type().is_dir() {
            fs::create_dir_all(&dst_path).await?;
        } else {
            if let Some(parent) = dst_path.parent() {
                fs::create_dir_all(parent).await?;
            }

            let abs_src = std::fs::canonicalize(path)
                .unwrap_or_else(|_| path.to_path_buf());
            let src_exists = path.exists();
            let src_is_file = path.is_file();

            fs::copy(path, &dst_path).await
                .with_context(|| format!(
                    "Failed to copy file:\n  src: {} (abs: {})\n  dst: {}\n  src exists: {}\n  src is_file: {}",
                    path.display(),
                    abs_src.display(),
                    dst_path.display(),
                    src_exists,
                    src_is_file
                ))?;
        }
    }

    Ok(())
}
