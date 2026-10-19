// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::path::Path;
use std::process::Command;

const START: &str = "# BEGIN ROOTFS DIRECTORY NORMALIZATION";
const END: &str = "# END ROOTFS DIRECTORY NORMALIZATION";

#[test]
fn rootfs_symlink_policy_survives_buildkit() {
    if !Command::new("docker")
        .arg("version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        eprintln!("skipping rootfs_symlink_policy_survives_buildkit: no Docker");
        return;
    }

    let template = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/Containerfile.eif"),
    )
    .unwrap();
    let busybox = template
        .lines()
        .find(|line| line.starts_with("FROM stagex/core-busybox@"))
        .unwrap()
        .replace(" AS busybox", " AS base");
    let normalization = template
        .split_once(START)
        .unwrap()
        .1
        .split_once(END)
        .unwrap()
        .0
        .trim();
    let run = normalization.split_once("\n\n").unwrap().0;
    let mut reject = "RUN if ( ".to_string();
    reject.push_str(run.strip_prefix("RUN ").unwrap());
    reject.push_str(" ); then echo 'unsafe symlink accepted' >&2; exit 1; fi");
    let pack = r#"RUN /bin/busybox find /build/initramfs -exec /bin/busybox touch -hcd "@0" {} + && \
    cd /build/initramfs && \
    /bin/busybox find . -print0 | /bin/busybox sort -z | \
    /bin/busybox cpio -0 -o -H newc --ignore-devno --renumber-inodes | \
    /bin/busybox gzip -9 > /build/rootfs.cpio.gz"#;

    let dockerfile = r#"{{BUSYBOX}}

FROM base AS merged
RUN mkdir -p /build/initramfs && \
    ln -s usr/bin /build/initramfs/bin && \
    ln -s usr/lib /build/initramfs/lib
{{NORMALIZE}}
RUN test "$(readlink /build/initramfs/bin)" = usr/bin && \
    test "$(readlink /build/initramfs/lib)" = usr/lib && \
    printf bin > /build/initramfs/bin/overlay && \
    printf lib > /build/initramfs/lib/overlay && \
    test -f /build/initramfs/usr/bin/overlay && \
    test -f /build/initramfs/usr/lib/overlay && touch /merged-ok
{{PACK}}

FROM base AS merged-archive
COPY --from=merged /build/rootfs.cpio.gz /
RUN mkdir /inspect && cd /inspect && \
    /bin/busybox gzip -dc /rootfs.cpio.gz | /bin/busybox cpio -id && \
    test "$(readlink bin)" = usr/bin && \
    test "$(readlink lib)" = usr/lib && \
    test -f usr/bin/overlay && test -f usr/lib/overlay && \
    touch /merged-archive-ok

FROM base AS ordinary-main
RUN mkdir -p /build/initramfs/bin /build/initramfs/lib
RUN test -e /build/initramfs/bin || mkdir -p /build/initramfs/bin
RUN test -e /build/initramfs/lib || mkdir -p /build/initramfs/lib
RUN test -e /build/initramfs/etc/ssl/certs || mkdir -p /build/initramfs/etc/ssl/certs
{{PACK}}

FROM base AS ordinary-patched
RUN mkdir -p /build/initramfs/bin /build/initramfs/lib
{{NORMALIZE}}
RUN test ! -e /build/initramfs/usr
{{PACK}}

FROM base AS absolute
RUN mkdir -p /build/initramfs/lib && ln -s /usr/bin /build/initramfs/bin
{{REJECT}}
RUN touch /absolute-ok

FROM base AS escaping
RUN mkdir -p /build/initramfs/lib && ln -s ../escape/bin /build/initramfs/bin
{{REJECT}}
RUN touch /escaping-ok

FROM base AS unexpected
RUN mkdir -p /build/initramfs/lib && ln -s sbin /build/initramfs/bin
{{REJECT}}
RUN touch /unexpected-ok

FROM base AS trailing-newline
RUN mkdir -p /build/initramfs/lib && \
    target="$(printf 'usr/bin\nx')" && target="${target%x}" && \
    ln -s "$target" /build/initramfs/bin
{{REJECT}}
RUN touch /trailing-newline-ok

FROM base AS symlinked-parent
RUN mkdir -p /build/initramfs/lib && \
    ln -s usr/bin /build/initramfs/bin && \
    ln -s elsewhere /build/initramfs/usr
{{REJECT}}
RUN touch /symlinked-parent-ok

FROM base AS target-file
RUN mkdir -p /build/initramfs/lib /build/initramfs/usr && \
    ln -s usr/bin /build/initramfs/bin && \
    printf file > /build/initramfs/usr/bin
{{REJECT}}
RUN touch /target-file-ok

FROM scratch AS output
COPY --from=merged /merged-ok /
COPY --from=merged /build/rootfs.cpio.gz /merged.cpio.gz
COPY --from=merged-archive /merged-archive-ok /
COPY --from=ordinary-main /build/rootfs.cpio.gz /main.cpio.gz
COPY --from=ordinary-patched /build/rootfs.cpio.gz /patched.cpio.gz
COPY --from=absolute /absolute-ok /
COPY --from=escaping /escaping-ok /
COPY --from=unexpected /unexpected-ok /
COPY --from=trailing-newline /trailing-newline-ok /
COPY --from=symlinked-parent /symlinked-parent-ok /
COPY --from=target-file /target-file-ok /
"#
    .replace("{{BUSYBOX}}", &busybox)
    .replace("{{NORMALIZE}}", normalization)
    .replace("{{REJECT}}", &reject)
    .replace("{{PACK}}", pack);

    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("Containerfile"), dockerfile).unwrap();
    let output_dir = temp.path().join("output");
    let mut output_arg = "type=local,dest=".to_string();
    output_arg.push_str(output_dir.to_str().unwrap());
    let output = Command::new("docker")
        .args([
            "build",
            "--no-cache",
            "--platform",
            "linux/amd64",
            "--target",
            "output",
            "--output",
            &output_arg,
            "-f",
            "Containerfile",
            ".",
        ])
        .env("DOCKER_BUILDKIT", "1")
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "rootfs symlink policy failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(output_dir.join("patched.cpio.gz")).unwrap(),
        std::fs::read(output_dir.join("main.cpio.gz")).unwrap()
    );
}
