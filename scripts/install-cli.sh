#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -euo pipefail

readonly ACKNOWLEDGEMENT_VERSION="host-build-v1"
readonly REQUESTED_BUILD="${1:-auto}"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

die() {
    echo "Error: $*" >&2
    exit 1
}

normalize_platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os:$arch" in
        Linux:x86_64|Linux:amd64)
            HOST_OS="linux"
            HOST_ARCH="x86_64"
            ;;
        Darwin:arm64)
            HOST_OS="macos"
            HOST_ARCH="arm64"
            ;;
        *)
            die "unsupported platform $os/$arch. Supported platforms are Linux/x86_64 and macOS/arm64."
            ;;
    esac
}

select_build() {
    case "$REQUESTED_BUILD" in
        auto|host)
            SELECTED_BUILD="host"
            ;;
        stagex)
            [ "$HOST_OS:$HOST_ARCH" = "linux:x86_64" ] || \
                die "the StageX CLI can only be installed on Linux/x86_64; detected $HOST_OS/$HOST_ARCH. Use 'make install-cli' to select the supported build automatically."
            SELECTED_BUILD="stagex"
            ;;
        *)
            die "unknown build selection '$REQUESTED_BUILD'; expected auto, stagex, or host."
            ;;
    esac
}

acknowledgement_file() {
    if [ -n "${CAUTION_CLI_CONFIG_DIR:-}" ]; then
        printf '%s\n' "$CAUTION_CLI_CONFIG_DIR/acknowledgements/$ACKNOWLEDGEMENT_VERSION"
        return
    fi

    if [ "$HOST_OS" = "macos" ]; then
        printf '%s\n' "$HOME/Library/Application Support/caution-cli/acknowledgements/$ACKNOWLEDGEMENT_VERSION"
    else
        printf '%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/caution-cli/acknowledgements/$ACKNOWLEDGEMENT_VERSION"
    fi
}

persist_acknowledgement() {
    local ack_file ack_dir tmp_file method="$1"
    ack_file="$(acknowledgement_file)"
    ack_dir="$(dirname "$ack_file")"
    mkdir -p "$ack_dir"
    chmod 0700 "$ack_dir"
    tmp_file="$(mktemp "${ack_file}.tmp.XXXXXX")"
    trap 'rm -f "$tmp_file"' RETURN
    {
        printf 'acknowledgement=%s\n' "$ACKNOWLEDGEMENT_VERSION"
        printf 'accepted_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'platform=%s/%s\n' "$HOST_OS" "$HOST_ARCH"
        printf 'method=%s\n' "$method"
    } > "$tmp_file"
    chmod 0600 "$tmp_file"
    mv -f "$tmp_file" "$ack_file"
    trap - RETURN
}

acknowledge_host_build() {
    local ack_file response
    ack_file="$(acknowledgement_file)"

    if [ -f "$ack_file" ]; then
        echo "Host-toolchain build risk previously acknowledged ($ACKNOWLEDGEMENT_VERSION)."
        return
    fi

    echo ""
    echo "Host-toolchain build acknowledgement"
    echo ""
    echo "This CLI will be compiled with your local Rust/C toolchain and linked"
    echo "against host system libraries, including libc and PC/SC dependencies."
    echo "It is not built through the StageX reproducible pipeline, so bit-for-bit"
    echo "reproducibility is not guaranteed or verified."
    echo ""

    if [ "${CAUTION_ACCEPT_HOST_BUILD_RISK:-}" = "1" ]; then
        persist_acknowledgement "environment"
        echo "Acknowledged through CAUTION_ACCEPT_HOST_BUILD_RISK=1."
        return
    fi

    if [ ! -t 0 ]; then
        die "host-build acknowledgement requires an interactive terminal. Set CAUTION_ACCEPT_HOST_BUILD_RISK=1 to accept non-interactively."
    fi

    printf "Type 'yes' to continue: "
    read -r response
    [ "$response" = "yes" ] || die "host-toolchain installation cancelled."
    persist_acknowledgement "interactive"
}

directory_is_usable() {
    local dir="$1" parent
    parent="$(dirname "$dir")"
    if [ -d "$dir" ]; then
        [ -w "$dir" ]
    else
        [ -d "$parent" ] && [ -w "$parent" ]
    fi
}

select_install_dir() {
    local resolved dir
    if [ -n "${CLI_INSTALL_DIR:-}" ]; then
        INSTALL_DIR="$CLI_INSTALL_DIR"
        return
    fi

    resolved="$(command -v caution 2>/dev/null || true)"
    if [ -n "$resolved" ] && [ -f "$resolved" ]; then
        dir="$(dirname "$resolved")"
        if directory_is_usable "$dir"; then
            INSTALL_DIR="$dir"
            return
        fi
    fi

    if [ "$HOST_OS" = "macos" ]; then
        for dir in "$HOME/.local/bin" /opt/homebrew/bin /usr/local/bin; do
            if directory_is_usable "$dir"; then
                INSTALL_DIR="$dir"
                return
            fi
        done
    fi

    INSTALL_DIR="$HOME/.local/bin"
}

build_cli() {
    local make_bin="${MAKE:-make}" build_target
    case "$SELECTED_BUILD" in
        stagex)
            build_target="build-cli"
            ARTIFACT="$CLI_OUT_DIR/caution-linux-x86_64"
            ;;
        host)
            build_target="build-cli-host"
            ARTIFACT="$CLI_OUT_DIR/caution-$HOST_OS-$HOST_ARCH-host"
            ;;
    esac

    echo "Building with: $SELECTED_BUILD"
    "$make_bin" CLI_OUT_DIR="$CLI_OUT_DIR" "$build_target"
    [ -f "$ARTIFACT" ] || die "expected build artifact was not produced: $ARTIFACT"
}

install_cli() {
    local installed resolved
    mkdir -p "$INSTALL_DIR"
    [ -d "$INSTALL_DIR" ] || die "$INSTALL_DIR does not exist."
    [ -w "$INSTALL_DIR" ] || die "$INSTALL_DIR is not writable."

    installed="$INSTALL_DIR/caution"
    install -m 0755 "$ARTIFACT" "$installed"
    "$installed" --version >/dev/null 2>&1
    echo "Installed caution ($SELECTED_BUILD build) to $installed"

    resolved="$(command -v caution 2>/dev/null || true)"
    if [ "$resolved" != "$installed" ]; then
        echo ""
        if [ -n "$resolved" ]; then
            echo "caution currently resolves to $resolved, not $installed."
        else
            echo "$INSTALL_DIR is not on your PATH."
        fi
        echo "Use the installed CLI in the current shell with:"
        echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
        echo "To persist it, add that line to your shell configuration and reload the shell."
    fi
}

main() {
    [ -n "${HOME:-}" ] || die "HOME is not set."
    cd "$REPO_ROOT"
    CLI_OUT_DIR="${CLI_OUT_DIR:-out/cli}"

    normalize_platform
    select_build
    select_install_dir

    echo "Detected platform: $HOST_OS/$HOST_ARCH"
    echo "Selected CLI build: $SELECTED_BUILD"
    echo "Install directory: $INSTALL_DIR"

    if [ "$SELECTED_BUILD" = "host" ]; then
        acknowledge_host_build
    fi

    build_cli
    install_cli
}

main "$@"
