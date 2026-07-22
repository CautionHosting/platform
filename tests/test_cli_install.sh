#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$REPO_ROOT/scripts/install-cli.sh"
TEST_ROOT="$(mktemp -d)"
SYSTEM_PATH="/usr/bin:/bin:/usr/sbin:/sbin"

cleanup() {
    rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

announce() {
    printf 'Testing %s...\n' "$1"
}

assert_contains() {
    local file="$1" expected="$2"
    grep -F "$expected" "$file" >/dev/null || \
        fail "expected '$expected' in $file"
}

assert_make_target() {
    local log="$1" expected="$2"
    [ -f "$log" ] || fail "expected make log $log"
    [ "$(tail -n 1 "$log")" = "$expected" ] || \
        fail "expected make target $expected, got $(tail -n 1 "$log")"
}

assert_installer_target() {
    local target="$1" expected_mode="$2" recipe
    recipe="$(awk -v target="$target:" '$0 == target { getline; print; exit }' "$REPO_ROOT/Makefile")"
    case "$recipe" in
        *"./scripts/install-cli.sh $expected_mode"*) ;;
        *) fail "expected $target to invoke installer mode $expected_mode" ;;
    esac
}

create_case() {
    local name="$1"
    CASE_DIR="$TEST_ROOT/$name"
    MOCK_BIN="$CASE_DIR/mock-bin"
    CASE_HOME="$CASE_DIR/home"
    CASE_OUT="$CASE_DIR/out"
    CASE_INSTALL="$CASE_DIR/install/bin"
    CASE_LOG="$CASE_DIR/output.log"
    MAKE_LOG="$CASE_DIR/make.log"
    mkdir -p "$MOCK_BIN" "$CASE_HOME" "$CASE_OUT"

    cat > "$MOCK_BIN/uname" <<'MOCK_UNAME'
#!/usr/bin/env bash
case "${1:-}" in
    -s) printf '%s\n' "$MOCK_UNAME_S" ;;
    -m) printf '%s\n' "$MOCK_UNAME_M" ;;
    *) exit 2 ;;
esac
MOCK_UNAME

    cat > "$MOCK_BIN/make" <<'MOCK_MAKE'
#!/usr/bin/env bash
set -euo pipefail

out_dir=""
target=""
for arg in "$@"; do
    case "$arg" in
        CLI_OUT_DIR=*) out_dir="${arg#CLI_OUT_DIR=}" ;;
        build-cli|build-cli-host) target="$arg" ;;
    esac
done

[ -n "$out_dir" ] || { echo "missing CLI_OUT_DIR" >&2; exit 2; }
[ -n "$target" ] || { echo "missing build target" >&2; exit 2; }
mkdir -p "$out_dir"

case "$target" in
    build-cli)
        artifact="$out_dir/caution-linux-x86_64"
        ;;
    build-cli-host)
        case "$(uname -s)" in
            Darwin) os="macos" ;;
            Linux) os="linux" ;;
            *) exit 2 ;;
        esac
        case "$(uname -m)" in
            arm64|aarch64) arch="arm64" ;;
            x86_64|amd64) arch="x86_64" ;;
            *) exit 2 ;;
        esac
        artifact="$out_dir/caution-$os-$arch-host"
        ;;
esac

cat > "$artifact" <<'MOCK_CAUTION'
#!/usr/bin/env sh
[ "${1:-}" = "--version" ] || exit 2
echo "caution 0.1.0-test"
MOCK_CAUTION
chmod 0755 "$artifact"
printf '%s\n' "$target" >> "$MOCK_MAKE_LOG"
MOCK_MAKE

    chmod 0755 "$MOCK_BIN/uname" "$MOCK_BIN/make"
}

run_installer() {
    local mode="$1" os="$2" arch="$3" acceptance="${4:-unset}"
    local -a environment=(
        "PATH=$MOCK_BIN:$SYSTEM_PATH"
        "HOME=$CASE_HOME"
        "XDG_CONFIG_HOME=$CASE_HOME/.config"
        "MAKE=$MOCK_BIN/make"
        "MOCK_MAKE_LOG=$MAKE_LOG"
        "MOCK_UNAME_S=$os"
        "MOCK_UNAME_M=$arch"
        "CLI_OUT_DIR=$CASE_OUT"
        "CLI_INSTALL_DIR=$CASE_INSTALL"
    )
    if [ "$acceptance" != "unset" ]; then
        environment+=("CAUTION_ACCEPT_HOST_BUILD_RISK=$acceptance")
    fi

    set +e
    env "${environment[@]}" bash "$INSTALLER" "$mode" \
        < /dev/null > "$CASE_LOG" 2>&1
    RUN_STATUS=$?
    set -e
}

announce "automatic StageX selection on Linux/x86_64"
create_case linux_auto
run_installer auto Linux x86_64
[ "$RUN_STATUS" -eq 0 ] || fail "Linux automatic install failed"
assert_make_target "$MAKE_LOG" build-cli
[ -x "$CASE_INSTALL/caution" ] || fail "Linux CLI was not installed"
assert_contains "$CASE_LOG" "Selected CLI build: stagex"
assert_contains "$CASE_LOG" "$CASE_INSTALL is not on your PATH."
[ ! -e "$CASE_HOME/.config/caution-cli/acknowledgements/host-build-v1" ] || \
    fail "StageX install unexpectedly persisted a host acknowledgement"

announce "host-build acknowledgement requirement on macOS/arm64"
create_case mac_requires_ack
run_installer auto Darwin arm64
[ "$RUN_STATUS" -ne 0 ] || fail "non-interactive macOS install succeeded without acknowledgement"
assert_contains "$CASE_LOG" "CAUTION_ACCEPT_HOST_BUILD_RISK=1"
[ ! -e "$MAKE_LOG" ] || fail "host build started before acknowledgement"

announce "automatic host build and acknowledgement persistence on macOS/arm64"
create_case mac_auto
run_installer auto Darwin arm64 1
[ "$RUN_STATUS" -eq 0 ] || fail "acknowledged macOS automatic install failed"
assert_make_target "$MAKE_LOG" build-cli-host
[ -x "$CASE_INSTALL/caution" ] || fail "macOS host CLI was not installed"
assert_contains "$CASE_LOG" "Selected CLI build: host"
ACK_FILE="$CASE_HOME/Library/Application Support/caution-cli/acknowledgements/host-build-v1"
[ -f "$ACK_FILE" ] || fail "macOS acknowledgement was not persisted"
assert_contains "$ACK_FILE" "method=environment"

announce "reuse of the persisted host-build acknowledgement"
run_installer auto Darwin arm64
[ "$RUN_STATUS" -eq 0 ] || fail "persisted acknowledgement was not honored"
assert_contains "$CASE_LOG" "risk previously acknowledged"

announce "explicit host build on Linux/x86_64"
create_case linux_host
run_installer host Linux x86_64 1
[ "$RUN_STATUS" -eq 0 ] || fail "explicit Linux host install failed"
assert_make_target "$MAKE_LOG" build-cli-host
[ -f "$CASE_OUT/caution-linux-x86_64-host" ] || fail "host artifact name is incorrect"

announce "rejection of an explicit StageX install on macOS/arm64"
create_case mac_forced_stagex
run_installer stagex Darwin arm64
[ "$RUN_STATUS" -ne 0 ] || fail "macOS StageX installation unexpectedly succeeded"
assert_contains "$CASE_LOG" "StageX CLI can only be installed on Linux/x86_64"
[ ! -e "$MAKE_LOG" ] || fail "incompatible StageX build started"

announce "rejection of unsupported platforms"
create_case unsupported
run_installer auto Linux arm64
[ "$RUN_STATUS" -ne 0 ] || fail "unsupported Linux/arm64 installation unexpectedly succeeded"
assert_contains "$CASE_LOG" "unsupported platform Linux/arm64"
[ ! -e "$MAKE_LOG" ] || fail "unsupported platform started a build"

announce "Makefile installer target wiring"
assert_installer_target install-cli auto
assert_installer_target install-cli-stagex stagex
assert_installer_target install-cli-host host
if grep -q '^install:' "$REPO_ROOT/Makefile"; then
    fail "generic install target should not exist"
fi

echo "CLI installer tests passed"
