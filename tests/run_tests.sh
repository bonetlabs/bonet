#!/usr/bin/env bash
#
# Build test artifacts, then launch the shared functional-test client/server.
#
# Usage:
#   ./tests/run_tests.sh [--suite csum|all] server [binary options...]
#   ./tests/run_tests.sh [--suite csum|all] client [binary options...]
#   ./tests/run_tests.sh server csum [binary options...]   # shorthand
#
# Options after server/client are forwarded to the Go binary. The runner adds
# --tests, --prog-dir and every applicable --config; repeated configs are
# loaded in order and later files override earlier values.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUITE="all"
MODE=""
FORWARD_ARGS=()

usage() {
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
    echo "error: $*" >&2
    echo >&2
    usage >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --suite)
            [ "$#" -ge 2 ] || die "--suite requires a value"
            SUITE="$2"
            shift 2
            ;;
        --suite=*)
            SUITE="${1#*=}"
            shift
            ;;
        server|client)
            MODE="$1"
            shift
            break
            ;;
        *)
            die "unknown runner argument '$1'"
            ;;
    esac
done

[ -n "$MODE" ] || die "missing mode: use server or client"

if [ "$#" -gt 0 ] && [[ "$1" != -* ]] && [ "$SUITE" = "all" ]; then
    SUITE="$1"
    shift
fi

while [ "$#" -gt 0 ]; do
    case "$1" in
        --suite)
            [ "$#" -ge 2 ] || die "--suite requires a value"
            SUITE="$2"
            shift 2
            ;;
        --suite=*)
            SUITE="${1#*=}"
            shift
            ;;
        *)
            FORWARD_ARGS+=("$1")
            shift
            ;;
    esac
done

SUITES=()
if [ "$SUITE" = "all" ]; then
    for dir in "$SCRIPT_DIR"/*; do
        [ -d "$dir" ] || continue
        [ -f "$dir/tests.csv" ] || continue
        SUITES+=("$(basename "$dir")")
    done
else
    [ -d "$SCRIPT_DIR/$SUITE" ] || die "suite '$SUITE' does not exist"
    [ -f "$SCRIPT_DIR/$SUITE/tests.csv" ] || die "suite '$SUITE' has no tests.csv"
    SUITES=("$SUITE")
fi

[ "${#SUITES[@]}" -gt 0 ] || die "no test suites found"

echo "[build]  compiling Go binaries and BPF programs ..."
if [ "$SUITE" = "all" ]; then
    make -C "$SCRIPT_DIR" --quiet all
else
    make -C "$SCRIPT_DIR" --quiet "$SUITE" bin/server bin/client
fi
echo "[build]  done"
echo

check_suite_artifacts() {
    local suite="$1"
    local suite_dir="$SCRIPT_DIR/$suite"
    local csv="$suite_dir/tests.csv"
    local missing=()

    [ -x "$SCRIPT_DIR/bin/server" ] || missing+=("bin/server")
    [ -x "$SCRIPT_DIR/bin/client" ] || missing+=("bin/client")

    while IFS= read -r obj; do
        [ -n "$obj" ] || continue
        [ -f "$suite_dir/$obj" ] || missing+=("$suite/$obj")
    done < <(awk -F, '$0 !~ /^#/ && $1 != "name" {print $3; print $5; print $7}' "$csv")

    if [ "${#missing[@]}" -gt 0 ]; then
        echo "[check]  MISSING artifacts for suite '$suite':" >&2
        for f in "${missing[@]}"; do
            echo "         - $f" >&2
        done
        exit 1
    fi

    echo "[check]  all artifacts present for suite '$suite'"
}

for suite in "${SUITES[@]}"; do
    check_suite_artifacts "$suite"
done
echo

SUDO=()
[ "$(id -u)" -eq 0 ] || SUDO=(sudo)

trap 'echo >&2; echo "[run]    interrupted; aborting remaining suites" >&2; exit 130' INT TERM

for suite in "${SUITES[@]}"; do
    suite_dir="$SCRIPT_DIR/$suite"
    suite_args=(--tests "$suite_dir/tests.csv" --prog-dir "$suite_dir")
    if [ -f "$SCRIPT_DIR/config.ini" ]; then
        suite_args+=(--config "$SCRIPT_DIR/config.ini")
    fi
    if [ -f "$suite_dir/config.ini" ]; then
        suite_args+=(--config "$suite_dir/config.ini")
    fi

    echo "[run]    suite '$suite' ($MODE)"
    if "${SUDO[@]}" "$SCRIPT_DIR/bin/$MODE" "${suite_args[@]}" "${FORWARD_ARGS[@]}"; then
        :
    else
        rc=$?
        if [ "$rc" -eq 130 ]; then
            echo "[run]    suite '$suite' interrupted; aborting remaining suites" >&2
        else
            echo "[run]    suite '$suite' failed with exit code $rc; aborting remaining suites" >&2
        fi
        exit "$rc"
    fi
done
