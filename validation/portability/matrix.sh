#!/bin/bash
# Load BONet's globals, unit cases and workloads, built with each given
# compiler, on each kernel, in a virtme-ng VM per kernel; then print
# summary.py. Kernels already tested are skipped, so an interrupted matrix
# can be started again with the same command.
#
# usage: matrix.sh -k KERNEL_DIR -o OUT [-c LABEL=CLANG]... [KERNEL...]
#   -k  where fetch-kernels.sh unpacked the kernels
#   -o  output: OUT/build/<label>/ (build.sh) and OUT/results/<kernel>/<label>/
#   -c  a compiler to test; repeat for several (default: default=clang)
#   KERNEL  names from kernels.txt (default: every one present in KERNEL_DIR)
# Environment: VNG (default: vng), MEMORY (2G), CPUS (2), TIMEOUT per kernel
# in seconds (1200).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
usage() { echo "usage: $0 -k KERNEL_DIR -o OUT [-c LABEL=CLANG]... [KERNEL...]" >&2; exit 2; }
KDIR= OUT= COMPILERS=()
while getopts k:o:c: opt; do
    case $opt in
        k) KDIR=$OPTARG ;;
        o) OUT=$OPTARG ;;
        c) COMPILERS+=("$OPTARG") ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ -n "$KDIR" ] && [ -n "$OUT" ] || usage
[ ${#COMPILERS[@]} -gt 0 ] || COMPILERS=(default=clang)
KDIR=$(cd "$KDIR" && pwd)
OUT=$(mkdir -p "$OUT" && cd "$OUT" && pwd)
VNG=${VNG:-vng}

for c in "${COMPILERS[@]}"; do
    label=${c%%=*} cc=${c#*=}
    [ -f "$OUT/build/$label/ok" ] && continue
    echo "== build with $label ($cc)"
    "$HERE/build.sh" "$cc" "$OUT/build/$label" > "$OUT/build-$label.log" 2>&1 ||
        { echo "$label: build failed, see $OUT/build-$label.log" >&2; exit 1; }
done

if [ $# -gt 0 ]; then
    kernels=("$@")
else
    mapfile -t kernels < <(grep -v '^\s*\(#\|$\)' "$HERE/kernels.txt" | awk '{print $1}')
fi
for k in "${kernels[@]}"; do
    res=$OUT/results/$k
    [ -f "$res/done" ] && { echo "$k: already tested"; continue; }
    img=$(ls "$KDIR/$k"/root/boot/vmlinuz-* 2>/dev/null | head -1)
    [ -n "$img" ] || { echo "$k: not in $KDIR (fetch-kernels.sh)"; continue; }
    rm -rf "$res"; mkdir -p "$res"
    # microvm hangs at boot on some kernels; the standard machine works on all
    timeout "${TIMEOUT:-1200}" "$VNG" --run "$img" --disable-microvm --memory "${MEMORY:-2G}" \
        --cpus "${CPUS:-2}" --rwdir="$OUT" --exec "$HERE/test.sh $OUT/build $res" \
        < /dev/null > "$res/vng.log" 2>&1
    echo "$k: $([ -f "$res/done" ] && cat "$res/uname" || echo "did not finish, see $res/vng.log")"
done
python3 "$HERE/summary.py" "$OUT/results"
