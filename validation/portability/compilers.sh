#!/bin/bash
# Check, without a VM, that the asm globals come out the same with every
# compiler: builds tests/globals with each one and compares the code of every
# global across them (compare_globals.py). With -s, also checks each build
# against the configurations chosen for the asm (../exec_metrics/check_asm.py,
# which needs the objects of candidates.py and bpftool).
#
# usage: compilers.sh -o OUT [-s CANDIDATES_DIR] LABEL=CLANG...
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
usage() { echo "usage: $0 -o OUT [-s CANDIDATES_DIR] LABEL=CLANG..." >&2; exit 2; }
OUT= CAND=
while getopts o:s: opt; do
    case $opt in
        o) OUT=$OPTARG ;;
        s) CAND=$OPTARG ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ -n "$OUT" ] && [ $# -ge 2 ] || usage
OUT=$(mkdir -p "$OUT" && cd "$OUT" && pwd)

objs=() status=0
for c in "$@"; do
    label=${c%%=*} cc=${c#*=}
    if ! make -s -C "$ROOT/tests/globals" CLANG="$cc" BUILD="$OUT/$label" "$OUT/$label/globals.o" > "$OUT/$label.log" 2>&1; then
        echo "$label: build failed, see $OUT/$label.log"; status=1; continue
    fi
    objs+=("$label=$OUT/$label/globals.o")
    if [ -n "$CAND" ]; then
        echo "$label: $(python3 "$ROOT/validation/exec_metrics/check_asm.py" --objs "$CAND" "$OUT/$label/globals.o" | tail -1)"
    fi
done
python3 "$HERE/compare_globals.py" "${objs[@]}" || status=1
exit $status
