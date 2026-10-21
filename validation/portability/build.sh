#!/bin/bash
# Build, with one compiler, everything matrix.sh loads in the kernel:
#   OUT/globals/   every XDP global in its own program (tests/globals):
#                  globals.o with the asm globals, globals_c.o with the C ones
#   OUT/units/     the cases of tests/units: default/ (asm) and c/
#   OUT/workloads/ the XDP workloads of ../framework: asm/ and c/
#   OUT/baseline/  the same workloads in plain eBPF (../baseline)
# and, once in the source tree, the host tools that load them.
#
# usage: build.sh CLANG OUT
set -eu
[ $# -eq 2 ] || { echo "usage: $0 CLANG OUT" >&2; exit 2; }
CLANG=$1
OUT=$(mkdir -p "$2" && cd "$2" && pwd)
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MULTIARCH=$(gcc -dumpmachine 2>/dev/null || echo x86_64-linux-gnu)
SYSINC=/usr/include/$MULTIARCH
case $(uname -m) in x86_64) ARCH=x86 ;; aarch64) ARCH=arm64 ;; *) ARCH=$(uname -m) ;; esac
FLAGS="-O2 -g -target bpf -mcpu=v3 -D__TARGET_ARCH_$ARCH -I$SYSINC -I$ROOT/src"

# Host tools: the same for every compiler.
make -s -C "$ROOT/tests/units" HOST_CC=cc build/run_case
make -s -C "$ROOT/validation/exec_metrics" CC=cc build/verifier_stats

make -s -C "$ROOT/tests/globals" CLANG="$CLANG" BUILD="$OUT/globals" "$OUT/globals/globals.o" "$OUT/globals/globals_c.o"
make -s -C "$ROOT/tests/units" CLANG="$CLANG" BUILD="$OUT/units" "$OUT/units/default.stamp" "$OUT/units/c.stamp"

mkdir -p "$OUT/workloads/asm" "$OUT/workloads/c" "$OUT/baseline" "$OUT/include/gnu"
for f in "$ROOT"/validation/framework/xdp_*.c; do
    b=$(basename "$f" .c)
    $CLANG $FLAGS -I"$ROOT/validation/framework" -c "$f" -o "$OUT/workloads/asm/$b.o"
    $CLANG $FLAGS -I"$ROOT/validation/framework" -DBNT_ASM_GLOBALS=0 -c "$f" -o "$OUT/workloads/c/$b.o"
done
# With -target bpf, glibc's gnu/stubs.h asks for the 32-bit stubs header,
# which 64-bit systems do not ship; an empty one is enough.
: > "$OUT/include/gnu/stubs-32.h"
for f in "$ROOT"/validation/baseline/xdp_*.c; do
    $CLANG $FLAGS -I"$ROOT/validation/baseline" -I"$OUT/include" -c "$f" -o "$OUT/baseline/$(basename "$f" .c).o"
done
"$CLANG" --version | head -1 > "$OUT/compiler.txt"
touch "$OUT/ok"
