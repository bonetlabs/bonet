#!/bin/sh
# Compile a BPF source through Merlin's LLVM passes (AlignBPF, then AtomicBPF):
# clang -emit-llvm, opt with the passes, llc.
#
# usage: merlin_llvm.sh MERLIN_DIR -O<level> IN.c OUT.o [clang flags...]
#
# Merlin (https://github.com/4ar0nma0/Merlin) is not part of this repository:
# pass the path of a clone. The passes are built once, against the LLVM that
# LLVM_CONFIG names (default llvm-config-20), into build/merlin-<version>/, and
# clang, opt and llc come from the same LLVM. Merlin targets LLVM 17; the
# copies built here get three small fixes for newer LLVM (StringRef::startswith
# became starts_with, and two missing includes). The clone is not modified.
set -e
merlin=$1 level=$2 in=$3 out=$4
shift 4
here=$(cd "$(dirname "$0")" && pwd)
llvm_config=${LLVM_CONFIG:-llvm-config-20}
bin=$($llvm_config --bindir)
build=$here/build/merlin-$($llvm_config --version)

if [ ! -f "$build/libAlignBPF.so" ] || [ ! -f "$build/libAtomicBPF.so" ]; then
    mkdir -p "$build"
    sed -e 's/\.startswith(/.starts_with(/' -e 's|#include <regex>|#include <regex>\n#include <sstream>|' \
        "$merlin/AlignBPF/align_pass.cpp" > "$build/align_pass.cpp"
    sed -e 's|#include "llvm/Support/AtomicOrdering.h"|#include "llvm/Support/AtomicOrdering.h"\n#include "llvm/IR/IRBuilder.h"|' \
        "$merlin/AtomicBPF/atomic_BPF.cpp" > "$build/atomic_BPF.cpp"
    "$bin/clang++" -shared -fPIC -O2 $($llvm_config --cxxflags) "$build/align_pass.cpp" -o "$build/libAlignBPF.so"
    "$bin/clang++" -shared -fPIC -O2 $($llvm_config --cxxflags) "$build/atomic_BPF.cpp" -o "$build/libAtomicBPF.so"
fi

# llc has no -Os/-Oz; they generate code as -O2.
case $level in -O1|-O3) llc_level=$level ;; *) llc_level=-O2 ;; esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
"$bin/clang" "$level" -g -target bpf -mcpu=v3 "$@" -S -emit-llvm "$in" -o "$tmp/in.ll"
"$bin/opt" --load-pass-plugin "$build/libAlignBPF.so" --load-pass-plugin "$build/libAtomicBPF.so" \
    -passes=alignbpf,atomicbpf "$tmp/in.ll" -o "$tmp/out.bc"
"$bin/llc" -march=bpf -mcpu=v3 "$llc_level" -filetype=obj "$tmp/out.bc" -o "$out"
