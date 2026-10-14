#!/bin/bash
# Build every configuration of the globals that collect.py compares.
#
# usage: candidates.sh OUT_DIR
#
# Environment:
#   CLANGS    space-separated LABEL:PATH pairs, e.g. "clang16:/opt/llvm16/bin/clang clang20:clang-20"
#   GCC_BPF   bpf-gcc to use, with GCC_LABEL as its label (default gcc)
#   MERLIN    clone of https://github.com/4ar0nma0/Merlin; adds Merlin's
#             bytecode optimizer on every build and its LLVM passes (see
#             merlin_llvm.sh, LLVM_CONFIG picks the LLVM)
#   LEVELS    optimization levels (default "O1 O2 O3 Os Oz"; gcc skips Oz)
#
# Writes OUT_DIR/<label>.o and OUT_DIR/configs.txt, one LABEL=OBJ per line,
# ready for collect.py: collect.py -o results/all.csv $(cat OUT_DIR/configs.txt)
set -e
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out=$(mkdir -p "$1" && cd "$1" && pwd)
levels=${LEVELS:-O1 O2 O3 Os Oz}
sysinc=/usr/include/$(uname -m)-linux-gnu
flags="-g -mcpu=v3 -D__TARGET_ARCH_x86 -I$repo/src -I$sysinc"

make -C "$repo/tests/globals" build/globals.c >/dev/null
src=$repo/tests/globals/build/globals.c
: > "$out/configs.txt"
add() { echo "$1=$out/$1.o" >> "$out/configs.txt"; }

for pair in $CLANGS; do
    label=${pair%%:*} cc=${pair#*:}
    for o in $levels; do
        "$cc" -$o $flags -target bpf -c "$src" -o "$out/$label-$o.o" 2>/dev/null && add "$label-$o"
    done
done

# gcc needs these three flags for every global to verify; the builds without
# them are kept because some globals verify, and run faster, without them.
if [ -n "$GCC_BPF" ]; then
    g=${GCC_LABEL:-gcc}
    for set in "base:" "noivopts:-fno-ivopts" "safe:-fno-ivopts -fno-cse-follow-jumps -fno-thread-jumps"; do
        name=${set%%:*} extra=${set#*:}
        for o in $levels; do
            [ "$o" = Oz ] && continue
            "$GCC_BPF" -$o $flags -idirafter /usr/include $extra -c "$src" -o "$out/$g-$name-$o.o" 2>/dev/null \
                && add "$g-$name-$o"
        done
    done
fi

if [ -n "$MERLIN" ]; then
    v=$(${LLVM_CONFIG:-llvm-config-20} --version | cut -d. -f1)
    for o in $levels; do
        "$here/merlin_llvm.sh" "$MERLIN" -$o "$src" "$out/clang$v-$o+merlin_llvm.o" $flags 2>/dev/null \
            && add "clang$v-$o+merlin_llvm"
    done
    for label in $(cut -d= -f1 "$out/configs.txt"); do
        python3 "$here/merlin_bc.py" "$MERLIN" "$out/$label.o" "$out/$label+merlin_bc.o" >/dev/null \
            && add "$label+merlin_bc"
    done
fi
echo "$out: $(wc -l < "$out/configs.txt") configurations"
