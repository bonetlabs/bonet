#!/bin/sh
# Load the objects of a macro_perf run and keep each verifier log, as <case>-<object>.log.
# Run as root on the kernel to measure (the paper's: 6.8), e.g. in a VM:
#   vng --run vmlinuz-6.8.0-... --rwdir=$PWD --exec "sh verifier_logs.sh RUN/objs OUT"
# usage: verifier_logs.sh OBJS_DIR OUT_DIR
set -e
[ $# -eq 2 ] || { echo "usage: $0 OBJS_DIR OUT_DIR" >&2; exit 2; }
objs=$1 out=$2
mkdir -p "$out"
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
uname -r > "$out/uname"
for c in plain inline globals-c globals-asm; do
    for o in "$objs/$c"/*.o; do
        n=$(basename "$o" .o)
        pin=/sys/fs/bpf/verifier-logs-$c-$n
        # -d makes bpftool print the verifier log of a program that loads
        bpftool -d prog load "$o" "$pin" type xdp > "$out/$c-$n.log" 2>&1 || echo "$c $n: load failed" >&2
        rm -f "$pin"
    done
done
