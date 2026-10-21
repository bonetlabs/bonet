#!/bin/sh
# Run inside the VM by matrix.sh, as root: load every build of BUILDS in this
# kernel and write the results to RESULTS/<compiler>/.
#   globals.tsv    verifier_stats on every global (asm and C)
#   units.txt      tests/units/check.py: each case's result against expected.json
#   workloads.tsv  verifier_stats on the workloads (asm and C)
#   baseline.tsv   verifier_stats on the plain eBPF workloads
#
# usage: test.sh BUILDS RESULTS
BUILDS=$1 RESULTS=$2
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
STATS=$ROOT/validation/exec_metrics/build/verifier_stats
mkdir -p "$RESULTS"
uname -r > "$RESULTS/uname"
for b in "$BUILDS"/*/; do
    b=${b%/}; o=$RESULTS/$(basename "$b")
    [ -f "$b/ok" ] || continue
    # the verifier logs of failed loads go to log/<set>/<object>/<program>.log
    mkdir -p "$o/log"
    "$STATS" -l "$o/log/globals" "$b/globals/globals.o" "$b/globals/globals_c.o" > "$o/globals.tsv" 2> "$o/globals.err"
    python3 "$ROOT/tests/units/check.py" "$b/units/default" "$b/units/c" > "$o/units.txt" 2>&1
    "$STATS" -l "$o/log/workloads-asm" "$b"/workloads/asm/*.o > "$o/workloads.tsv" 2> "$o/workloads.err"
    "$STATS" -l "$o/log/workloads-c" "$b"/workloads/c/*.o | tail -n +2 >> "$o/workloads.tsv" 2>> "$o/workloads.err"
    "$STATS" -l "$o/log/baseline" "$b"/baseline/*.o > "$o/baseline.tsv" 2> "$o/baseline.err"
done
echo done > "$RESULTS/done"
