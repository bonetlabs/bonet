#!/usr/bin/env python3
"""Run the XDP workload cases of workloads.py in the kernel.

For each build (a directory with one <workload>.o per workload) and each case,
runs build/run_prog (BPF_PROG_TEST_RUN) with the case's packet and map
contents, and prints one tab-separated line: build, workload, case, status
(OK, or why it did not run), action, output packet, and the map entries after
the run as map:key=value separated by spaces. workload_metrics.py compares the
interpreter with it. Needs root and the network of vm_net.sh, for the
forwarding cases.

usage: workload_kernel.py LABEL=DIR... > workloads_kernel.tsv
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from workloads import CASES  # noqa: E402

RUN = os.path.join(HERE, 'build', 'run_prog')

print('build\tworkload\tcase\tstatus\taction\tpacket\tmaps')
for b in sys.argv[1:]:
    label, d = b.split('=', 1)
    for wl, case, pkt, maps, want in CASES:
        obj = os.path.join(d, wl + '.o')
        if not os.path.exists(obj):
            continue
        args = [RUN, obj, pkt.hex()]
        for m, entries in maps.items():
            for k, v in entries.items():
                args += [m, k.hex(), v.hex()]
        out = subprocess.run(args, capture_output=True, text=True).stdout.split('\n')
        w = out[0].split()
        if not w or w[0] != 'OK':
            print(f'{label}\t{wl}\t{case}\t{w[0] if w else "NOOUTPUT"}\t\t\t')
            continue
        entries = ' '.join(f'{x[1]}:{x[2]}={x[3]}' for x in (line.split() for line in out[1:]) if x and x[0] == 'MAP')
        print(f'{label}\t{wl}\t{case}\tOK\t{w[1]}\t{w[2] if len(w) > 2 else ""}\t{entries}')
