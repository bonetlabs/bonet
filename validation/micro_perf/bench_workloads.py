#!/usr/bin/env python3
"""Time the XDP workload cases of ../exec_metrics/workloads.py in the kernel.

For each build (a directory with one <workload>.o per workload) and each case,
runs build/bench_prog through build/bench_wrap.o and prints one tab-separated
line: build, workload, case, the action and output packet of the check run,
the ns per packet of each round, and the packets that reached v1. The build
"ref" is added: build/ref/<ACTION>.o, a program that only takes the case's
action, timed on the same packet. A workload costs its time minus ref's.

XDP_TX and XDP_REDIRECT cases must deliver every packet (REPEAT x ROUNDS);
fewer means some took another path. Needs root, bpftool, and the network of
../exec_metrics/vm_net.sh run with build/sink.o; IFINDEX is what it prints.

usage: bench_workloads.py [-n REPEAT] [-r ROUNDS] IFINDEX LABEL=DIR... > bench.tsv
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'exec_metrics'))
from workloads import CASES  # noqa: E402

ACTION = {0: 'ABORTED', 1: 'DROP', 2: 'PASS', 3: 'TX', 4: 'REDIRECT'}

ap = argparse.ArgumentParser()
ap.add_argument('-n', type=int, default=500000)
ap.add_argument('-r', type=int, default=5)
ap.add_argument('ifindex')
ap.add_argument('builds', nargs='+', metavar='LABEL=DIR')
opt = ap.parse_args()


def seen(reset=False):
    """Packets counted by build/sink.o on v1."""
    out = subprocess.run(['bpftool', '-j', 'map', 'dump', 'name', 'seen'], capture_output=True, text=True).stdout
    if not out.strip():
        return None
    n = json.loads(out)[0]['value']
    if isinstance(n, list):  # without BTF bpftool prints the bytes
        n = int.from_bytes(bytes(int(x, 16) for x in n), 'little')
    if reset:
        subprocess.run(['bpftool', 'map', 'update', 'name', 'seen', 'key'] + ['0'] * 4 + ['value'] + ['0'] * 8,
                       capture_output=True)
    return n


print('build\tworkload\tcase\taction\tpacket\tns\tdelivered')
builds = [b.split('=', 1) for b in opt.builds] + [['ref', os.path.join(HERE, 'build', 'ref')]]
for label, d in builds:
    for wl, case, pkt, maps, want in CASES:
        obj = os.path.join(d, (ACTION[want] if label == 'ref' else wl) + '.o')
        if not os.path.exists(obj):
            continue
        seen(reset=True)
        args = [os.path.join(HERE, 'build', 'bench_prog'), '-n', str(opt.n), '-r', str(opt.r), '-i', opt.ifindex,
                '-w', os.path.join(HERE, 'build', 'bench_wrap.o'), obj, pkt.hex()]
        for m, entries in ({} if label == 'ref' else maps).items():
            for k, v in entries.items():
                args += [m, k.hex(), v.hex()]
        out = subprocess.run(args, capture_output=True, text=True).stdout.split('\n')
        check = out[0].split()
        if not check or check[0] != 'CHECK':
            print(f'{label}\t{wl}\t{case}\t{out[0]}\t\t\t')
            continue
        ns = ','.join(line.split()[1] for line in out[1:] if line.startswith('ROUND'))
        print(f'{label}\t{wl}\t{case}\t{check[1]}\t{check[2] if len(check) > 2 else ""}\t{ns}\t{seen()}')
