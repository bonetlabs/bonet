#!/usr/bin/env python3
"""Executed-instruction metrics of the XDP workload programs.

For each build and each case of workloads.py, runs the whole program in the
interpreter (progsim.Prog: the program and every global it calls), and, with
--xlated, the program as the verifier translated it. Both are compared with
the kernel's result from workload_kernel.py. Writes one CSV row per build and
case:

  action, same_as_kernel          interpreter's action; whether action,
                                  packet and map entries match the kernel
  exec, main_exec, globals_exec   instructions executed by the whole program,
                                  by the program's own code, by the globals
  ld, st, mul                     loads, stores (atomics included), mul
  helper_calls, global_calls
  mca_skylake, mca_znver3         llvm-mca cycles of the executed path
  xl_exec, xl_same_as_kernel, xl_mca_skylake, xl_mca_znver3
                                  the same on the translated code

--xlated DIR holds DIR/<label>/<object>/<program>.xlated, .funcs and .maps
(verifier_stats -x DIR/<label> on each build) and DIR/kallsyms.txt from the
same boot. --ifindex is the one vm_net.sh printed in the kernel run: the
forwarding cases write it in the packet path.

usage: workload_metrics.py --kernel TSV [--xlated DIR --ifindex N] [-o CSV] LABEL=DIR...
"""
import argparse
import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mca  # noqa: E402
from bpfsim import CTX, PKT, Run  # noqa: E402
from common import xlated_helpers  # noqa: E402
from progsim import Prog, XProg  # noqa: E402
from workloads import CASES, FIB  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument('--kernel', required=True)
ap.add_argument('--xlated')
ap.add_argument('--ifindex', type=int, default=0)
ap.add_argument('-o', default='-')
ap.add_argument('builds', nargs='+', metavar='LABEL=DIR')
opt = ap.parse_args()

kernel = {}
for r in csv.DictReader(open(opt.kernel), delimiter='\t'):
    kernel[(r['build'], r['workload'], r['case'])] = r
helpers = xlated_helpers(opt.xlated) if opt.xlated else None
fib = dict(FIB, ifindex=opt.ifindex)


def run(prog, pkt):
    r = Run(prog, pkt)
    ret = r.call(prog.entry, [CTX])
    out = bytes(r.pkt[r.data - PKT:r.data_end - PKT]).hex()
    return r, ret, out


def map_entries(prog):
    """{map:key: value hex} after a run, as workload_kernel.py prints them."""
    at = {base: buf for base, buf, kind in prog.regions}
    return {f'{m.name}:{k.hex()}': bytes(at[a]).hex() for m in prog.maps.values() for k, a in m.values.items()}


def same(k, ret, out, entries):
    want = dict(e.split('=', 1) for e in k['maps'].split()) if k['maps'] else {}
    return int(int(ret) == int(k['action']) and out == k['packet']
               and all(entries.get(key) == v for key, v in want.items()))


cols = ['build', 'workload', 'case', 'action', 'same_as_kernel', 'exec', 'main_exec', 'globals_exec',
        'ld', 'st', 'mul', 'helper_calls', 'global_calls', 'mca_skylake', 'mca_znver3',
        'xl_exec', 'xl_same_as_kernel', 'xl_mca_skylake', 'xl_mca_znver3']
f = sys.stdout if opt.o == '-' else open(opt.o, 'w', newline='')
w = csv.DictWriter(f, fieldnames=cols)
w.writeheader()
for b in opt.builds:
    label, d = b.split('=', 1)
    for wl, case, pkt, maps, want in CASES:
        obj = os.path.join(d, wl + '.o')
        k = kernel.get((label, wl, case))
        if not os.path.exists(obj) or not k or k['status'] != 'OK':
            continue  # not built, or rejected by the verifier
        p = Prog(obj, maps, fib)
        r, ret, out = run(p, pkt)
        c = r.c
        row = dict(build=label, workload=wl, case=case, action=ret, same_as_kernel=same(k, ret, out, map_entries(p)),
                   exec=r.exec, main_exec=r.own_exec, globals_exec=r.exec - r.own_exec,
                   ld=sum(v for n, v in c.items() if n.startswith('ld_')),
                   st=sum(v for n, v in c.items() if n.startswith(('st_', 'atomic_'))),
                   mul=c['mul'], helper_calls=sum(v for n, v in c.items() if n.startswith('call_helper')),
                   global_calls=c['call_global'],
                   mca_skylake=mca.cycles(r.all_insns, 'skylake'), mca_znver3=mca.cycles(r.all_insns, 'znver3'))
        if opt.xlated:
            xp = XProg(Prog(obj, maps, fib), os.path.join(opt.xlated, label, os.path.basename(obj), p.entry), helpers)
            y, yret, yout = run(xp, pkt)
            row.update(xl_exec=y.exec, xl_same_as_kernel=int(int(yret) == int(k['action']) and yout == k['packet']),
                       xl_mca_skylake=mca.cycles(y.all_insns, 'skylake'), xl_mca_znver3=mca.cycles(y.all_insns, 'znver3'))
        w.writerow(row)
