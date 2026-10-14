#!/usr/bin/env python3
"""Write one CSV row per (configuration, case) with the metrics of each global.

Each configuration is a label and an object containing every global (as
tests/globals/build/globals.o does). The interpreter gives what only running
the code can: executed instructions, by class, csum bytes and the stack used on
that path. With --verifier, which takes the output of verifier_stats on the
same objects, each row also gets what the kernel reports (columns k_*): whether
it loaded, the verifier error, the verifier stats, the stack depth, and the
size of the global after the verifier (instructions) and after the JIT (bytes).
With --ref, each row says whether the case produced the same result as the
reference object.

usage: collect.py -o OUT.csv [--ref REF.o] [--verifier TSV] LABEL=OBJ...
example: collect.py -o results/clang.csv --ref c20.o --verifier vs.tsv clang20=c20.o clang22=c22.o
"""
import argparse
import csv
import os

from common import CASES, run_case
from bpfsim import Elf

KERNEL = ['processed', 'max_states_per_insn', 'total_states', 'peak_states', 'verif_usec', 'subprogs',
          'stack', 'xlated_insns', 'jited_bytes']

ap = argparse.ArgumentParser()
ap.add_argument('-o', '--out', required=True)
ap.add_argument('--ref')
ap.add_argument('--verifier')
ap.add_argument('configs', nargs='+', metavar='LABEL=OBJ')
opt = ap.parse_args()

kern = {}  # (object basename, global) -> row of verifier_stats
if opt.verifier:
    for r in csv.DictReader(open(opt.verifier), delimiter='\t'):
        if r['program'].startswith('c__bnt_'):
            kern[(os.path.basename(r['object']), r['program'][len('c__bnt_'):-len('_g')])] = r

ref = {}
if opt.ref:
    r = Elf(opt.ref)
    for g, label, pkt, args, pre in CASES:
        x = run_case(r, g, pkt, args, pre)
        ref[(g, label)] = (x.get('error'), x.get('ret'), x.get('out'), x.get('pkt'))

rows, classes = [], set()
for cfg in opt.configs:
    name, path = cfg.split('=', 1)
    elf = Elf(path)
    for g, label, pkt, args, pre in CASES:
        x = run_case(elf, g, pkt, args, pre)
        row = dict(config=name, object=path, global_fn=g, case=label,
                   static_insns=elf.funcs[f'__bnt_{g}_g'][1],
                   exec_insns=x['exec'], sim_stack_max=x.get('stack_max', ''),
                   helper_bytes=x.get('helper_bytes', ''), ret=x.get('ret', ''),
                   error=x.get('error', ''))
        if opt.verifier:
            k = kern.get((os.path.basename(path), g))
            row['loaded'] = '' if k is None else int(k['ok'] == '1')
            row['k_error'] = '' if k is None else k['error']
            for c in KERNEL:
                row['k_' + c] = '' if k is None else (k.get(c) or '')
        if opt.ref:
            row['same_as_ref'] = int(ref[(g, label)] == (x.get('error'), x.get('ret'), x.get('out'), x.get('pkt')))
        for k, v in x.get('by_class', {}).items():
            row['n_' + k] = v
            classes.add('n_' + k)
        rows.append(row)

order = ['config', 'object', 'global_fn', 'case', 'static_insns', 'exec_insns', 'sim_stack_max',
         'helper_bytes', 'ret', 'error', 'same_as_ref', 'loaded', 'k_error'] + ['k_' + c for c in KERNEL]
present = set().union(*(r.keys() for r in rows))
fields = [f for f in order if f in present] + sorted(classes)
os.makedirs(os.path.dirname(os.path.abspath(opt.out)), exist_ok=True)
with open(opt.out, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields, restval=0)
    w.writeheader()
    w.writerows(rows)
print(f'{opt.out}: {len(rows)} rows, {len(opt.configs)} configurations')
