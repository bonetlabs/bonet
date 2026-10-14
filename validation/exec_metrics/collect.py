#!/usr/bin/env python3
"""Write one CSV row per (configuration, case) with the interpreter's metrics.

Each configuration is a label and an object containing every global (as
tests/globals/build/globals.o does). With --ref, each row also says whether the
case produced the same result as the reference object.

usage: collect.py -o OUT.csv [--ref REF.o] LABEL=OBJ...
example: collect.py -o results/clang.csv --ref c20.o clang20=c20.o clang22=c22.o
"""
import argparse
import csv
import os

from common import CASES, run_case
from bpfsim import Elf

ap = argparse.ArgumentParser()
ap.add_argument('-o', '--out', required=True)
ap.add_argument('--ref')
ap.add_argument('configs', nargs='+', metavar='LABEL=OBJ')
opt = ap.parse_args()

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
                   exec_insns=x['exec'], stack_max=x.get('stack_max', ''),
                   helper_bytes=x.get('helper_bytes', ''), ret=x.get('ret', ''),
                   error=x.get('error', ''))
        if opt.ref:
            row['same_as_ref'] = int(ref[(g, label)] == (x.get('error'), x.get('ret'), x.get('out'), x.get('pkt')))
        for k, v in x.get('by_class', {}).items():
            row['n_' + k] = v
            classes.add('n_' + k)
        rows.append(row)

fields = list(rows[0].keys() - set(classes))
fields = [f for f in ['config', 'object', 'global_fn', 'case', 'static_insns', 'exec_insns', 'stack_max',
                      'helper_bytes', 'ret', 'error', 'same_as_ref'] if f in fields] + sorted(classes)
os.makedirs(os.path.dirname(os.path.abspath(opt.out)), exist_ok=True)
with open(opt.out, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields, restval=0)
    w.writeheader()
    w.writerows(rows)
print(f'{opt.out}: {len(rows)} rows, {len(opt.configs)} configurations')
