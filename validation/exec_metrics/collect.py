#!/usr/bin/env python3
"""Write one CSV row per (configuration, case) with the metrics of each global.

Each configuration is a label and an object containing every global (as
tests/globals/build/globals.o does). The interpreter gives what only running
the code can: executed instructions, by class, csum bytes and the stack used on
that path. exec_insns and the n_* columns count the global's own instructions;
exec_total adds those of the globals it calls, which calls lists. With --verifier, which takes the output of verifier_stats on the
same objects, each row also gets what the kernel reports (columns k_*): whether
it loaded, the verifier error, the verifier stats, the stack depth, and the
size of the global after the verifier (instructions) and after the JIT (bytes).
With --ref, each row says whether the case produced the same result as the
reference object, as the interpreter sees it. With --kernel-cases, which takes
the output of kernel_cases.py, each row says how the kernel ran the case:
k_status, k_ret, k_same_as_expected (the kernel's result against
tests/units/expected.json) and sim_same_as_kernel (the interpreter's result
against the kernel's, same configuration).

With --xlated, the directory verifier_stats -x wrote, the interpreter also
runs each case on the global as the verifier translated it (columns xl_*: own
instructions, with the called globals, reads, writes, mul, and whether the
result matches the kernel's).

With --mca CPU[,CPU...] (llvm-mca CPU names, e.g. skylake,znver3), each row
also gets the cycles llvm-mca estimates for the global's own executed path
lowered to x86-64 as the kernel's JIT does (mca.py): mca_<cpu> on the compiled
code and, with --xlated, xl_mca_<cpu> on the translated code.

usage: collect.py -o OUT.csv [--ref REF.o] [--verifier TSV] [--kernel-cases TSV] [--xlated DIR] [--mca CPUS] LABEL=OBJ...
example: collect.py -o results/clang.csv --ref c20.o --verifier vs.tsv clang20=c20.o clang22=c22.o
"""
import argparse
import csv
import json
import os
from concurrent.futures import ThreadPoolExecutor

import mca

from common import CASES, UNITS, differences, load_xlated, run_case, xlated_helpers
from bpfsim import Elf

KERNEL = ['processed', 'max_states_per_insn', 'total_states', 'peak_states', 'verif_usec', 'subprogs',
          'stack', 'xlated_insns', 'jited_bytes']

ap = argparse.ArgumentParser()
ap.add_argument('-o', '--out', required=True)
ap.add_argument('--ref')
ap.add_argument('--verifier')
ap.add_argument('--kernel-cases')
ap.add_argument('--xlated')
ap.add_argument('--mca', default='')
ap.add_argument('-j', type=int, default=os.cpu_count())
ap.add_argument('configs', nargs='+', metavar='LABEL=OBJ')
opt = ap.parse_args()

kern = {}  # (object basename, global) -> row of verifier_stats
if opt.verifier:
    for r in csv.DictReader(open(opt.verifier), delimiter='\t'):
        if r['program'].startswith('c__bnt_'):
            kern[(os.path.basename(r['object']), r['program'][len('c__bnt_'):-len('_g')])] = r

kcases = {}  # (label, case) -> row of kernel_cases.py
if opt.kernel_cases:
    for r in csv.DictReader(open(opt.kernel_cases), delimiter='\t'):
        kcases[(r['config'], r['case'])] = r
    expected = json.load(open(os.path.join(UNITS, 'expected.json')))


def as_result(r):
    return dict(ret=int(r['ret']), out=bytes.fromhex(r['out']), pkt=bytes.fromhex(r['pkt']))


ref = {}
if opt.ref:
    r = Elf(opt.ref)
    for g, label, pkt, args, pre in CASES:
        x = run_case(r, g, pkt, args, pre)
        ref[(g, label)] = (x.get('error'), x.get('ret'), x.get('out'), x.get('pkt'))

helpers = xlated_helpers(opt.xlated) if opt.xlated else None


def count(by_class, prefix):
    return sum(v for k, v in by_class.items() if k.startswith(prefix))


CPUS = [c for c in opt.mca.split(',') if c]


def one_config(cfg):
    rows = []
    name, path = cfg.split('=', 1)
    elf = Elf(path)
    xl = {}
    for g, label, pkt, args, pre in CASES:
        x = run_case(elf, g, pkt, args, pre)
        row = dict(config=name, object=os.path.basename(path), global_fn=g, case=label,
                   static_insns=elf.funcs[f'__bnt_{g}_g'][1],
                   exec_insns=x['exec'], exec_total=x.get('exec_total', ''), calls=x.get('calls', ''),
                   sim_stack_max=x.get('stack_max', ''),
                   helper_bytes=x.get('helper_bytes', ''), ret=x.get('ret', ''),
                   error=x.get('error', ''))
        if opt.verifier:
            k = kern.get((os.path.basename(path), g))
            row['loaded'] = '' if k is None else int(k['ok'] == '1')
            row['k_error'] = '' if k is None else k['error']
            for c in KERNEL:
                row['k_' + c] = '' if k is None else (k.get(c) or '')
        if opt.kernel_cases:
            k = kcases.get((name, f'{g}/{label}'))
            row['k_status'] = '' if k is None else k['status']
            row['k_ret'] = k['ret'] if k and k['status'] == 'OK' else ''
            row['k_same_as_expected'] = row['sim_same_as_kernel'] = ''
            if k and k['status'] == 'OK':
                kr = as_result(k)
                row['k_same_as_expected'] = int(not differences(g, kr, as_result(expected[f'{g}/{label}'])))
                if 'error' not in x:
                    row['sim_same_as_kernel'] = int(not differences(g, x, kr))
        if opt.xlated:
            if g not in xl:
                xl[g] = load_xlated(opt.xlated, path, g, helpers)
            for c in ['xl_exec_insns', 'xl_exec_total', 'xl_ld', 'xl_st', 'xl_mul', 'xl_same_as_kernel']:
                row[c] = ''
            if xl[g] is not None:
                y = run_case(xl[g], g, pkt, args, pre)
                if 'error' in y:
                    row['xl_same_as_kernel'] = 0
                else:
                    row.update(xl_exec_insns=y['exec'], xl_exec_total=y['exec_total'],
                               xl_ld=count(y['by_class'], 'ld_'), xl_st=count(y['by_class'], 'st_'),
                               xl_mul=y['by_class'].get('mul', 0))
                    k = kcases.get((name, f'{g}/{label}'))
                    if k and k['status'] == 'OK':
                        row['xl_same_as_kernel'] = int(not differences(g, y, as_result(k)))
                    for cpu in CPUS:
                        row[f'xl_mca_{cpu}'] = mca.cycles(y['insns'], cpu)
            for cpu in CPUS:
                row.setdefault(f'xl_mca_{cpu}', '')
        for cpu in CPUS:
            row[f'mca_{cpu}'] = mca.cycles(x['insns'], cpu) if 'error' not in x else ''
        if opt.ref:
            row['same_as_ref'] = int(ref[(g, label)] == (x.get('error'), x.get('ret'), x.get('out'), x.get('pkt')))
        for k, v in x.get('by_class', {}).items():
            row['n_' + k] = v
        rows.append(row)
    return rows


rows = []
with ThreadPoolExecutor(opt.j) as ex:
    for part in ex.map(one_config, opt.configs):
        rows += part
classes = {k for r in rows for k in r if k.startswith('n_')}

order = ['config', 'object', 'global_fn', 'case', 'static_insns', 'exec_insns', 'exec_total', 'calls',
         'sim_stack_max',
         'helper_bytes', 'ret', 'error', 'same_as_ref', 'loaded', 'k_error', 'k_status', 'k_ret',
         'k_same_as_expected', 'sim_same_as_kernel'] + ['k_' + c for c in KERNEL] + \
        ['xl_exec_insns', 'xl_exec_total', 'xl_ld', 'xl_st', 'xl_mul', 'xl_same_as_kernel'] + \
        [f'mca_{c}' for c in CPUS] + [f'xl_mca_{c}' for c in CPUS]
present = set().union(*(r.keys() for r in rows))
fields = [f for f in order if f in present] + sorted(classes)
os.makedirs(os.path.dirname(os.path.abspath(opt.out)), exist_ok=True)
with open(opt.out, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields, restval=0)
    w.writeheader()
    w.writerows(rows)
print(f'{opt.out}: {len(rows)} rows, {len(opt.configs)} configurations')
