#!/usr/bin/env python3
"""Summary of matrix.sh: one line per kernel and compiler.

The first table counts what loaded and behaved as expected: the globals
(asm and C), the unit cases (asm and C, against tests/units/expected.json)
and the workloads (asm and C). The second gives, for the workloads of the
paper, the instructions the verifier processed and the stack depth reported
for the whole program (plain eBPF / asm globals / C globals).

usage: summary.py RESULTS_DIR      (OUT/results of matrix.sh)
"""
import csv
import os
import re
import sys

PAPER = ('xdp_mmlf', 'xdp_static_dnat', 'xdp_ip6ip6_encap')


def rows(path):
    if not os.path.exists(path):
        return []
    return [r for r in csv.DictReader(open(path), delimiter='\t') if r['object'] != 'object']


def count(rs, where):
    sel = [r for r in rs if where in r['object']]
    return f"{sum(r['ok'] == '1' for r in sel)}/{len(sel)}"


def units(path):
    """check.py prints '<variant>: N/M cases match' per variant."""
    out = {}
    if os.path.exists(path):
        for line in open(path):
            m = re.match(r'(\w+): (\d+/\d+) cases match', line)
            if m:
                out[m.group(1)] = m.group(2)
    return out


def paper(rs, where, prog, col):
    r = [x for x in rs if where in x['object'] and x['program'] == prog]
    if not r:
        return '-'
    return r[0][col] if r[0]['ok'] == '1' else 'FAIL'


def kernel_key(name):
    return [int(x) for x in re.findall(r'\d+', name)[:4]]


res = sys.argv[1]
kernels = sorted((k for k in os.listdir(res) if os.path.isdir(os.path.join(res, k))), key=kernel_key)
lines = []
for k in kernels:
    d = os.path.join(res, k)
    if not os.path.exists(os.path.join(d, 'done')):
        lines.append((k, None))
        continue
    for c in sorted(x for x in os.listdir(d) if os.path.isdir(os.path.join(d, x))):
        lines.append((k, os.path.join(d, c)))

print(f"{'kernel':18s} {'compiler':12s} {'globals asm':>11} {'C':>6} {'units asm':>10} {'C':>8} {'workloads asm':>13} {'C':>6}")
for k, d in lines:
    if d is None:
        print(f'{k:18s} did not finish')
        continue
    g, w = rows(f'{d}/globals.tsv'), rows(f'{d}/workloads.tsv')
    u = units(f'{d}/units.txt')
    print(f"{k:18s} {os.path.basename(d):12s} {count(g, 'globals.o'):>11} {count(g, 'globals_c.o'):>6} "
          f"{u.get('default', '?'):>10} {u.get('c', '?'):>8} {count(w, '/asm/'):>13} {count(w, '/c/'):>6}")

print()
print('Paper workloads: verifier instructions and stack bytes, plain / asm / C')
print(f"{'kernel':18s} {'compiler':12s} " + ' '.join(f'{p[4:]:>22s}' for p in PAPER))
for col, unit in (('processed', 'insns'), ('prog_stack_sum', 'stack')):
    for k, d in lines:
        if d is None:
            continue
        w, b = rows(f'{d}/workloads.tsv'), rows(f'{d}/baseline.tsv')
        cells = ['/'.join([paper(b, '/', p, col), paper(w, '/asm/', p, col), paper(w, '/c/', p, col)]) for p in PAPER]
        print(f"{k:18s} {os.path.basename(d):12s} " + ' '.join(f'{c:>22s}' for c in cells) + f'  {unit}')
