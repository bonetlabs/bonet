#!/usr/bin/env python3
"""Branch coverage of the API cases, with the interpreter (no root needed).

Runs every case of every API on validation/exec_metrics/bpfsim.py and records,
for each conditional jump, whether it was taken, not taken, or both. Reports:
  - per API, the branches of its own code (the inline wrapper, in `run`);
  - per global, the branches of its asm, over the cases of every API.
Each conditional jump counts as two branches.

usage: coverage.py BUILD [--uncovered]   (--uncovered lists the missing ones)
"""
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..', '..', 'validation', 'exec_metrics'))
import cases as C  # noqa: E402
from bpfsim import CTX, Run  # noqa: E402
from progsim import Prog  # noqa: E402


def is_cond_jump(code):
    return code & 7 in (5, 6) and code & 0xf0 not in (0x00, 0x80, 0x90)


def main():
    build = sys.argv[1]
    apis = json.load(open(os.path.join(build, 'gen', 'apis.json')))
    taken = collections.defaultdict(set)    # (function, insn offset) -> {True, False}
    jumps = collections.defaultdict(set)    # function -> insn offsets of its conditional jumps
    users = collections.defaultdict(set)    # global -> APIs whose cases reach it
    errors = collections.Counter()
    for name, sig in sorted(apis.items()):
        prog = Prog(os.path.join(build, 'obj', name + '.o'))
        data = prog.region_names.index('.data')
        starts = sorted((s, fn) for fn, (s, n) in prog.funcs.items())
        owner = {}
        for s, fn in starts:
            key = name if fn == prog.entry else fn
            for i in range(s, s + prog.funcs[fn][1]):
                owner[i] = (key, i - s)
                if is_cond_jump(prog.text[i * 8]):
                    jumps[key].add(i - s)
        for label, pkt, io in C.cases(name, sig):
            prog.regions[data][1][:] = io
            r = Run(prog, pkt)
            r.trace = []
            try:
                r.call(prog.entry, [CTX])
            except Exception as ex:  # an unknown helper or a bad access: the kernel would have rejected it
                errors[(name, str(ex)[:60])] += 1
            tr = r.trace
            for i in range(len(tr) - 1):
                pc = tr[i][0]
                if is_cond_jump(prog.text[pc * 8]):
                    taken[owner[pc]].add(tr[i + 1][0] != pc + 1)
                    if owner[pc][0] != name:
                        users[owner[pc][0]].add(name)

    def cov(fn):
        n = len(jumps[fn]) * 2
        return sum(len(taken[(fn, o)]) for o in jumps[fn]), n

    show = '--uncovered' in sys.argv
    tot = [0, 0]
    print('== API wrappers (inline code in run)')
    for name in sorted(apis):
        h, n = cov(name)
        tot[0] += h
        tot[1] += n
        if h < n:
            print(f'{name:48s} {h:4d}/{n:<4d}')
    print(f'wrappers: {tot[0]}/{tot[1]} = {100 * tot[0] / max(tot[1], 1):.1f}%\n')
    tot = [0, 0]
    print('== globals (asm)')
    for fn in sorted(f for f in jumps if f not in apis):
        h, n = cov(fn)
        tot[0] += h
        tot[1] += n
        print(f'{fn[6:-2]:30s} {h:4d}/{n:<4d} {100 * h / max(n, 1):5.1f}%  ({len(users[fn])} APIs)')
        if show and h < n:
            miss = [f'{o}{"" if True in taken[(fn, o)] else "t"}{"" if False in taken[(fn, o)] else "f"}'
                    for o in sorted(jumps[fn]) if len(taken[(fn, o)]) < 2]
            print('    missing (insn, t: never taken, f: never fell through):', ' '.join(miss))
    print(f'globals: {tot[0]}/{tot[1]} = {100 * tot[0] / max(tot[1], 1):.1f}%')
    if errors:
        print('\ninterpreter errors:', dict(errors.most_common(10)))


main()
