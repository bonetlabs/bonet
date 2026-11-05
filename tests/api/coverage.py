#!/usr/bin/env python3
"""Branch coverage of the library's C code by the API cases (no root needed).

The programs are built from the C globals at -O1 with debug info (make
coverage builds them in BUILD/cov) and run on validation/exec_metrics/bpfsim.py.
Each conditional jump in the library headers is mapped to its source position
(file, line, column), so the copies the compiler makes of a condition (inlined
functions, unrolled loops) count as one. Only functions a program can call
count: the globals no public API reaches are left out. Each condition counts as
two branches.

usage: coverage.py BUILD [--uncovered]   (--uncovered lists the missing ones)
"""
import collections
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..', '..', 'validation', 'exec_metrics'))
import cases as C  # noqa: E402
from bpfsim import CTX, Run  # noqa: E402
from progsim import Prog  # noqa: E402

LIBRARY = ('bnt_core.h', 'bnt_xdp.h', 'bnt_rw.h')
DWARFDUMP = os.environ.get('LLVM_DWARFDUMP', 'llvm-dwarfdump')


def is_cond_jump(code):
    return code & 7 in (5, 6) and code & 0xf0 not in (0x00, 0x80, 0x90)


def line_tables(path):
    """{end address: [(address, file, line, column)]}, one per section."""
    out = subprocess.run([DWARFDUMP, '--debug-line', path], capture_output=True, text=True, check=True).stdout
    files, seqs, rows, fi = {}, {}, [], None
    for line in out.split('\n'):
        m = re.match(r'file_names\[\s*(\d+)\]:', line)
        if m:
            fi = int(m.group(1))
            continue
        m = re.match(r'\s+name: "(.*)"', line)
        if m and fi is not None:
            files[fi] = os.path.basename(m.group(1))
            continue
        m = re.match(r'0x([0-9a-f]+)\s+(\d+)\s+(\d+)\s+(\d+)\s', line)
        if m:
            addr = int(m.group(1), 16)
            if 'end_sequence' in line:
                seqs[addr] = rows
                rows = []
            else:
                rows.append((addr, files.get(int(m.group(4))), int(m.group(2)), int(m.group(3))))
    return seqs


def main():
    build = sys.argv[1]
    apis = json.load(open(os.path.join(build, 'gen', 'apis.json')))
    taken = collections.defaultdict(set)    # (file, line, column) -> {True, False}
    errors = collections.Counter()
    for name, sig in sorted(apis.items()):
        path = os.path.join(build, 'cov', name + '.o')
        prog = Prog(path)
        data = prog.region_names.index('.data')
        tables = line_tables(path)
        prog_len = prog.funcs[prog.entry][1]    # the program's section, laid out first, holds only the entry

        def position(pc):
            sec_len, addr = (prog_len, pc) if pc < prog_len else (len(prog.text) // 8 - prog_len, pc - prog_len)
            best = None
            for row in tables.get(sec_len * 8, []):
                if row[0] > addr * 8:
                    break
                best = row
            return best[1:] if best else None

        fn_at = {}
        for fn, (s, n) in prog.funcs.items():
            for i in range(s, s + n):
                fn_at[i] = fn
        reach, todo = {prog.entry}, [prog.entry]
        while todo:
            s, n = prog.funcs[todo.pop()]
            for i in range(s, s + n):
                fn = fn_at.get(prog.calls.get(i))
                if fn and fn not in reach:
                    reach.add(fn)
                    todo.append(fn)
        where = {}
        for fn in reach:
            s, n = prog.funcs[fn]
            for i in range(s, s + n):
                if is_cond_jump(prog.text[i * 8]):
                    p = position(i)
                    if p and p[0] in LIBRARY and p[1]:
                        where[i] = p
                        taken.setdefault(p, set())

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
                if pc in where:
                    taken[where[pc]].add(tr[i + 1][0] != pc + 1)

    hit = sum(len(v) for v in taken.values())
    print(f'{len(taken)} conditions, branches: {hit}/{2 * len(taken)} = {100 * hit / max(2 * len(taken), 1):.1f}%')
    if '--uncovered' in sys.argv:
        src = {f: open(os.path.join(HERE, '..', '..', 'src', f)).read().split('\n') for f in LIBRARY}
        for (f, line, col), t in sorted(taken.items()):
            if len(t) < 2:
                side = 'never reached' if not t else 'never taken' if True not in t else 'always taken'
                print(f'{f}:{line}:{col}\t{side}\t{src[f][line - 1].strip()}')
    if errors:
        print('\ninterpreter errors:', dict(errors.most_common(10)))


main()
