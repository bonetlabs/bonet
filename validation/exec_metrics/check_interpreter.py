#!/usr/bin/env python3
"""Check the interpreter against the kernel.

Runs every case of tests/units with the interpreter, on the objects that
tests/units built, and compares with tests/units/expected.json, which holds the
results the kernel produced. Build them first with `make -C tests/units`.

usage: check_interpreter.py [default|strict]
"""
import json
import os
import sys

from common import CASES, UNITS, differences, run_case
from bpfsim import Elf

variant = sys.argv[1] if len(sys.argv) > 1 else 'default'
expected = json.load(open(os.path.join(UNITS, 'expected.json')))

bad = 0
for n, (g, label, pkt, args, pre) in enumerate(CASES):
    name = f'{g}/{label}'
    obj = os.path.join(UNITS, 'build', variant, f'case_{n}.o')
    if not os.path.exists(obj):
        sys.exit(f'{obj} missing: run make -C tests/units first')
    got, e = run_case(Elf(obj), g, pkt, args, pre), expected[name]
    if 'error' in got:
        print(f'{name}: interpreter error: {got["error"]}')
        bad += 1
        continue
    d = differences(g, got, dict(ret=e['ret'], out=bytes.fromhex(e['out']), pkt=bytes.fromhex(e['pkt'])))
    if d:
        print(f'{name}: ' + '; '.join(d) + ' (interpreter vs kernel)')
        bad += 1
print(f'{variant}: {len(CASES) - bad}/{len(CASES)} cases match the kernel')
sys.exit(1 if bad else 0)
