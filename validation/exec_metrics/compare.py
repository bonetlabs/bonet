#!/usr/bin/env python3
"""Compare two builds of the globals case by case: results and executed insns.

Each object must contain every global, as tests/globals/build/globals.o does.
Prints the cases whose result or instruction count changed, then a summary.

usage: compare.py OLD.o NEW.o
"""
import sys

from common import CASES, run_case
from bpfsim import Elf

old, new = Elf(sys.argv[1]), Elf(sys.argv[2])
better = worse = differ = 0
total = [0, 0]
for g, label, pkt, args, pre in CASES:
    a, b = run_case(old, g, pkt, args, pre), run_case(new, g, pkt, args, pre)
    key = lambda r: (r.get('error'), r.get('ret'), r.get('out'), r.get('pkt'))
    same = key(a) == key(b)
    total[0] += a['exec']
    total[1] += b['exec']
    better += b['exec'] < a['exec']
    worse += b['exec'] > a['exec']
    differ += not same
    if not same or a['exec'] != b['exec']:
        print(f"{g + '/' + label:34s} {a['exec']:5d} -> {b['exec']:5d}" + ('' if same else '  RESULT DIFFERS'))
print(f'{len(CASES)} cases: {better} fewer insns, {worse} more, {differ} different results; '
      f'total {total[0]} -> {total[1]}')
