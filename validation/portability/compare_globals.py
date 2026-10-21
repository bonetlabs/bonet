#!/usr/bin/env python3
"""Check that every compiler produces the same asm globals.

The default build ships the XDP globals as BPF assembly (src/bnt_asm_globals.h),
so the code of each __bnt_*_g function must be byte for byte the same whatever
clang builds the program. Compares each global in each object with the same
global in the first object, and prints one line per object.

usage: compare_globals.py LABEL=OBJECT...   (tests/globals builds: globals.o)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'exec_metrics'))
from bpfsim import Elf  # noqa: E402


def globals_of(path):
    e = Elf(path)
    return {name: bytes(e.text[s * 8:(s + n) * 8]) for name, (s, n) in e.funcs.items()
            if name.startswith('__bnt_') and name.endswith('_g')}


if len(sys.argv) < 3:
    sys.exit(__doc__.strip().splitlines()[-1])
objs = [a.split('=', 1) for a in sys.argv[1:]]
ref_label, ref = objs[0][0], globals_of(objs[0][1])
bad = 0
print(f'{ref_label}: {len(ref)} globals (reference)')
for label, path in objs[1:]:
    g = globals_of(path)
    diff = sorted(n for n in ref if g.get(n) != ref[n])
    extra = sorted(set(g) - set(ref))
    if diff or extra:
        bad += 1
        print(f'{label}: {len(diff)} globals differ from {ref_label}: {" ".join(n[6:-2] for n in diff + extra)}')
    else:
        print(f'{label}: {len(g)} globals, same code as {ref_label}')
sys.exit(1 if bad else 0)
