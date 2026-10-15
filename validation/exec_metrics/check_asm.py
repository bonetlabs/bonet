#!/usr/bin/env python3
"""Check the shipped asm globals against the configurations chosen for them.

For each global in OBJ (default: tests/globals/build/globals.o, the default
build, which uses src/bnt_asm_globals.h):
- its code must be the chosen configuration's, apart from the `ja +0` that
  the asm drops (jumps are compared by the instruction they reach);
- its BTF FUNC must have global linkage and named parameters (bpftool).

usage: check_asm.py [--choices FILE] [--objs DIR] [OBJ]
"""
import argparse
import os
import re
import struct
import subprocess
import sys

from bpfsim import Elf

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
ap = argparse.ArgumentParser()
ap.add_argument('--choices', default=os.path.join(HERE, 'data', 'choices-kernel7.0.txt'))
ap.add_argument('--objs', default=os.path.join(HERE, 'results', 'objs'))
ap.add_argument('obj', nargs='?', default=os.path.join(REPO, 'tests', 'globals', 'build', 'globals.o'))
opt = ap.parse_args()

choice = {}
for line in open(opt.choices):
    if ':' in line:
        g, c = line.split(':', 1)
        choice[f'__bnt_{g.strip()}_g'] = c.split('(')[0].strip()


def code(elf, g):
    """The function's instructions without `ja +0`, jumps as target positions."""
    s, n = elf.funcs[g]
    t, raw, i = elf.text, [], s
    while i < s + n:
        c, regs, off, imm = struct.unpack_from('<BBhi', t, i * 8)
        w = 2 if c == 0x18 else 1
        raw.append((i, c, regs, off, t[i * 8:(i + w) * 8]))
        i += w
    nop = lambda r: r[1] == 0x05 and r[3] == 0
    pos, k = {}, 0
    for r in raw:
        pos[r[0]] = k
        k += not nop(r)
    pos[s + n] = k
    return [(c, regs, 'to', pos[i + off + 1]) if c & 7 in (5, 6) and c & 0xf0 not in (0x80, 0x90) else (c, regs, b)
            for i, c, regs, off, b in raw if not nop((i, c, regs, off))]


bad = 0
asm = Elf(opt.obj)
objs = {}
for g, c in sorted(choice.items()):
    if c not in objs:
        objs[c] = Elf(os.path.join(opt.objs, c + '.o'))
    if g not in asm.funcs:
        print(f'{g}: missing from {opt.obj}')
        bad += 1
    elif code(asm, g) != code(objs[c], g):
        print(f'{g}: code differs from {c}')
        bad += 1

btf = subprocess.run(['bpftool', 'btf', 'dump', 'file', opt.obj, 'format', 'raw'],
                     check=True, capture_output=True, text=True).stdout
types, cur = {}, None
for line in btf.splitlines():
    m = re.match(r"\[(\d+)\] (\w+) '([^']*)'(.*)", line)
    if m:
        cur = int(m.group(1))
        types[cur] = (m.group(2), m.group(3), m.group(4), [])
    elif cur and line.startswith('\t'):
        types[cur][3].append(line.strip())
funcs = {name: rest for kind, name, rest, _ in types.values() if kind == 'FUNC' and name in choice}
for g in sorted(choice):
    rest = funcs.get(g)
    if rest is None:
        print(f'{g}: no BTF FUNC')
        bad += 1
        continue
    proto = types[int(re.search(r'type_id=(\d+)', rest).group(1))]
    if 'linkage=global' not in rest:
        print(f'{g}: BTF linkage is not global')
        bad += 1
    if any("'(anon)'" in p for p in proto[3]):
        print(f'{g}: BTF parameters without names')
        bad += 1
print(f'{len(choice)} globals: {"all match" if not bad else f"{bad} problems"}')
sys.exit(1 if bad else 0)
