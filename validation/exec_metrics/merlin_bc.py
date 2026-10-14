#!/usr/bin/env python3
"""Run Merlin's bytecode optimizer on each function of a BPF object.

Merlin (https://github.com/4ar0nma0/Merlin) is not part of this repository:
pass the path of a clone. Its Python/optimize.py needs numpy. Its own driver
(BPFProg) reads and writes the ELF with lief and runs the optimizer once per
function symbol on the whole section, so a section holding many globals gets
optimized many times over. Here each function goes through optimize.Section
once, and the bytes are written back in place: Merlin keeps every instruction
slot (it writes `ja +0` nops), so offsets and relocations stay valid.

usage: merlin_bc.py MERLIN_DIR IN.o OUT.o
"""
import os
import struct
import sys
import types

merlin, src, dst = sys.argv[1:4]
sys.modules['lief'] = types.ModuleType('lief')  # only BPFProg uses it
sys.path.insert(0, os.path.join(merlin, 'Python'))
from optimize import Section  # noqa: E402

d = bytearray(open(src, 'rb').read())
shoff, = struct.unpack_from('<Q', d, 0x28)
shentsize, shnum, shstrndx = struct.unpack_from('<HHH', d, 0x3a)
sh = [struct.unpack_from('<IIQQQQIIQQ', d, shoff + i * shentsize) for i in range(shnum)]


def name(tab, off):
    return d[tab + off:d.index(b'\0', tab + off)].decode()


text = [i for i, s in enumerate(sh) if name(sh[shstrndx][4], s[0]) == '.text'][0]
symtab = [s for s in sh if s[1] == 2][0]
strtab = sh[symtab[6]][4]
funcs = []
for i in range(symtab[5] // 24):
    n, info, other, shndx, val, size = struct.unpack_from('<IBBHQQ', d, symtab[4] + i * 24)
    if (info & 0xf) == 2 and shndx == text and size:
        funcs.append((name(strtab, n), val, size))

changed = failed = 0
for fn, val, size in funcs:
    a = sh[text][4] + val
    old = bytes(d[a:a + size])
    try:
        new = bytes(Section(old.hex(), fn).dump())
    except Exception as ex:
        print(f'{fn}: Merlin failed ({type(ex).__name__}), left as is', file=sys.stderr)
        failed += 1
        continue
    assert len(new) == size
    if new != old:
        d[a:a + size] = new
        changed += 1
open(dst, 'wb').write(d)
print(f'{dst}: {changed} of {len(funcs)} functions changed, {failed} failed')
