"""Print a function of a BPF ELF object as clang BPF assembly (pseudo-C syntax),
with jumps to .L labels, calls between functions by name, and `ja +0` dropped
(the verifier removes it anyway)."""
import struct, sys
sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from bpfsim import Elf

ALU = {0x00: '+=', 0x10: '-=', 0x20: '*=', 0x30: '/=', 0x40: '|=', 0x50: '&=', 0x60: '<<=', 0x70: '>>=',
       0x90: '%=', 0xa0: '^=', 0xb0: '=', 0xc0: 's>>='}
JMP = {0x10: '==', 0x20: '>', 0x30: '>=', 0x40: '&', 0x50: '!=', 0x60: 's>', 0x70: 's>=', 0xa0: '<',
       0xb0: '<=', 0xc0: 's<', 0xd0: 's<='}
SZ = {0x00: 'u32', 0x08: 'u16', 0x10: 'u8', 0x18: 'u64'}


def call_targets(elf):
    """insn index in .text -> name of the function a relocated call goes to."""
    d = elf.d
    out = {}
    rel = elf.secs.get('.rel.text')
    if not rel:
        return out
    for i in range(rel[5] // 16):
        off, info = struct.unpack_from('<QQ', d, rel[4] + i * 16)
        nm, sinfo, shndx, val, size = elf.syms[info >> 32]
        if (sinfo & 0xf) != 2:
            raise ValueError(f'call through a section symbol at {off}: not a named function')
        out[off // 8] = nm
    return out


def mem(r, off):
    return f'(r{r} + {off})' if off >= 0 else f'(r{r} - {-off})'


def function(elf, name, label_prefix):
    start, n = elf.funcs[name]
    t = elf.text
    calls = call_targets(elf)
    insns, targets = [], set()
    i = start
    while i < start + n:
        code, regs, off, imm = struct.unpack_from('<BBhi', t, i * 8)
        insns.append((i, code, regs & 0xf, regs >> 4, off, imm))
        if code & 7 in (5, 6) and code & 0xf0 not in (0x80, 0x90):
            targets.add(i + off + 1)
        i += 2 if code == 0x18 else 1
    lab = lambda k: f'.L{label_prefix}_{k - start}'
    out = []
    for i, code, d, s, off, imm in insns:
        if i in targets:
            out.append(lab(i) + ':')
        cls, op = code & 7, code & 0xf0
        if cls in (4, 7):
            R = 'r' if cls == 7 else 'w'
            if op == 0xd0:
                assert cls == 4, 'bswap (v4) not expected'
                out.append(f'r{d} = {"be" if code & 0x08 else "le"}{imm} r{d}')
                continue
            assert off == 0, f'{name}: v4 ALU form (off={off})'
            if op == 0x80:
                out.append(f'{R}{d} = -{R}{d}')
                continue
            rhs = f'{R}{s}' if code & 0x08 else str(imm)
            out.append(f'{R}{d} {ALU[op]} {rhs}')
        elif cls == 0:
            assert code == 0x18 and s == 0, f'{name}: LD_IMM64 with a relocation'
            hi = struct.unpack_from('<i', t, i * 8 + 12)[0]
            v = (imm & 0xffffffff) | ((hi & 0xffffffff) << 32)
            out.append(f'r{d} = {v:#x} ll')
        elif cls == 1:
            assert code & 0xe0 == 0x60, f'{name}: load mode {code:#x}'
            out.append(f'{"r" if code & 0x18 == 0x18 else "w"}{d} = *({SZ[code & 0x18]} *){mem(s, off)}')
        elif cls == 2:
            assert code & 0xe0 == 0x60, f'{name}: store mode {code:#x}'
            out.append(f'*({SZ[code & 0x18]} *){mem(d, off)} = {imm}')
        elif cls == 3:
            assert code & 0xe0 == 0x60, f'{name}: store mode {code:#x}'
            out.append(f'*({SZ[code & 0x18]} *){mem(d, off)} = {"r" if code & 0x18 == 0x18 else "w"}{s}')
        else:
            if op == 0x90:
                out.append('exit')
            elif op == 0x80:
                if s == 1:
                    out.append(f'call {calls[i]}')
                else:
                    assert s == 0, f'{name}: kfunc call'
                    out.append(f'call {imm}')
            elif op == 0x00:
                assert cls == 5, f'{name}: gotol (v4)'
                if off:
                    out.append(f'goto {lab(i + off + 1)}')
            else:
                R = 'w' if cls == 6 else 'r'
                rhs = f'{R}{s}' if code & 0x08 else str(imm)
                out.append(f'if {R}{d} {JMP[op]} {rhs} goto {lab(i + off + 1)}')
    end = start + n
    if end in targets:
        raise ValueError(f'{name}: jump past the end')
    return out


if __name__ == '__main__':
    e = Elf(sys.argv[1])
    print('\n'.join(function(e, sys.argv[2], 'x')))
