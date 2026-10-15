"""Estimated cycles of an executed BPF path, computed by llvm-mca.

The BPF instructions a global executed (bpfsim Run.insns) are lowered to x86-64
the way the kernel's x86 JIT lowers them (arch/x86/net/bpf_jit_comp.c): the
same register mapping, movzx for 8- and 16-bit loads, ror+movzx for a 16-bit
byte swap, shlx/shrx/sarx for shifts by a register (CPUs with BMI2), cmp or test
plus a conditional jump for each branch. llvm-mca then schedules that sequence
on a CPU model (ports, latencies, dispatch width, register dependencies) and
gives the total cycles of one pass.

Not modelled: the function's prologue and epilogue, time inside helpers and
called globals (their calls are the same in every build), branch
mispredictions, cache misses. llvm-mca assumes loads and stores do not alias,
so a value stored and read back at once (a spill) costs the store and the load
but no forwarding delay.

usage: mca.cycles(insns, cpu) -> int
"""
import hashlib
import subprocess

MCA = 'llvm-mca-20'
R64 = ['rax', 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'rbx', 'r13', 'r14', 'r15', 'rbp']
R32 = ['eax', 'edi', 'esi', 'edx', 'ecx', 'r8d', 'ebx', 'r13d', 'r14d', 'r15d', 'ebp']
R16 = ['ax', 'di', 'si', 'dx', 'cx', 'r8w', 'bx', 'r13w', 'r14w', 'r15w', 'bp']
R8 = ['al', 'dil', 'sil', 'dl', 'cl', 'r8b', 'bl', 'r13b', 'r14b', 'r15b', 'bpl']
ALU = {0x00: 'add', 0x10: 'sub', 0x40: 'or', 0x50: 'and', 0xa0: 'xor'}
SHIFT = {0x60: 'shl', 0x70: 'shr', 0xc0: 'sar'}
JCC = {0x10: 'je', 0x20: 'ja', 0x30: 'jae', 0x40: 'jne', 0x50: 'jne', 0x60: 'jg', 0x70: 'jge',
       0xa0: 'jb', 0xb0: 'jbe', 0xc0: 'jl', 0xd0: 'jle'}
SIZE = {0x00: 4, 0x08: 2, 0x10: 1, 0x18: 8}


def lower(insns):
    out = []
    for code, d, s, off, imm, imm2 in insns:
        cls, op = code & 7, code & 0xf0
        if cls in (4, 7):
            q = cls == 7
            R = R64 if q else R32
            x = 'q' if q else 'l'
            if op == 0xd0:
                if code & 0x08:  # to big endian
                    if imm == 16:
                        out += [f'rorw $8, %{R16[d]}', f'movzwl %{R16[d]}, %{R32[d]}']
                    elif imm == 32:
                        out.append(f'bswapl %{R32[d]}')
                    else:
                        out.append(f'bswapq %{R64[d]}')
                elif imm == 16:
                    out.append(f'movzwl %{R16[d]}, %{R32[d]}')
                elif imm == 32:
                    out.append(f'movl %{R32[d]}, %{R32[d]}')
                continue
            reg = code & 0x08
            if op in ALU:
                out.append(f'{ALU[op]}{x} %{R[s]}, %{R[d]}' if reg else f'{ALU[op]}{x} ${imm}, %{R[d]}')
            elif op == 0xb0:
                if reg:
                    out.append(f'mov{x} %{R[s]}, %{R[d]}')
                elif imm == 0:
                    out.append(f'xorl %{R32[d]}, %{R32[d]}')
                else:
                    out.append(f'mov{x} ${imm}, %{R[d]}')
            elif op == 0x20:
                out.append(f'imul{x} %{R[s]}, %{R[d]}' if reg else f'imul{x} ${imm}, %{R[d]}, %{R[d]}')
            elif op in SHIFT:
                out.append(f'{SHIFT[op]}x{x} %{R[s]}, %{R[d]}, %{R[d]}' if reg else f'{SHIFT[op]}{x} ${imm & (63 if q else 31)}, %{R[d]}')
            elif op == 0x80:
                out.append(f'neg{x} %{R[d]}')
            elif op in (0x30, 0x90):  # div/mod: the JIT saves rax/rdx around a div
                out += ['pushq %rax', 'pushq %rdx', f'mov{x} %{R[d]}, %{R[0]}', 'xorl %edx, %edx',
                        f'div{x} %{R[s]}' if reg else f'div{x} %r11', f'mov{x} %{(R[0] if op == 0x30 else R[3])}, %r11',
                        'popq %rdx', 'popq %rax', f'mov{x} %r11, %{R[d]}']
        elif cls == 0:  # LD_IMM64
            v = (imm & 0xffffffff) | ((imm2 & 0xffffffff) << 32)
            out.append(f'movabsq ${v}, %{R64[d]}')
        elif cls == 1:
            n = SIZE[code & 0x18]
            out.append({1: f'movzbl {off}(%{R64[s]}), %{R32[d]}', 2: f'movzwl {off}(%{R64[s]}), %{R32[d]}',
                        4: f'movl {off}(%{R64[s]}), %{R32[d]}', 8: f'movq {off}(%{R64[s]}), %{R64[d]}'}[n])
        elif cls == 2:
            n = SIZE[code & 0x18]
            out.append(f'mov{ {1: "b", 2: "w", 4: "l", 8: "q"}[n]} ${imm}, {off}(%{R64[d]})')
        elif cls == 3:
            n = SIZE[code & 0x18]
            r = {1: R8, 2: R16, 4: R32, 8: R64}[n][s]
            out.append(f'mov{ {1: "b", 2: "w", 4: "l", 8: "q"}[n]} %{r}, {off}(%{R64[d]})')
        elif cls in (5, 6):
            if op == 0x00:
                if off or cls == 6:
                    out.append('jmp .Lt')
                continue  # ja +0 is removed by the verifier
            if op == 0x90:
                out.append('retq')
                continue
            if op == 0x80:
                out.append('callq .Lt')
                continue
            x = 'l' if cls == 6 else 'q'
            R = R32 if cls == 6 else R64
            cmp = 'test' if op == 0x40 else 'cmp'
            out.append(f'{cmp}{x} %{R[s]}, %{R[d]}' if code & 0x08 else f'{cmp}{x} ${imm}, %{R[d]}')
            out.append(f'{JCC[op]} .Lt')
    return out


_cache = {}


def cycles(insns, cpu):
    asm = '\n'.join(lower(insns))
    key = (cpu, hashlib.sha1(asm.encode()).hexdigest())
    if key not in _cache:
        src = asm + '\n.Lt:\n'
        r = subprocess.run([MCA, '-mtriple=x86_64', f'-mcpu={cpu}', '-iterations=1', '-summary-view',
                            '-instruction-info=false', '-resource-pressure=false'],
                           input=src, capture_output=True, text=True)
        tot = [line for line in r.stdout.splitlines() if line.startswith('Total Cycles:')]
        if not tot:
            raise RuntimeError(f'llvm-mca failed: {r.stderr.strip()[:200]}')
        _cache[key] = int(tot[0].split()[-1])
    return _cache[key]
