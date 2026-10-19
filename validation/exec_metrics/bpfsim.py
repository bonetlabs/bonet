"""BPF interpreter for the BONet XDP globals.

Runs one function of a BPF ELF object, as compiled, or of a program as the
verifier translated it (Xlated), and records:
  exec          executed BPF instructions, the called globals included (an
                LD_IMM64 counts once; a `ja +0` does not, since the verifier
                removes it)
  own_exec      the same, for the function called only, without the globals it
                calls
  by_class      executed instructions per class: alu32, alu64, endian, ldimm64,
                loads and stores per region (pkt, ctx, stack, mem), jcond, ja,
                nop (`ja +0`), call_global, call_helper:<id>, exit, mul, div;
                own_class is the same for the function called only
  calls         globals called by the function, by name, with how many times
  helper_bytes  bytes processed by bpf_csum_diff
  stack_max     deepest stack use of the active call chain, in bytes
  insns         the function's own executed instructions, raw, for mca.py
  all_insns     every executed instruction, the called globals included

It implements what the globals and the workload programs use: ALU/JMP/JMP32,
memory loads, stores and atomics, calls between functions (r6-r9 and r10
preserved), and the helpers bpf_csum_diff, bpf_xdp_adjust_head,
bpf_fib_lookup, bpf_map_lookup_elem (also as the verifier inlines it for a
hash map) and bpf_redirect. bpf_fib_lookup returns the code the test VM gives,
forwarding disabled, unless the object brings a result (progsim.Prog with
fib). check_interpreter.py checks it against results recorded from the
kernel.
"""
import struct, collections

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1

def s64(x): return x - (1 << 64) if x & (1 << 63) else x
def s32(x): x &= M32; return x - (1 << 32) if x & (1 << 31) else x


class Elf:
    """Just enough ELF64 parsing for a BPF relocatable object."""
    def __init__(self, path):
        d = self.d = open(path, 'rb').read()
        shoff, = struct.unpack_from('<Q', d, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from('<HHH', d, 0x3a)
        sh = [struct.unpack_from('<IIQQQQIIQQ', d, shoff + i * shentsize) for i in range(shnum)]
        names = sh[shstrndx]
        def secname(o): return d[names[4] + o:d.index(b'\0', names[4] + o)].decode()
        self.secs = {secname(s[0]): s for s in sh}
        self.sh = sh
        symtab = self.secs['.symtab']; strtab = sh[symtab[6]]
        self.syms = []
        for i in range(symtab[5] // 24):
            n, info, other, shndx, val, size = struct.unpack_from('<IBBHQQ', d, symtab[4] + i * 24)
            nm = d[strtab[4] + n:d.index(b'\0', strtab[4] + n)].decode()
            self.syms.append((nm, info, shndx, val, size))
        self.text_idx = [i for i, s in enumerate(sh) if secname(s[0]) == '.text'][0]
        t = self.secs['.text']
        self.text = d[t[4]:t[4] + t[5]]
        self.funcs = {nm: (val // 8, size // 8) for nm, info, shndx, val, size in self.syms
                      if (info & 0xf) == 2 and shndx == self.text_idx}
        self.func_at = {s: nm for nm, (s, n) in self.funcs.items()}
        self.calls = {}  # insn index in .text -> target insn index
        rel = self.secs.get('.rel.text')
        if rel:
            for i in range(rel[5] // 16):
                off, info = struct.unpack_from('<QQ', d, rel[4] + i * 16)
                nm, sinfo, shndx, val, size = self.syms[info >> 32]
                idx = off // 8
                imm = s32(struct.unpack_from('<i', self.text, off + 4)[0])
                if (sinfo & 0xf) == 2:
                    self.calls[idx] = val // 8
                else:  # section symbol: target relative to the section
                    self.calls[idx] = val // 8 + imm + 1


class Xlated:
    """A program as the verifier translated it: the raw instructions from
    bpf_prog_info, the start of each function, and the helper ids its calls
    refer to (the kernel replaces them with addresses; helpers maps each call
    immediate back to its id). Its context is struct xdp_buff, not xdp_md."""
    kernel_ctx = True

    def __init__(self, insns, funcs, helpers):
        t = bytearray(insns)
        self.calls = {}
        for i in range(0, len(t), 8):
            code, regs = t[i], t[i + 1]
            if code == 0x85 and regs >> 4 == 0:  # helper call
                imm = struct.unpack_from('<i', t, i + 4)[0]
                struct.pack_into('<i', t, i + 4, helpers[imm])
            elif code == 0x85 and regs >> 4 == 1:  # call between functions: off is the jump, imm the function's index
                self.calls[i // 8] = i // 8 + struct.unpack_from('<h', t, i + 2)[0] + 1
        self.text = bytes(t)
        n = len(t) // 8
        starts = sorted(funcs.values())
        self.funcs = {nm: (s, (starts[starts.index(s) + 1] if starts.index(s) + 1 < len(starts) else n) - s)
                      for nm, s in funcs.items()}
        self.func_at = {s: nm for nm, s in funcs.items()}


class Mem:
    def __init__(self):
        self.regions = []  # (base, bytearray, kind)
    def add(self, base, data, kind):
        self.regions.append((base, data, kind)); return base
    def find(self, addr, n):
        for base, buf, kind in self.regions:
            if base <= addr and addr + n <= base + len(buf):
                return buf, addr - base, kind
        raise RuntimeError(f'bad access {addr:#x}+{n}')
    def load(self, addr, n):
        buf, o, kind = self.find(addr, n)
        return int.from_bytes(buf[o:o + n], 'little'), kind
    def store(self, addr, n, v):
        buf, o, kind = self.find(addr, n)
        buf[o:o + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'little'); return kind


PKT, CTX, STACK, OUT = 0x10000000, 0x20000000, 0x30000000, 0x40000000
RXQ, DEV = 0x50000000, 0x60000000  # xdp_rxq_info and net_device, for Xlated
HEADROOM = 256
FRAME = 512


class Run:
    def __init__(self, elf, packet, out_size=256, max_steps=200000):
        self.elf = elf; self.mem = Mem(); self.max_steps = max_steps
        self.pkt = bytearray(HEADROOM) + bytearray(packet)
        self.mem.add(PKT, self.pkt, 'pkt')
        self.data = PKT + HEADROOM; self.data_end = PKT + len(self.pkt)
        self.ctx = bytearray(24); self.mem.add(CTX, self.ctx, 'ctx')
        self.out = bytearray(out_size); self.mem.add(OUT, self.out, 'mem')
        self.stack = bytearray(FRAME * 16); self.mem.add(STACK, self.stack, 'stack')
        self.c = collections.Counter(); self.exec = 0; self.helper_bytes = 0
        self.own = collections.Counter(); self.own_exec = 0; self.calls = collections.Counter()
        self.insns = []  # the same, raw (code, dst, src, off, imm, imm2), for mca.py
        self.all_insns = []  # every executed instruction, the called globals included
        # A whole program (progsim.Prog) brings its data sections, map values,
        # the values of its relocated LD_IMM64, its maps and a fib_lookup result.
        for base, buf, kind in getattr(elf, 'regions', ()):
            self.mem.add(base, buf, kind)
        self.ldimm = getattr(elf, 'ldimm', {})
        self.kernel_ctx = getattr(elf, 'kernel_ctx', False)
        self.depth_used = [0]; self.stack_max = 0
        self.trace = None

    def ctx_load(self, off, size):
        if self.kernel_ctx:  # struct xdp_buff, as the verifier rewrote the loads
            return {0: self.data, 8: self.data_end, 16: self.data, 24: PKT, 32: RXQ}.get(off, 0)
        # The verifier rewrites xdp_md loads into full 64-bit pointers.
        if off == 0: return self.data
        if off == 4: return self.data_end
        if off == 8: return self.data  # data_meta == data
        if off == 12: return 1        # ingress_ifindex
        return 0

    def call(self, name, args):
        start, _ = self.elf.funcs[name]
        r = [0] * 11
        for i, a in enumerate(args): r[1 + i] = a & M64
        r[10] = STACK + FRAME
        ret = self.exec_from(start, r, 0)
        return s32(ret)

    def note_stack(self, frame, addr, n):
        top = STACK + FRAME * (frame + 1)
        if STACK + FRAME * frame <= addr < top:
            used = top - addr
            if used > self.depth_used[frame]: self.depth_used[frame] = used
            self.stack_max = max(self.stack_max, sum(self.depth_used[:frame + 1]))

    def exec_from(self, pc, r, frame):
        t = self.elf.text
        c = collections.Counter()  # this call's own instructions, by class
        try:
            return self._exec(pc, r, frame, t, c)
        finally:
            self.c.update(c)
            if frame == 0:
                self.own.update(c)
                # mul and div are also counted as alu; nop is not an instruction
                self.own_exec = sum(c.values()) - c['nop'] - c['mul'] - c['div']

    def _exec(self, pc, r, frame, t, c):
        while True:
            if self.exec > self.max_steps: raise RuntimeError('step limit')
            code, regs, off, imm = struct.unpack_from('<BBhi', t, pc * 8)
            dst, src = regs & 0xf, regs >> 4
            cls = code & 7; self.exec += 1
            ins = (code, dst, src, off, imm, struct.unpack_from('<i', t, pc * 8 + 12)[0] if code == 0x18 else 0)
            self.all_insns.append(ins)
            if frame == 0:
                self.insns.append(ins)
            if self.trace is not None: self.trace.append((pc, list(r)))
            if cls in (4, 7):  # ALU / ALU64
                op = code & 0xf0; is64 = cls == 7
                if op == 0xd0:  # endian
                    c['endian'] += 1
                    v = r[dst]
                    if code & 0x08:  # to big endian
                        v = int.from_bytes((v & ((1 << imm) - 1)).to_bytes(imm // 8, 'little'), 'big')
                    else:
                        v &= (1 << imm) - 1
                    r[dst] = v; pc += 1; continue
                b = r[src] if code & 0x08 else (imm & M64 if is64 else imm & M32)
                a = r[dst] if is64 else r[dst] & M32
                if not is64: b &= M32
                m = M64 if is64 else M32; bits = 64 if is64 else 32
                sa = s64(a) if is64 else s32(a)
                if op == 0x00: v = a + b
                elif op == 0x10: v = a - b
                elif op == 0x20: v = a * b; c['mul'] += 1
                elif op == 0x30: v = a // b if b else 0; c['div'] += 1
                elif op == 0x40: v = a | b
                elif op == 0x50: v = a & b
                elif op == 0x60: v = a << (b & (bits - 1))
                elif op == 0x70: v = a >> (b & (bits - 1))
                elif op == 0x80: v = -a
                elif op == 0x90: v = a % b if b else a; c['div'] += 1
                elif op == 0xa0: v = a ^ b
                elif op == 0xb0: v = b
                elif op == 0xc0: v = sa >> (b & (bits - 1))
                else: raise RuntimeError(f'alu op {code:#x}')
                r[dst] = v & m
                c['alu64' if is64 else 'alu32'] += 1; pc += 1; continue
            if cls == 0:  # LD_IMM64
                lo = imm & M32; hi = struct.unpack_from('<i', t, pc * 8 + 12)[0] & M32
                r[dst] = self.ldimm.get(pc, lo | (hi << 32)); c['ldimm64'] += 1; pc += 2; continue
            if cls in (1, 2, 3):
                size = {0x00: 4, 0x08: 2, 0x10: 1, 0x18: 8}[code & 0x18]
                if cls == 3 and (code & 0xe0) == 0xc0:  # atomic
                    addr = (r[dst] + off) & M64
                    old, kind = self.mem.load(addr, size)
                    m = (1 << (8 * size)) - 1
                    v = r[src] & m
                    op = imm & ~1
                    if op == 0xe0: new = v                                  # xchg
                    elif op == 0xf0:                                        # cmpxchg
                        new = v if old == r[0] & m else old
                        r[0] = old
                    else: new = {0x00: old + v, 0x40: old | v, 0x50: old & v, 0xa0: old ^ v}[op] & m
                    self.mem.store(addr, size, new)
                    if imm & 1 and op not in (0xe0, 0xf0): r[src] = old
                    elif op == 0xe0: r[src] = old
                    c['atomic_' + kind] += 1
                    pc += 1; continue
                if (code & 0xe0) != 0x60: raise RuntimeError(f'mode {code:#x}')
                if cls == 1:
                    addr = (r[src] + off) & M64
                    if CTX <= addr < CTX + (64 if self.kernel_ctx else 24):
                        r[dst] = self.ctx_load(addr - CTX, size); kind = 'ctx'
                    elif self.kernel_ctx and RXQ <= addr < RXQ + 64:
                        r[dst] = DEV if addr == RXQ else 0; kind = 'ctx'
                    elif self.kernel_ctx and DEV <= addr < DEV + 4096:
                        r[dst] = 1; kind = 'ctx'  # only ifindex is read
                    else:
                        r[dst], kind = self.mem.load(addr, size)
                    self.note_stack(frame, addr, size)
                    c['ld_' + kind] += 1
                else:
                    addr = (r[dst] + off) & M64
                    v = r[src] if cls == 3 else imm & M64
                    kind = self.mem.store(addr, size, v)
                    self.note_stack(frame, addr, size)
                    c['st_' + kind] += 1
                pc += 1; continue
            if cls in (5, 6):
                op = code & 0xf0; is32 = cls == 6
                if op == 0x90:  # exit
                    c['exit'] += 1; return r[0]
                if op == 0x80:  # call
                    if src == 1:
                        c['call_global'] += 1
                        tgt = self.elf.calls.get(pc, pc + imm + 1)
                        if frame == 0:
                            self.calls[self.elf.func_at.get(tgt, f'pc{tgt}')] += 1
                        saved = r[6:11]
                        if len(self.depth_used) <= frame + 1: self.depth_used.append(0)
                        self.depth_used[frame + 1] = 0
                        nr = r[:]; nr[10] = STACK + FRAME * (frame + 2)
                        r0 = self.exec_from(tgt, nr, frame + 1)
                        r = r[:6] + saved; r[0] = r0
                        for k in (1, 2, 3, 4, 5): r[k] = 0xdeadbeef  # clobbered
                    else:
                        c[f'call_helper:{imm}'] += 1
                        r[0] = self.helper(imm, r) & M64
                        for k in (1, 2, 3, 4, 5): r[k] = 0xdeadbeef
                    pc += 1; continue
                if op == 0x00:
                    if off == 0 and not is32:  # nop; the verifier removes it
                        self.exec -= 1; c['nop'] += 1; pc += 1; continue
                    c['ja'] += 1; pc += off + 1; continue
                a = r[dst]; b = r[src] if code & 0x08 else imm & M64
                if is32: a &= M32; b &= M32
                sa, sb = (s32(a), s32(b)) if is32 else (s64(a), s64(b))
                take = {0x10: a == b, 0x20: a > b, 0x30: a >= b, 0x40: bool(a & b), 0x50: a != b,
                        0x60: sa > sb, 0x70: sa >= sb, 0xa0: a < b, 0xb0: a <= b,
                        0xc0: sa < sb, 0xd0: sa <= sb}[op]
                c['jcond'] += 1
                pc += off + 1 if take else 1; continue
            raise RuntimeError(f'opcode {code:#x}')

    def helper(self, hid, r):
        if hid == 28:  # bpf_csum_diff(from, from_size, to, to_size, seed)
            frm, fs, to, ts, seed = r[1], r[2] & M32, r[3], r[4] & M32, r[5] & M32
            if fs % 4 or ts % 4 or fs + ts > 512: return (-22) & M64
            s = seed
            for i in range(0, fs, 4): s += (~self.mem.load(frm + i, 4)[0]) & M32
            for i in range(0, ts, 4): s += self.mem.load(to + i, 4)[0]
            while s >> 32: s = (s & M32) + (s >> 32)
            # Kernel 7.0 returns the sum folded to 16 bits (end-around carry), the
            # same on every architecture; checked against BPF_PROG_TEST_RUN.
            while s >> 16: s = (s & 0xffff) + (s >> 16)
            self.helper_bytes += fs + ts
            return s
        if hid == 44:  # bpf_xdp_adjust_head(ctx, delta)
            nd = self.data + s32(r[2])
            if nd < PKT + 40 or nd > self.data_end - 14: return (-22) & M64
            self.data = nd; return 0
        if hid == 69:  # bpf_fib_lookup(ctx, params, plen, flags)
            fib = getattr(self.elf, 'fib', None)
            if fib is None:
                return 5  # stub: the test VM has forwarding off (FWD_DISABLED)
            # The routes the workload VM is set up with (fib['routes']: family,
            # prefix bytes, prefix length); no route: BPF_FIB_LKUP_RET_NOT_FWDED.
            fam = self.mem.load(r[2], 1)[0]
            n = 4 if fam == 2 else 16
            dst = bytes(self.mem.load(r[2] + 32 + i, 1)[0] for i in range(n))
            bits = lambda b: ''.join(f'{x:08b}' for x in b)
            if not any(f == fam and bits(dst)[:ln] == bits(pfx)[:ln] for f, pfx, ln in fib['routes']):
                return 4
            self.mem.store(r[2] + 8, 4, fib['ifindex'])
            for i, b in enumerate(fib['smac'] + fib['dmac']):
                self.mem.store(r[2] + 52 + i, 1, b)
            return 0
        if hid == 1001:  # __htab_map_lookup_elem: the verifier inlines a hash map lookup
            # as this call followed by r0 += offsetof(htab_elem, key) + the
            # rounded key size; return the element, so that r0 ends at the value
            m = self.elf.maps[r[1]]
            key = bytes(self.mem.load(r[2] + i, 1)[0] for i in range(m.key_size))
            v = m.values.get(key, 0)
            return v - (48 + (m.key_size + 7) // 8 * 8) if v else 0  # 48: offsetof(htab_elem, key) on 7.0
        if hid == 1:  # bpf_map_lookup_elem(map, key)
            m = self.elf.maps[r[1]]
            key = bytes(self.mem.load(r[2] + i, 1)[0] for i in range(m.key_size))
            return m.values.get(key, 0)
        if hid == 23:  # bpf_redirect(ifindex, flags)
            return 4 if r[2] == 0 else 0  # XDP_REDIRECT
        raise RuntimeError(f'helper {hid}')

    def metrics(self):
        return dict(exec=self.exec, stack_max=self.stack_max, helper_bytes=self.helper_bytes,
                    by_class=dict(self.c))
