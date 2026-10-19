"""Load a whole BPF program from its object, for bpfsim.Run.

As libbpf does: the program's section comes first and .text (the globals and
other functions it calls) after it; calls and LD_IMM64 are resolved through the
relocations; data sections (.rodata, .data, .bss) get a copy in memory; each
map gets a handle, and a lookup returns a pointer into its value storage.

Prog(path, maps={name: {key: value}}, fib=None)
  maps  initial contents, keys and values as bytes
  fib   None for the FWD_DISABLED stub, or dict(ifindex, smac, dmac, routes):
        bpf_fib_lookup succeeds, with that result, for a destination in one of
        the routes, (family, prefix bytes, prefix length) as workloads.FIB
"""
import struct

DATA = 0x70000000   # data sections, 1 MiB apart
MAPS = 0x80000000   # map handles
VALS = 0x90000000   # map values


class Map:
    def __init__(self, name, key_size, value_size):
        self.name, self.key_size, self.value_size = name, key_size, value_size
        self.values = {}  # key bytes -> address of the value


class Prog:
    def __init__(self, path, maps=None, fib=None):
        d = self.d = open(path, 'rb').read()
        shoff, = struct.unpack_from('<Q', d, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from('<HHH', d, 0x3a)
        sh = [struct.unpack_from('<IIQQQQIIQQ', d, shoff + i * shentsize) for i in range(shnum)]
        name = lambda o: d[sh[shstrndx][4] + o:d.index(b'\0', sh[shstrndx][4] + o)].decode()
        names = [name(s[0]) for s in sh]
        symtab = sh[names.index('.symtab')]
        strtab = sh[symtab[6]]
        syms = []
        for i in range(symtab[5] // 24):
            n, info, other, shndx, val, size = struct.unpack_from('<IBBHQQ', d, symtab[4] + i * 24)
            syms.append((d[strtab[4] + n:d.index(b'\0', strtab[4] + n)].decode(), info, shndx, val, size))

        # Executable sections: the program's own first, then .text.
        exe = [i for i, s in enumerate(sh) if s[2] & 0x4 and s[5]]
        prog_secs = [i for i in exe if names[i] != '.text']
        assert len(prog_secs) == 1, f'{path}: expected one program section, got {[names[i] for i in prog_secs]}'
        order = prog_secs + [i for i in exe if names[i] == '.text']
        base, text = {}, b''
        for i in order:
            base[i] = len(text) // 8
            text += d[sh[i][4]:sh[i][4] + sh[i][5]]
        self.text = text
        self.funcs = {nm: (base[shndx] + val // 8, size // 8) for nm, info, shndx, val, size in syms
                      if (info & 0xf) == 2 and shndx in base}
        self.func_at = {s: nm for nm, (s, n) in self.funcs.items()}
        self.entry = [nm for nm, info, shndx, val, size in syms if (info & 0xf) == 2 and shndx == prog_secs[0]][0]

        # Data sections and maps.
        self.regions, data_at, self.region_names = [], {}, []
        for i, s in enumerate(sh):
            if s[2] & 0x2 and not s[2] & 0x4 and names[i].startswith(('.rodata', '.data', '.bss')):
                buf = bytearray(s[5]) if s[1] == 8 else bytearray(d[s[4]:s[4] + s[5]])  # SHT_NOBITS
                data_at[i] = DATA + len(data_at) * 0x100000
                self.regions.append((data_at[i], buf, 'data'))
                self.region_names.append(names[i])
        maps_sec = names.index('.maps') if '.maps' in names else -1
        self.maps, handle = {}, {}
        contents = maps or {}
        for nm, info, shndx, val, size in syms:
            if shndx == maps_sec and (info & 0xf) == 1:
                entries = contents.get(nm, {})
                k = next(iter(entries), b'')
                m = Map(nm, len(k), len(entries[k]) if entries else 0)
                for key, value in entries.items():
                    addr = VALS + len(self.regions) * 0x10000
                    self.regions.append((addr, bytearray(value), 'map'))
                    self.region_names.append(nm)
                    m.values[key] = addr
                h = MAPS + len(handle) * 0x1000
                handle[nm] = h
                self.maps[h] = m
        self.map_handle = handle

        # Relocations: calls to functions, LD_IMM64 of maps and data.
        self.calls, self.ldimm = {}, {}
        for i in order:
            rname = '.rel' + names[i]
            if rname not in names:
                continue
            r = sh[names.index(rname)]
            for k in range(r[5] // 16):
                off, info = struct.unpack_from('<QQ', d, r[4] + k * 16)
                snm, sinfo, sshndx, sval, ssize = syms[info >> 32]
                idx = base[i] + off // 8
                code = text[idx * 8]
                imm = struct.unpack_from('<i', text, idx * 8 + 4)[0]
                if code == 0x85:
                    if (sinfo & 0xf) == 2:
                        self.calls[idx] = base[sshndx] + sval // 8
                    else:
                        self.calls[idx] = base[sshndx] + sval // 8 + imm + 1
                elif code == 0x18:
                    if sshndx == maps_sec:
                        self.ldimm[idx] = handle[snm]
                    elif sshndx in data_at:
                        self.ldimm[idx] = data_at[sshndx] + sval + imm
                    else:
                        raise ValueError(f'{path}: LD_IMM64 to {snm} in section {names[sshndx]}')
        self.fib = fib


HTAB_KEY = 48  # offsetof(struct htab_elem, key), kernel 7.0 (vmlinux BTF)


class XProg:
    """A whole program as the verifier translated it (verifier_stats -x), with
    the data sections, maps and fib result of the matching Prog. LD_IMM64 of
    maps and map values come as (map id, offset) and are resolved through
    <program>.maps; the inlined lookup of a hash map calls
    __htab_map_lookup_elem, which returns the element, before the key."""
    kernel_ctx = True

    def __init__(self, prog, path, helpers):
        t = bytearray(open(path + '.xlated', 'rb').read())
        funcs = dict((n, int(s)) for n, s in (line.split() for line in open(path + '.funcs')))
        ids = {}
        try:
            for line in open(path + '.maps'):
                i, n = line.split(None, 1)
                ids[int(i)] = n.strip()
        except FileNotFoundError:
            pass
        sec_at = {}  # data section name -> address in prog.regions
        for (base, buf, kind), name in zip(prog.regions, prog.region_names):
            if kind == 'data':
                sec_at[name] = base
        self.calls, self.ldimm = {}, {}
        for i in range(0, len(t), 8):
            code, regs = t[i], t[i + 1]
            src = regs >> 4
            if code == 0x85 and src == 0:
                imm = struct.unpack_from('<i', t, i + 4)[0]
                struct.pack_into('<i', t, i + 4, helpers[imm])
            elif code == 0x85 and src == 1:
                self.calls[i // 8] = i // 8 + struct.unpack_from('<h', t, i + 2)[0] + 1
            elif code == 0x18 and src in (1, 2):
                mid = struct.unpack_from('<i', t, i + 4)[0]
                off = struct.unpack_from('<i', t, i + 12)[0]
                name = ids[mid]
                if src == 1:   # the map itself
                    self.ldimm[i // 8] = next(h for nm, h in prog.map_handle.items() if nm.startswith(name))
                else:          # a value: .rodata, .data or .bss
                    sec = name if name in sec_at else next(s for s in sec_at if name.endswith(s))
                    self.ldimm[i // 8] = sec_at[sec] + off
        self.text = bytes(t)
        n = len(t) // 8
        starts = sorted(funcs.values())
        self.funcs = {nm: (s, (starts[starts.index(s) + 1] if starts.index(s) + 1 < len(starts) else n) - s)
                      for nm, s in funcs.items()}
        self.func_at = {s: nm for nm, s in funcs.items()}
        self.entry = prog.entry
        self.regions, self.maps, self.fib, self.map_handle = prog.regions, prog.maps, prog.fib, prog.map_handle
