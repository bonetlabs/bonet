#!/usr/bin/env python3
"""Time each global on its tests/units cases with bench_prog, in the kernel.

Takes directories of case programs (case_<n>.o, as tests/units builds them or
as ../exec_metrics/candidates.py writes them under cases/<label>/). Those
programs return XDP_PASS, whose skb costs more, and varies more, than the
global itself, so each one is copied with the return value changed to
XDP_DROP before timing. The build "ref" is build/ref_case.o, which only stores
the result as the case programs do: subtract it to get the cost of the call.

Prints one tab-separated line per build and case: build, case number, case
name, the action of the check run, the ns per packet of each round. CASES_JSON
is tests/units/build/gen/cases.json. Needs root and the network of
../exec_metrics/vm_net.sh (for the fib cases); IFINDEX is what it prints.

usage: bench_globals.py [-n REPEAT] [-r ROUNDS] CASES_JSON IFINDEX LABEL=DIR... > bench.tsv
"""
import argparse
import json
import os
import struct
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def to_drop(src, dst):
    """Copy an object, making every "r0 = XDP_PASS; exit" of section xdp return XDP_DROP."""
    b = bytearray(open(src, 'rb').read())
    shoff, = struct.unpack_from('<Q', b, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', b, 0x3a)
    sh = [struct.unpack_from('<IIQQQQ', b, shoff + i * shentsize) for i in range(shnum)]
    names = sh[shstrndx][4]
    n = 0
    for name, _, _, _, off, size in sh:
        if b[names + name:b.index(0, names + name)] != b'xdp':
            continue
        for i in range(off, off + size - 8, 8):
            if b[i] in (0xb4, 0xb7) and b[i + 1] == 0 and b[i + 4:i + 8] == b'\2\0\0\0' and b[i + 8] == 0x95:
                b[i + 4] = 1
                n += 1
    if not n:
        raise SystemExit(f'{src}: no XDP_PASS return found')
    open(dst, 'wb').write(b)


ap = argparse.ArgumentParser()
ap.add_argument('-n', type=int, default=500000)
ap.add_argument('-r', type=int, default=5)
ap.add_argument('cases')
ap.add_argument('ifindex')
ap.add_argument('builds', nargs='+', metavar='LABEL=DIR')
opt = ap.parse_args()

cases = json.load(open(opt.cases))
tmp = tempfile.mkdtemp()
ref = os.path.join(HERE, 'build', 'ref_case.o')


def bench(obj, pkt):
    args = [os.path.join(HERE, 'build', 'bench_prog'), '-n', str(opt.n), '-r', str(opt.r), '-i', opt.ifindex,
            '-w', os.path.join(HERE, 'build', 'bench_wrap.o'), obj, pkt]
    out = subprocess.run(args, capture_output=True, text=True).stdout.split('\n')
    check = out[0].split()
    if not check or check[0] != 'CHECK':
        return out[0], ''
    return check[1], ','.join(line.split()[1] for line in out[1:] if line.startswith('ROUND'))


print('build\tn\tcase\taction\tns')
for c in cases:
    print('ref\t%d\t%s\t%s\t%s' % (c['n'], c['name'], *bench(ref, c['pkt'])), flush=True)
for b in opt.builds:
    label, d = b.split('=', 1)
    for c in cases:
        src = os.path.join(d, 'case_%d.o' % c['n'])
        if not os.path.exists(src):
            continue
        obj = os.path.join(tmp, 'case.o')
        to_drop(src, obj)
        print('%s\t%d\t%s\t%s\t%s' % (label, c['n'], c['name'], *bench(obj, c['pkt'])), flush=True)
