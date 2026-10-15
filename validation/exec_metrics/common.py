"""Shared helpers: the case list from tests/units, one interpreted run, and the
comparison of two results."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
UNITS = os.path.join(REPO, 'tests', 'units')
sys.path.insert(0, UNITS)

from bpfsim import PKT, Run, Xlated  # noqa: E402
from cases import CASES, COMPARE  # noqa: E402,F401


def run_case(elf, g, pkt, args, pre):
    """Run __bnt_<g>_g on pkt; return what the call produced and its metrics:
    exec and by_class count the global's own instructions, exec_total also those
    of the globals it calls (listed in calls)."""
    r = Run(elf, pkt)
    r.out[:len(pre)] = pre
    try:
        ret = r.call(f'__bnt_{g}_g', args)
    except Exception as ex:  # unknown opcode, bad access, step limit
        return dict(error=str(ex), exec=r.exec)
    calls = ';'.join(f'{n[6:-2] if n.startswith("__bnt_") else n}:{k}' for n, k in sorted(r.calls.items()))
    return dict(ret=ret, out=bytes(r.out), pkt=bytes(r.pkt[r.data - PKT:r.data_end - PKT]),
                exec=r.own_exec, exec_total=r.exec, calls=calls, stack_max=r.stack_max,
                helper_bytes=r.helper_bytes, by_class=dict(r.own), insns=r.insns)


def fold16(b):
    s = int.from_bytes(b[:4], 'little')
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return s


def differences(g, a, b):
    """What differs between two results of global g (dicts with ret, out, pkt
    as bytes), compared as tests/units does: the fib globals' buffer is not
    compared, the checksum globals' sum only after folding to 16 bits."""
    d = []
    if a['ret'] != b['ret']:
        d.append(f"ret {a['ret']} vs {b['ret']}")
    if a['pkt'] != b['pkt']:
        d.append('packet differs')
    mode = COMPARE.get(g)
    if mode == 'csum32':
        if fold16(a['out']) != fold16(b['out']):
            d.append('checksum differs')
    elif mode != 'no_out' and a['out'] != b['out']:
        d.append('buffer differs')
    return d


HELPERS = [('bpf_csum_diff', 28), ('bpf_xdp_adjust_head', 44), ('bpf_xdp_fib_lookup', 69)]


def xlated_helpers(xdir):
    """Helper call immediates in the translated code -> helper ids, from the
    kallsyms.txt written by the same boot (the kernel stores the helper's
    address minus __bpf_call_base, which changes with every boot)."""
    ks = {}
    for line in open(os.path.join(xdir, 'kallsyms.txt')):
        w = line.split()
        ks[w[2]] = int(w[0], 16)
    base = ks['__bpf_call_base']
    return {((ks[n] - base + 2**31) % 2**32) - 2**31: h for n, h in HELPERS if n in ks}


def load_xlated(xdir, obj, g, helpers):
    """The translated test program of global g from object obj, or None."""
    p = os.path.join(xdir, os.path.basename(obj), f'c__bnt_{g}_g')
    if not os.path.exists(p + '.xlated'):
        return None
    funcs = dict((n, int(s)) for n, s in (line.split() for line in open(p + '.funcs')))
    return Xlated(open(p + '.xlated', 'rb').read(), funcs, helpers)
