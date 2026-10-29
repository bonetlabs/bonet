#!/usr/bin/env python3
"""Generate the cases, run them, and compare the results with the model.

usage: check.py gen BUILD               write BUILD/cases/<api>.txt (run_api input)
       check.py run BUILD RESULTS        run every API in this kernel (root):
                                         RESULTS/<api>.txt, run_api's output
       check.py report BUILD RESULTS     compare with the model, print the report

A case fails when the return value, a pointer argument's memory or a view
differs from the model, when the packet differs after a successful call, or
when a failed call changed the packet. A third check does not use the model: a
setter that keeps checksums must leave valid every checksum that was valid
before (CSUM).
"""
import collections
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cases as C  # noqa: E402
import model as M  # noqa: E402

ROOT = os.path.join(HERE, '..', '..')


def load(build):
    return json.load(open(os.path.join(build, 'gen', 'apis.json')))


def gen(build):
    d = os.path.join(build, 'cases')
    os.makedirs(d, exist_ok=True)
    n = 0
    for name, sig in load(build).items():
        cs = C.cases(name, sig)
        with open(os.path.join(d, name + '.txt'), 'w') as f:
            for label, pkt, io in cs:
                f.write(f'{pkt.hex()} {io.hex()}\n')
        n += len(cs)
    print(f'{d}: {n} cases')


def run(build, results):
    os.makedirs(os.path.join(results, 'log'), exist_ok=True)
    runner = os.path.join(build, 'run_api')
    for name in sorted(load(build)):
        with open(os.path.join(build, 'cases', name + '.txt')) as fin, \
                open(os.path.join(results, name + '.txt'), 'w') as fout:
            subprocess.run([runner, os.path.join(build, 'obj', name + '.o'),
                            os.path.join(results, 'log', name + '.log')], stdin=fin, stdout=fout)


# ---- checksum validity, computed from scratch ---------------------------------

def valid_csums(pkt, offs):
    """{which: valid} for the checksums of a corpus packet with header offsets offs."""
    r = {}
    b = bytes(pkt)
    try:
        if 'ipv4' in offs:
            o = offs['ipv4']
            hl = (b[o] & 15) * 4
            r['ipv4'] = M.csum16(b[o:o + hl]) == 0
            l4 = o + hl
            proto, ph = b[o + 9], b[o + 12:o + 20]
            tot = int.from_bytes(b[o + 2:o + 4], 'big')
            if proto in (6, 17) and not int.from_bytes(b[o + 6:o + 8], 'big') & 0x3fff and offs.get(
                    'tcp' if proto == 6 else 'udp') == l4:
                seg = b[l4:o + tot]
                if proto == 17 and seg[6:8] == b'\0\0':
                    return r
                r['l4'] = M.csum16(ph + bytes([0, proto]) + len(seg).to_bytes(2, 'big') + seg) == 0
            if proto == 1 and offs.get('icmp4') == l4:
                r['l4'] = M.csum16(b[l4:o + tot]) == 0
        elif 'ipv6' in offs:
            o = offs['ipv6']
            for vt, proto in (('tcp', 6), ('udp', 17), ('icmp6', 58)):
                if vt in offs and offs[vt] == o + 40 and b[o + 6] == proto:
                    seg = b[o + 40:o + 40 + int.from_bytes(b[o + 4:o + 6], 'big')]
                    if proto == 17 and seg[6:8] == b'\0\0':
                        return r
                    r['l4'] = M.csum16(b[o + 8:o + 40] + len(seg).to_bytes(4, 'big') + bytes([0, 0, 0, proto])
                                       + seg) == 0
    except IndexError:
        pass
    return r


KEEPS_CSUM = re.compile(r'bnt_(ipv4|ipv6|tcp|udp|icmp4|icmp6)__(set|clear|dec)_(?!.*no_csum)'
                        r'(?!check$|checksum$|total_len$|payload_len$|len$|hlen$|base_nexthdr$)')


def compare(name, sig, label, pkt, io, line):
    """(list of failures, the result) for one case."""
    exp = M.model(name, sig, pkt, M.IO.unpack(io))
    f = line.split()
    if not f or f[0] != 'OK':
        return [' '.join(f) or 'no output'], False, None
    got = M.IO.unpack(bytes.fromhex(f[1]))
    gpkt = bytes.fromhex(f[2]) if len(f) > 2 else b''
    ret, vout, buf = got[9], list(got[10:18]), got[18]
    fails = []
    if ret != exp.ret:
        fails.append(f'ret {M.NAMES.get(ret, ret)} (model {M.NAMES.get(exp.ret, exp.ret)})')
    evout, ebuf = exp.io
    if vout != evout:
        fails.append(f'views {vout} (model {evout})')
    if name.endswith('fib_lookup') and exp.ret == M.OK:
        fields = M.FIB_FIELDS[6 if 'ipv6' in name else 4]
        for o, n in fields:
            if buf[M.SLOT + o:M.SLOT + o + n] != ebuf[M.SLOT + o:M.SLOT + o + n]:
                fails.append(f'fib bytes {o}..{o + n}')
    elif buf != ebuf:
        diff = [i for i in range(len(buf)) if buf[i] != ebuf[i]]
        fails.append(f'memory at slot {diff[0] // M.SLOT} byte {diff[0] % M.SLOT}: '
                     f'{buf[diff[0]:diff[0] + 8].hex()} (model {ebuf[diff[0]:diff[0] + 8].hex()})')
    if exp.pkt is not None:
        if gpkt != exp.pkt:
            fails.append(f'packet: {first_diff(gpkt, exp.pkt)}')
    elif gpkt != pkt:
        fails.append(f'packet changed by a failed call: {first_diff(gpkt, pkt)}')
    return fails, (ret, gpkt)


def first_diff(a, b):
    if len(a) != len(b):
        return f'length {len(a)} (model {len(b)})'
    i = next(i for i in range(len(a)) if a[i] != b[i])
    return f'byte {i}: {a[i:i + 8].hex()} (model {b[i:i + 8].hex()})'


def documented(apis):
    """@retval codes in the doc comment of each API."""
    docs = {}
    for f in ('bnt_core.h', 'bnt_xdp.h'):
        s = open(os.path.join(ROOT, 'src', f)).read()
        for m in re.finditer(r'/\*\*((?:(?!\*/).)*)\*/\s*static\s+__always_inline\s+[\w \*]+?\b'
                             r'(bnt_[a-z0-9]+__\w+)\s*\(', s, re.S):
            if m.group(2) in apis:
                rv = re.findall(r'@retval\s+BNT_(\w+)', m.group(1))
                if rv:
                    docs[m.group(2)] = {('OK' if r == 'OK' else r.replace('ERR_', '')) for r in rv}
    return docs


def report(build, results):
    apis = load(build)
    docs = documented(apis)
    fails, csum_bad, outcomes, loadfail = {}, {}, {}, {}
    total = 0
    for name, sig in sorted(apis.items()):
        cs = C.cases(name, sig)
        lines = open(os.path.join(results, name + '.txt')).read().splitlines()
        if lines and lines[0].startswith('LOADFAIL'):
            loadfail[name] = lines[0][9:]
            continue
        if len(lines) != len(cs):
            loadfail[name] = f'{len(lines)} results for {len(cs)} cases'
            continue
        outcomes[name] = collections.Counter()
        for (label, pkt, io), line in zip(cs, lines):
            total += 1
            fl, got = compare(name, sig, label, pkt, io, line)
            if fl:
                fails.setdefault(name, []).append((label, fl))
            if got is None:
                continue
            ret, gpkt = got
            outcomes[name][M.NAMES.get(ret, 'value') if sig['ret'] == 'int' else 'value'] += 1
            vt = C.view_type(sig['params'][0])
            if KEEPS_CSUM.match(name) and ret == M.OK and label.startswith('pkt:') and \
                    vt in C.CORPUS[label[4:]]['off']:
                offs = C.CORPUS[label[4:]]['off']
                before, after = valid_csums(pkt, offs), valid_csums(gpkt, offs)
                bad = [k for k, v in before.items() if v and after.get(k) is False]
                if bad:
                    csum_bad.setdefault(name, []).append(f'{label} ({", ".join(bad)})')

    print(f'{len(apis)} APIs, {total} cases run; {len(loadfail)} APIs do not load')
    print(f'{sum(len(v) for v in fails.values())} failing cases in {len(fails)} APIs; '
          f'{len(csum_bad)} APIs break a valid checksum\n')
    if loadfail:
        print('== LOAD FAILURES')
        for n, why in loadfail.items():
            print(f'{n}: {why}')
        print()
    if fails:
        print('== FAILURES (first 3 per API)')
        for n, fl in fails.items():
            print(f'{n}: {len(fl)} cases')
            for label, why in fl[:3]:
                print(f'    {label}: {"; ".join(why)}')
        print()
    if csum_bad:
        print('== CSUM (valid before, invalid after)')
        for n, l in csum_bad.items():
            print(f'{n}: {", ".join(l[:4])}')
        print()
    print('== OUTCOMES (reached in the kernel; [doc only] = documented, never reached; '
          '[undoc] = reached, not documented)')
    for n in sorted(outcomes):
        got = outcomes[n]
        line = ' '.join(f'{k}:{v}' for k, v in sorted(got.items()))
        extra = ''
        if n in docs:
            miss = docs[n] - set(got)
            und = set(got) - docs[n] - {'value'}
            extra = (f'  [doc only: {" ".join(sorted(miss))}]' if miss else '') + \
                    (f'  [undoc: {" ".join(sorted(und))}]' if und else '')
        print(f'{n}: {line}{extra}')


def main():
    cmd, build = sys.argv[1], sys.argv[2]
    if cmd == 'gen':
        gen(build)
    elif cmd == 'run':
        run(build, sys.argv[3])
    else:
        report(build, sys.argv[3])


if __name__ == '__main__':
    main()
