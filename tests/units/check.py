#!/usr/bin/env python3
"""Run every case in the kernel and compare with expected.json.

For each built variant (default, c, strict) runs build/<variant>/case_<n>.o with
run_case and compares the global's return value, the out buffer and the packet
after the call with the recorded results. Needs root.

usage: check.py VARIANT_DIR...           compare
       check.py --update VARIANT_DIR     record expected.json from this run
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from cases import COMPARE  # noqa: E402

RUN = os.path.join(HERE, 'build', 'run_case')
EXPECTED = os.path.join(HERE, 'expected.json')


def fold16(b):
    s = int.from_bytes(b[:4], 'little')
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return s


def run_variant(vdir):
    index = json.load(open(os.path.join(vdir, '..', 'gen', 'cases.json')))
    results = {}
    for c in index:
        obj = os.path.join(vdir, f"case_{c['n']}.o")
        line = subprocess.run([RUN, obj, c['pkt']], capture_output=True, text=True).stdout.split()
        if not line or line[0] != 'OK':
            results[c['name']] = dict(error=' '.join(line) or 'no output', g=c['g'])
        else:
            results[c['name']] = dict(ret=int(line[1]), out=line[2], pkt=line[3] if len(line) > 3 else '',
                                      g=c['g'])
    return results


def same(name, got, exp):
    if 'error' in got:
        return got['error']
    mode = COMPARE.get(got['g'])
    diffs = []
    if got['ret'] != exp['ret']:
        diffs.append(f"ret {got['ret']} (expected {exp['ret']})")
    if got['pkt'] != exp['pkt']:
        diffs.append('packet differs')
    if mode == 'csum32':
        if fold16(bytes.fromhex(got['out'])) != fold16(bytes.fromhex(exp['out'])):
            diffs.append('checksum differs')
    elif mode != 'no_out' and got['out'] != exp['out']:
        diffs.append('buffer differs')
    return '; '.join(diffs)


def main():
    if sys.argv[1] == '--update':
        res = run_variant(sys.argv[2])
        bad = [n for n, r in res.items() if 'error' in r]
        if bad:
            sys.exit(f'not recording: {len(bad)} cases failed, first: {bad[0]}: {res[bad[0]]["error"]}')
        with open(EXPECTED, 'w') as f:
            json.dump({n: {k: v for k, v in r.items() if k != 'g'} for n, r in res.items()}, f, indent=1,
                      sort_keys=True)
        print(f'expected.json: {len(res)} cases recorded')
        return
    expected = json.load(open(EXPECTED))
    failed = 0
    for vdir in sys.argv[1:]:
        res = run_variant(vdir)
        bad = 0
        for name, got in res.items():
            if name not in expected:
                print(f'FAIL {os.path.basename(vdir)} {name}: no expected result')
                bad += 1
                continue
            d = same(name, got, expected[name])
            if d:
                print(f'FAIL {os.path.basename(vdir)} {name}: {d}')
                bad += 1
        print(f'{os.path.basename(vdir)}: {len(res) - bad}/{len(res)} cases match')
        failed += bad
    sys.exit(1 if failed else 0)


main()
