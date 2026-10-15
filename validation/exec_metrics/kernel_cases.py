#!/usr/bin/env python3
"""Run the case programs of every configuration in the kernel.

Runs OUT_DIR/cases/<label>/case_<n>.o, as built by candidates.py, with
tests/units/build/run_case (BPF_PROG_TEST_RUN) and prints one tab-separated
line per configuration and case: label, case, status (OK, or why it did not
run), and the global's return value, out buffer and packet after the call.
collect.py --kernel-cases compares them with tests/units/expected.json.
Needs root, and make -C tests/units for run_case.

usage: kernel_cases.py [-j N] OUT_DIR > kernel_cases.tsv
"""
import argparse
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from common import CASES, UNITS  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument('-j', type=int, default=os.cpu_count())
ap.add_argument('out')
opt = ap.parse_args()
run_case = os.path.join(UNITS, 'build', 'run_case')
labels = [line.split('=', 1)[0] for line in open(os.path.join(opt.out, 'configs.txt')) if line.strip()]


def one(job):
    label, n = job
    g, case, pkt = CASES[n][0], CASES[n][1], CASES[n][2]
    obj = os.path.join(opt.out, 'cases', label, f'case_{n}.o')
    if not os.path.exists(obj):
        return [label, f'{g}/{case}', 'NOBUILD', '', '', '']
    w = subprocess.run([run_case, obj, pkt.hex()], capture_output=True, text=True).stdout.split()
    if not w or w[0] != 'OK':
        return [label, f'{g}/{case}', (w[0] if w else 'NOOUTPUT'), '', '', '']
    return [label, f'{g}/{case}', 'OK', w[1], w[2], w[3] if len(w) > 3 else '']


print('config\tcase\tstatus\tret\tout\tpkt')
with ThreadPoolExecutor(opt.j) as ex:
    for row in ex.map(one, [(l, n) for l in labels for n in range(len(CASES))]):
        print('\t'.join(row))
