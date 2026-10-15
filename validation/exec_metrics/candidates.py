#!/usr/bin/env python3
"""Build every configuration of the globals that collect.py compares.

For each configuration it builds two things with the same compiler and flags:
OUT_DIR/<label>.o, every global (tests/globals), which the interpreter and
verifier_stats measure; and OUT_DIR/cases/<label>/case_<n>.o, the programs of
tests/units, which kernel_cases.py runs in the kernel. It then checks that each
global is the same code in both, so the kernel runs exactly what is measured.

usage: candidates.py [-j N] OUT_DIR

Environment:
  CLANGS       space-separated LABEL:PATH pairs, e.g. "clang16:/opt/llvm16/bin/clang clang20:clang-20"
  GCC_BPF      bpf-gcc to use, with GCC_LABEL as its label (default gcc)
  MERLIN       clone of https://github.com/4ar0nma0/Merlin: adds its bytecode
               optimizer on top of every build, and its LLVM passes
               (merlin_llvm.sh; LLVM_CONFIG picks the LLVM, default llvm-config-20)
  LEVELS       optimization levels (default "O1 O2 O3 Os Oz"; gcc has no Oz)
  OBJCOPY      strips DWARF from the case programs (default llvm-objcopy-20)

Writes OUT_DIR/configs.txt, one LABEL=OBJ per line, for collect.py.
"""
import argparse
import os
import shlex
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
from bpfsim import Elf  # noqa: E402
from common import CASES  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument('-j', type=int, default=os.cpu_count())
ap.add_argument('out')
opt = ap.parse_args()
out = os.path.abspath(opt.out)
env = os.environ
levels = env.get('LEVELS', 'O1 O2 O3 Os Oz').split()
objcopy = env.get('OBJCOPY', 'llvm-objcopy-20')
sysinc = f'/usr/include/{os.uname().machine}-linux-gnu'
# The candidates are compilations of the C globals, not of the shipped asm.
flags = ['-g', '-mcpu=v3', '-D__TARGET_ARCH_x86', '-DBNT_ASM_GLOBALS=0', f'-I{REPO}/src', f'-I{sysinc}']

subprocess.run(['make', '-s', '-C', f'{REPO}/tests/globals', 'build/globals.c'], check=True)
subprocess.run(['make', '-s', '-C', f'{REPO}/tests/units', 'build/gen.stamp'], check=True)
globals_c = f'{REPO}/tests/globals/build/globals.c'
gen = f'{REPO}/tests/units/build/gen'
cases = sorted(int(f[5:-2]) for f in os.listdir(gen) if f.startswith('case_') and f.endswith('.c'))

# label -> function(src, dst) that compiles src into dst
configs = {}
for pair in env.get('CLANGS', '').split():
    label, cc = pair.split(':', 1)
    for o in levels:
        configs[f'{label}-{o}'] = lambda s, d, cc=cc, o=o: [cc, f'-{o}', *flags, '-target', 'bpf', '-c', s, '-o', d]
if env.get('GCC_BPF'):
    g = env.get('GCC_LABEL', 'gcc')
    # Only the last set gets every global through the verifier, but some
    # globals verify, and run faster, with fewer flags.
    for name, extra in [('base', ''), ('noivopts', '-fno-ivopts'),
                        ('safe', '-fno-ivopts -fno-cse-follow-jumps -fno-thread-jumps')]:
        for o in levels:
            if o != 'Oz':
                configs[f'{g}-{name}-{o}'] = lambda s, d, o=o, extra=extra: [
                    env['GCC_BPF'], f'-{o}', *flags, '-idirafter', '/usr/include', *shlex.split(extra),
                    '-c', s, '-o', d]
if env.get('MERLIN'):
    v = subprocess.run([env.get('LLVM_CONFIG', 'llvm-config-20'), '--version'], capture_output=True,
                       text=True, check=True).stdout.split('.')[0]
    # Build the passes once, before the parallel runs.
    subprocess.run([f'{HERE}/merlin_llvm.sh', env['MERLIN'], '--build'], check=True)
    for o in levels:
        configs[f'clang{v}-{o}+merlin_llvm'] = lambda s, d, o=o: [
            f'{HERE}/merlin_llvm.sh', env['MERLIN'], f'-{o}', s, d, *flags]


def run(cmd):
    return subprocess.run(cmd, capture_output=True).returncode == 0


def build(label, make):
    os.makedirs(f'{out}/cases/{label}', exist_ok=True)
    ok = run(make(globals_c, f'{out}/{label}.o'))
    for n in cases:
        d = f'{out}/cases/{label}/case_{n}.o'
        if run(make(f'{gen}/case_{n}.c', d)):
            run([objcopy, '--strip-debug', d])
    return ok


def merlin_bc(label):
    """label+merlin_bc from label: the bytecode optimizer on every object."""
    m = f'{label}+merlin_bc'
    os.makedirs(f'{out}/cases/{m}', exist_ok=True)
    ok = run([sys.executable, f'{HERE}/merlin_bc.py', env['MERLIN'], f'{out}/{label}.o', f'{out}/{m}.o'])
    for n in cases:
        s = f'{out}/cases/{label}/case_{n}.o'
        if os.path.exists(s):
            run([sys.executable, f'{HERE}/merlin_bc.py', env['MERLIN'], s, f'{out}/cases/{m}/case_{n}.o'])
    return ok


with ThreadPoolExecutor(opt.j) as ex:
    built = dict(zip(configs, ex.map(lambda kv: build(*kv), configs.items())))
    labels = [l for l in configs if built[l]]
    if env.get('MERLIN'):
        mb = dict(zip(labels, ex.map(merlin_bc, labels)))
        labels += [f'{l}+merlin_bc' for l in labels if mb[l]]


def func_bytes(path, name):
    e = Elf(path)
    if name not in e.funcs:
        return None
    s, n = e.funcs[name]
    return e.text[s * 8:(s + n) * 8]


# The global in each case program must be the code measured in <label>.o.
mismatch = []
for label in labels:
    whole = {}
    for n in cases:
        p = f'{out}/cases/{label}/case_{n}.o'
        if not os.path.exists(p):
            continue
        fn = f'__bnt_{CASES[n][0]}_g'
        if fn not in whole:
            whole[fn] = func_bytes(f'{out}/{label}.o', fn)
        if func_bytes(p, fn) != whole[fn]:
            mismatch.append(f'{label} case_{n} {fn}')
with open(f'{out}/configs.txt', 'w') as f:
    f.writelines(f'{l}={out}/{l}.o\n' for l in labels)
with open(f'{out}/mismatch.txt', 'w') as f:
    f.writelines(m + '\n' for m in mismatch)
print(f'{out}: {len(labels)} configurations, {len(mismatch)} case programs whose global differs '
      f'from the measured one (see mismatch.txt)')
