"""Shared helpers: the case list from tests/units and one interpreted run."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
UNITS = os.path.join(REPO, 'tests', 'units')
sys.path.insert(0, UNITS)

from bpfsim import PKT, Run  # noqa: E402
from cases import CASES, COMPARE  # noqa: E402,F401


def run_case(elf, g, pkt, args, pre):
    """Run __bnt_<g>_g on pkt; return metrics and what the call produced."""
    r = Run(elf, pkt)
    r.out[:len(pre)] = pre
    try:
        ret = r.call(f'__bnt_{g}_g', args)
    except Exception as ex:  # unknown opcode, bad access, step limit
        return dict(error=str(ex), exec=r.exec)
    return dict(ret=ret, out=bytes(r.out), pkt=bytes(r.pkt[r.data - PKT:r.data_end - PKT]),
                exec=r.exec, stack_max=r.stack_max, helper_bytes=r.helper_bytes, by_class=dict(r.c))
