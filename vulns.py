from binary import Binary
from dataclasses import dataclass
from typing import Optional

import angr
import claripy


class Vulnerability:
    """Abstract class for potentially usable vulnerabilities"""


@dataclass
class StackBufferOverflow(Vulnerability):
    addr: int
    saved_rip_offset: int
    max_write_size: Optional[int]


def find_gets_vulns(bin: Binary) -> list[Vulnerability]:
    """Find calls to gets with a stack buffer"""

    crossrefs = []
    for d in bin.afl:
        if d["name"] == "sym.imp.gets":
            crossrefs = bin.crossrefs(d["offset"])

    if crossrefs == []:
        return []

    ret = []

    for crossref in crossrefs:
        state = bin.angr.factory.full_init_state()
        goal = crossref["from"]
        simgr = bin.angr.factory.simulation_manager(state)
        simgr.explore(find=goal)
        for found in simgr.found:
            rbp = found.solver.eval(found.regs.get("rdi"), cast_to=int)
            rdi = found.solver.eval(found.regs.get("rbp"), cast_to=int)

            rip_offset = rdi - rbp + 8

            # rdi-rbp is the number of bytes to write from the buffer to the end of the stack frame,
            # 8 past that is the return address

            ret.append(StackBufferOverflow(crossref["from"], rip_offset, None))

    return ret


def find_vulns(bin: Binary) -> list[Vulnerability]:
    ret = []

    ret += find_gets_vulns(bin)

    return ret
