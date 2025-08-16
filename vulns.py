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
    """Find calls to gets into a stack buffer"""

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
            rdi = found.solver.eval(found.regs.rdi, cast_to=int)
            rbp = found.solver.eval(found.regs.rbp, cast_to=int)

            rip_offset = rbp - rdi + 8

            # rdi-rbp is the number of bytes to write from the buffer to the end of the stack frame,
            # 8 past that is the return address

            ret.append(StackBufferOverflow(crossref["from"], rip_offset, None))

    return ret


def find_fgets_vulns(bin: Binary) -> list[Vulnerability]:
    """Find calls to fgets into a stack buffer which writes past the buffer size"""

    crossrefs = []
    for d in bin.afl:
        if d["name"] == "sym.imp.fgets":
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
            rdi = found.solver.eval(found.regs.rdi, cast_to=int)
            rsi = found.solver.eval(found.regs.rsi, cast_to=int)
            rbp = found.solver.eval(found.regs.rbp, cast_to=int)

            rip_offset = rbp - rdi + 8
            write_size = rsi

            # Only store this vulnerability if we'll be able to write into rip completely
            if write_size >= rip_offset + 8:
                ret.append(StackBufferOverflow(crossref["from"], rip_offset, rsi))

    return ret


def find_vulns(bin: Binary) -> list[Vulnerability]:
    ret = []

    ret += find_gets_vulns(bin)
    ret += find_fgets_vulns(bin)

    return ret
