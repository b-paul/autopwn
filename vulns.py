import angr
from binary import Binary
from dataclasses import dataclass
from typing import Optional
from goals import Goal, WinFunction


class Vulnerability:
    """Abstract class for potentially usable vulnerabilities"""


@dataclass
class StackBufferOverflow(Vulnerability):
    addr: int
    saved_rip_offset: int
    max_write_size: Optional[int]


@dataclass
class WinFunctionCall(Vulnerability):
    name: str
    addr: int
    state: angr.SimState


def find_gets_vulns(bin: Binary) -> list[Vulnerability]:
    """Find calls to gets into a stack buffer"""

    ret = []

    for crossref, found in bin.crossref_states("sym.imp.gets", bin.angr.factory.full_init_state()):
        rdi = found.solver.eval(found.regs.rdi, cast_to=int)
        rbp = found.solver.eval(found.regs.rbp, cast_to=int)

        rip_offset = rbp - rdi + 8

        # rdi-rbp is the number of bytes to write from the buffer to the end of the stack frame,
        # 8 past that is the return address

        ret.append(StackBufferOverflow(crossref["from"], rip_offset, None))

    return ret


def find_fgets_vulns(bin: Binary) -> list[Vulnerability]:
    """Find calls to fgets into a stack buffer which writes past the buffer size"""

    ret = []

    for crossref, found in bin.crossref_states("sym.imp.fgets", bin.angr.factory.full_init_state()):
        rdi = found.solver.eval(found.regs.rdi, cast_to=int)
        rsi = found.solver.eval(found.regs.rsi, cast_to=int)
        rbp = found.solver.eval(found.regs.rbp, cast_to=int)

        rip_offset = rbp - rdi + 8
        write_size = rsi

        # Only store this vulnerability if we'll be able to write into rip completely
        if write_size >= rip_offset + 8:
            ret.append(StackBufferOverflow(crossref["from"], rip_offset, rsi))

    return ret


def find_win_vulns(bin: Binary, goals: list[Goal]) -> list[Vulnerability]:
    ret = []

    for goal in goals:
        if isinstance(goal, WinFunction):
            for crossref, found in bin.crossref_states(goal.addr, bin.angr.factory.full_init_state()):
                ret.append(WinFunctionCall(goal.name, goal.addr, found))

    return ret


def find_vulns(bin: Binary, goals: list[Goal]) -> list[Vulnerability]:
    ret = []

    ret += find_gets_vulns(bin)
    ret += find_fgets_vulns(bin)
    ret += find_win_vulns(bin, goals)

    return ret
