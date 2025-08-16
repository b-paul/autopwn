import angr
from binary import Binary
from dataclasses import dataclass
from typing import Optional
from goals import Goal, WinFunction

import angr


class Vulnerability:
    """Abstract class for potentially usable vulnerabilities"""


@dataclass
class StackBufferOverflow(Vulnerability):
    addr: int
    saved_rip_offset: int
    max_write_size: Optional[int]
    needed_input: bytes

    def __str__(self) -> str:
        return f"Stack Buffer Overflow @ {self.addr} (rip offset: {self.saved_rip_offset}, max write size: {self.max_write_size})"


@dataclass
class WinFunctionCall(Vulnerability):
    name: str
    addr: int
    state: angr.SimState

    def __str__(self) -> str:
        return f"Win Function Call: {self.name}"


def find_gets_vulns(bin: Binary) -> list[Vulnerability]:
    """Find calls to gets into a stack buffer"""

    ret = []

    options = angr.options.unicorn
    options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state = bin.angr.factory.entry_state(add_options=options, stdin=angr.SimFile)

    for crossref, found in bin.crossref_states("sym.imp.gets", state):
        rdi = found.solver.eval(found.regs.rdi, cast_to=int)
        rbp = found.solver.eval(found.regs.rbp, cast_to=int)

        rip_offset = rbp - rdi + 8

        # rdi-rbp is the number of bytes to write from the buffer to the end of the stack frame,
        # 8 past that is the return address

        input = found.solver.eval(found.posix.stdin.load(0, found.posix.stdin.size), cast_to=bytes)

        ret.append(StackBufferOverflow(crossref["from"], rip_offset, None, input))

    return ret


def find_fgets_vulns(bin: Binary) -> list[Vulnerability]:
    """Find calls to fgets into a stack buffer which writes past the buffer size"""

    ret = []

    options = angr.options.unicorn
    options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state = bin.angr.factory.entry_state(add_options=options, stdin=angr.SimFile)

    def constraint(state):
        rip_offset = state.regs.rbp - state.regs.rdi + 8
        write_size = state.regs.rsi

        return state.satisfiable(extra_constraints=[write_size >= rip_offset + 8])

    for crossref, found in bin.crossref_states("sym.imp.fgets", state, constraint):
        rip_offset = found.regs.rbp - found.regs.rdi + 8
        write_size = found.regs.rsi
        found.solver.add(write_size >= rip_offset + 8)

        rsi = found.solver.eval(found.regs.rsi, cast_to=int)
        rip_offset = found.solver.eval(rip_offset, cast_to=int)

        input = found.solver.eval(found.posix.stdin.load(0, found.posix.stdin.size), cast_to=bytes)

        ret.append(StackBufferOverflow(crossref["from"], rip_offset, rsi, input))

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
