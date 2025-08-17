from binary import Binary
from dataclasses import dataclass
from typing import Optional
from goals import Goal, WinFunction

import angr


options = angr.options.unicorn
options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)


class Vulnerability:
    # This should really be renamed to Primative
    """Abstract class for potentially usable vulnerabilities"""


@dataclass
class StackBufferOverflow(Vulnerability):
    addr: int
    saved_rip_offset: int
    max_write_size: Optional[int]
    state: angr.SimState

    def __str__(self) -> str:
        return f"Stack Buffer Overflow @ {self.addr} (rip offset: {self.saved_rip_offset}, max write size: {self.max_write_size})"


@dataclass
class WinFunctionCall(Vulnerability):
    name: str
    addr: int
    state: angr.SimState

    def __str__(self) -> str:
        return f"Win Function Call: {self.name}"


@dataclass
class UnconstrainedPrintf(Vulnerability):
    addr: int
    state: angr.SimState


@dataclass
class BufferWrite(Vulnerability):
    """Write arbitrary bytes to a buffer from stdin"""

    instruction_addr: int
    buffer_addr: int
    buffer_type: str | None
    buffer_len: int | None


def find_gets_vulns(bin: Binary) -> list[Vulnerability]:
    """Find calls to gets into a stack buffer"""

    ret = []

    state = bin.angr.factory.full_init_state(add_options=options, stdin=angr.SimFile)

    for crossref, found in bin.crossref_states("sym.imp.gets", state):
        rdi = found.solver.eval(found.regs.rdi, cast_to=int)
        rbp = found.solver.eval(found.regs.rbp, cast_to=int)

        rip_offset = rbp - rdi + 8

        # rdi-rbp is the number of bytes to write from the buffer to the end of the stack frame,
        # 8 past that is the return address

        ret.append(StackBufferOverflow(crossref["from"], rip_offset, None, found))

    return ret


def find_fgets_vulns(bin: Binary) -> list[Vulnerability]:
    """Find calls to fgets into a stack buffer which writes past the buffer size"""

    ret = []

    options = angr.options.unicorn
    options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state = bin.angr.factory.full_init_state(add_options=options, stdin=angr.SimFile)

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

        ret.append(StackBufferOverflow(crossref["from"], rip_offset, rsi, found))

    return ret


def find_win_vulns(bin: Binary, goals: list[Goal]) -> list[Vulnerability]:
    ret = []

    for goal in goals:
        if isinstance(goal, WinFunction):
            for crossref, found in bin.crossref_states(
                goal.addr,
                bin.angr.factory.full_init_state(add_options=options, stdin=angr.SimFile),
            ):
                ret.append(WinFunctionCall(goal.name, goal.addr, found))

    return ret


def find_printf_vulns(bin: Binary) -> list[Vulnerability]:
    ret = []

    base_state = bin.angr.factory.full_init_state(add_options=options, stdin=angr.SimFile)
    # This is required to avoid our 'reaching the printf' input from causing buffer
    # overflows. Ideally we'd just be able to tell it to minimise the length of the
    # input buffer, but we can't. We just guess that most 'gets' calls point to buffers
    # at least 50 bytes in size.
    base_state.libc.max_gets_size = 50
    crossrefs = bin.crossref_states(
        "sym.imp.printf",
        base_state
    )
    for crossref, state in crossrefs:
        rdi = state.solver.eval(state.regs.rdi, cast_to=int)

        is_variable = state.solver.satisfiable(
            extra_constraints=[state.regs.rdi != rdi]
        )
        if is_variable:
            continue

        first_byte = state.solver.eval(state.memory.load(rdi, 1), cast_to=int)
        is_user_controlled = state.solver.satisfiable(
            extra_constraints=[state.memory.load(rdi, 1) != first_byte]
        )

        # Revert to default so that we can still test overflows after running the
        # leak.
        state.libc.max_gets_size = 256

        if is_user_controlled:
            ret.append(UnconstrainedPrintf(crossref["from"], state))

    return ret


def find_buffer_writes(bin: Binary) -> list[BufferWrite]:
    ret = []

    def constraint(state: angr.SimState) -> bool:
        # rdi is constant
        rdi = state.solver.eval(state.regs.rdi)
        return not state.solver.satisfiable(extra_constraints=[state.regs.rdi != rdi])

    crossrefs = bin.crossref_states(
        "sym.imp.gets", bin.angr.factory.full_init_state(), constraint
    ) + bin.crossref_states(
        "sym.imp.fgets", bin.angr.factory.full_init_state(), constraint
    )

    for crossref, state in crossrefs:
        buffer_type = None
        buffer_len = None

        rdi = state.solver.eval(state.regs.rdi, cast_to=int)
        rsi = state.solver.eval(state.regs.rsi, cast_to=int)

        if not bin.pie and rdi & 0xffffffffff000000 == 0:
            buffer_type = "Global"
        if crossref["refname"] == "sym.imp.fgets" and not state.solver.satisfiable(extra_constraints=[state.regs.rsi != rsi]):
            buffer_len = rsi
        ret.append(BufferWrite(crossref["from"], rdi, buffer_type, buffer_len))

    return ret


def find_vulns(bin: Binary, goals: list[Goal]) -> list[Vulnerability]:
    ret = []

    class Printf(angr.SimProcedure):
        def run(self, format: str):
            return

    if bin.loader.find_symbol("printf") is not None:
        bin.angr.rehook_symbol("printf", Printf(), False)
    if bin.loader.find_symbol("__printf__chk") is not None:
        bin.angr.rehook_symbol("__printf__chk", Printf(), False)

    ret += find_gets_vulns(bin)
    ret += find_fgets_vulns(bin)
    ret += find_win_vulns(bin, goals)
    ret += find_printf_vulns(bin)
    ret += find_buffer_writes(bin)

    if bin.loader.find_symbol("printf") is not None:
        bin.angr.rehook_symbol("printf", angr.SIM_PROCEDURES["libc"]["printf"](), False)
    if bin.loader.find_symbol("__printf__chk") is not None:
        bin.angr.rehook_symbol("__printf_chk", angr.SIM_PROCEDURES["libc"]["printf"](), False)

    return ret
