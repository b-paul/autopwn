import angr
from typing import Generator

from binary import Binary
from dataclasses import dataclass

class Goal():
    """
    Abstract class for a possible goal.
    """


@dataclass(frozen=True)
class WinFunction(Goal):
    """A function that might solve the challenge when called"""
    name: str
    addr: int

    def __str__(self) -> str:
        return f"Win Function: {self.name} @ 0x{self.addr:x}"


@dataclass(frozen=True)
class SystemFunction(Goal):
    """A system() entry in the PLT"""
    addr: int

    def __str__(self) -> str:
        return f"system() PLT entry @ 0x{self.addr:x}"


def find_goals(bin: Binary) -> Generator[Goal, None, None]:
    found = set()
    for win_function in find_win_functions(bin):
        if win_function not in found:
            yield win_function
            found.add(win_function)


def find_win_functions(bin: Binary) -> Generator[Goal, None, None]:
    # First, try a list of well-known goal function names
    for name in ['win', 'goal', 'wins']:
        sym = bin.loader.find_symbol(name)
        if sym is not None:
            yield WinFunction(name, sym.rebased_addr)

    # Otherwise, try to detect them from their behaviour
    # If it opens a flag.txt file, it's probably a win function
    fopen = next((fn for fn in bin.afl if fn["name"] == "sym.imp.fopen"), None)
    if fopen:
        crossrefs = bin.crossrefs(fopen["offset"])
        for crossref in crossrefs:
            caller = next(fn for fn in bin.afl if fn["name"] == crossref["fcn_name"])
            options = angr.options.unicorn
            state = bin.angr.factory.call_state(
                bin.angr.loader.find_symbol(caller["name"].removeprefix("sym.")).rebased_addr,
                add_options=options
            )

            for crossref, found in bin.crossref_states(fopen["offset"], state):
                if "flag" in bin.load_string(found.solver.eval(found.regs.rdi)):
                    yield WinFunction(caller["name"].removeprefix("sym."), caller["offset"])


    system = next((fn for fn in bin.afl if fn["name"] == "sym.imp.system"), None)
    system_goals = []
    if system:
        system_goals.append(SystemFunction(system["offset"]))
        crossrefs = bin.crossrefs(system["offset"])
        for crossref in crossrefs:
            caller = next(fn for fn in bin.afl if fn["name"] == crossref["fcn_name"])
            options = angr.options.unicorn
            state = bin.angr.factory.call_state(
                bin.angr.loader.find_symbol(caller["name"].removeprefix("sym.")).rebased_addr,
                add_options=options,
                prototype="void func(void)"
            )

            for crossref, found in bin.crossref_states(system["offset"], state):
                if "flag" in bin.load_string(found.solver.eval(found.regs.rdi)):
                    yield WinFunction(caller["name"].removeprefix("sym."), caller["offset"])

    yield from system_goals
