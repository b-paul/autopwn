import angr

from binary import Binary
from dataclasses import dataclass

class Goal():
    """
    Abstract class for a possible goal.
    """

@dataclass
class WinFunction(Goal):
    """A function that might solve the challenge when called"""
    name: int
    addr: int


def print_goals(goals: list[Goal]):
    for goal in goals:
        match goal:
            case WinFunction():
                print(f"Win Function: {goal.name} @ 0x{goal.addr:x}")


def find_goals(bin: Binary) -> list[Goal]:
    return find_win_functions(bin)


def find_win_functions(bin: Binary) -> list[Goal]:
    found_goals = []

    # First, try a list of well-known goal function names
    for name in ['win', 'goal', 'wins']:
        sym = bin.loader.find_symbol(name)
        if sym is not None:
            print(sym.rebased_addr)
            found_goals.append(WinFunction(name, sym.rebased_addr))

    # Otherwise, try to detect them from their behaviour
    # If it opens a flag.txt file, it's probably a win function
    fopen = next((fn for fn in bin.afl if fn["name"] == "sym.imp.fopen"), None)
    if fopen:
        crossrefs = bin.crossrefs(fopen["offset"])
        for crossref in crossrefs:
            caller = next(fn for fn in bin.afl if fn["name"] == crossref["fcn_name"])
            options = angr.options.unicorn
            check = bin.angr.factory.call_state(
                bin.angr.loader.find_symbol(caller["name"].removeprefix("sym.")).rebased_addr,
                add_options=options
            )

            simgr = bin.angr.factory.simulation_manager(check)
            simgr.explore(find=crossref["from"], avoid=[])

            strings = set([bin.load_string(found.solver.eval(found.regs.rdi)) for found in simgr.found])
            if any("flag.txt" in string for string in strings):
                found_goals.append(WinFunction(caller["name"].removeprefix("sym."), caller["offset"]))

    return found_goals
