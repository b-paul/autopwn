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
                print(f"Win Function: {goal._name} @ 0x{goal.addr():x}")


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
    print(bin.afl)
    print(bin.crossrefs(bin.afl[0]["offset"]))

    return found_goals
