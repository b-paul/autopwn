from binary import Binary

class Goal():
    """
    Abstract class for a possible goal.
    """

class WinFunction(Goal):
    """A function that might solve the challenge when called"""
    def __init__(self, name: str, addr: int):
        self._name = name
        self._addr = addr

    def addr(self) -> int:
        """The memory address of this function"""
        return self._addr


def print_goals(goals: list[Goal]):
    for goal in goals:
        match goal:
            case WinFunction():
                print(f"Win Function: {goal._name} @ 0x{goal.addr():x}")


def find_goals(bin: Binary) -> list[Goal]:
    ret = []

    for name in ['win', 'goal', 'wins']:
        sym = bin.loader.find_symbol(name)
        if sym is not None:
            print(sym.rebased_addr)
            ret.append(WinFunction(name, sym.rebased_addr))

    return ret
