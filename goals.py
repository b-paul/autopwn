from pwn import ELF

class Goal():
    """
    Abstract class for a possible goal.
    """

class WinFunction(Goal):
    """A function that might solve the challenge when called"""
    def __init__(self, name: str, addr: int):
        self._addr = addr

    def addr(self) -> int:
        """The memory address of this function"""
        return self._addr

def find_goals(bin_path: str) -> list[Goal]:
    ret = []

    # TODO this does the logging thing
    elf = ELF(bin_path)

    for name in ['win', 'goal', 'wins']:
        if name in elf.symbols:
            ret.append(WinFunction(name, elf.symbols[name]))

    return ret
