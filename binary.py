import angr
import cle
import json
import r2pipe

from pwn import ELF


class Binary:
    def __init__(self, path: str):
        self.path = path

        self.loader = cle.Loader(path)

        self.elf = ELF(path, checksec=False)

        self.angr = angr.Project(path, auto_load_libs=False)

        self.relro = self.elf.relro
        self.canary = self.elf.canary
        self.nx = self.elf.nx
        self.pie = self.elf.pie

        self.r2 = r2pipe.open(path)
        self.r2.cmd("aaa")
        self.afl = json.loads(self.r2.cmd("aflj"))

        self.angr = angr.Project(path, auto_load_libs=False)

    def crossrefs(self, symbol: int):
        return json.loads(self.r2.cmd(f"axtj {symbol}"))

    def load_string(self, addr: int) -> str:
        self.r2.cmd(f"s {addr}")
        return self.r2.cmd("ps")

    # What's the type of state?!??!?!?!??!?!!?!?!!!?!?
    def crossref_states(self, symbol: int, state) -> list[tuple]:
        """
        Get a list of angr states that reach a crossreference to a symbol call, starting at the given (angr) state
        """
        fn = next((fn for fn in self.afl if fn["name"] == symbol), None)
        if fn is None:
            return []

        crossrefs = self.crossrefs(fn["offset"])
        if crossrefs == []:
            return []

        d = []
        for crossref in crossrefs:
            print(crossref)
            goal = crossref["from"]
            simgr = self.angr.factory.simulation_manager(state)
            simgr.explore(find=goal)
            d += [(crossref, found) for found in simgr.found]

        return d
