import angr
import cle
import json
import r2pipe

from typing import Optional

from pwnlib.context import context
from pwnlib.elf.elf import ELF


class Binary:
    def __init__(self, path: str):
        self.path = path

        self.elf = ELF(path, checksec=False)
        context.binary = self.elf

        self.angr = angr.Project(path, auto_load_libs=False)

        self.relro = self.elf.relro
        self.canary = self.elf.canary
        self.nx = self.elf.nx
        self.pie = self.elf.pie

        self.r2 = r2pipe.open(path, ["-2"])
        self.r2.cmd("aaa")
        self.afl = json.loads(self.r2.cmd("aflj"))

        opts = {}
        if self.pie:
            opts = {"base_addr": 0}
            self.elf.address = 0
        self.loader = cle.Loader(path, main_opts=opts)
        self.angr = angr.Project(path, auto_load_libs=False, main_opts=opts)

    def crossrefs(self, symbol: int):
        return json.loads(self.r2.cmd(f"axtj {symbol}"))

    def load_string(self, addr: int) -> str:
        self.r2.cmd(f"s {addr}")
        return self.r2.cmd("ps")

    def crossref_states(
        self,
        symbol: int | str,
        state: angr.SimState,
        goal_constraint: Optional[callable] = None,
    ) -> list[tuple]:
        """
        Get a list of angr states that reach a crossreference to a symbol call, starting at the given (angr) state
        """
        if isinstance(symbol, str):
            fn = next((fn for fn in self.afl if fn["name"] == symbol), None)
            if fn is None:
                return []

            crossrefs = self.crossrefs(fn["offset"])
            if crossrefs == []:
                return []
        else:
            crossrefs = self.crossrefs(symbol)
            if crossrefs == []:
                return []

        d = []
        for crossref in crossrefs:
            goal = crossref["from"]
            simgr = self.angr.factory.simulation_manager(state.copy())
            simgr.explore(find=goal)
            if goal_constraint is not None:
                d += [
                    (crossref, found) for found in simgr.found if goal_constraint(found)
                ]
            else:
                d += [(crossref, found) for found in simgr.found]

        return d
