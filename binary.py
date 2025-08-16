import cle
import json
import r2pipe

from pwn import ELF

class Binary:
    def __init__(self, path: str):
        self.path = path

        self.loader = cle.Loader(path)

        self.elf = ELF(path)

        self.relro = self.elf.relro
        self.canary = self.elf.canary
        self.nx = self.elf.nx
        self.pie = self.elf.pie

        self.r2 = r2pipe.open(path)
        self.r2.cmd("aaa")
        self.afl = json.loads(self.r2.cmd("aflj"))

    def crossrefs(self, symbol: int):
        return json.loads(self.r2.cmd(f"axtj {symbol}"))
