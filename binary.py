import cle
import json
import r2pipe
from pwn import ELF

class Binary():
    def __init__(self, path: str):
        self.path = path

        self.loader = cle.Loader(path)

        elf = ELF(path, checksec=False)

        self.relro = elf.relro
        self.canary = elf.canary
        self.nx = elf.nx
        self.pie = elf.pie

        self.r2 = r2pipe.open(path)
        self.r2.cmd("aaa")
        self.afl = json.loads(self.r2.cmd("aflj"))

    def crossrefs(self, symbol: int):
        return json.loads(self.r2.cmd(f"axtj {symbol}"))
