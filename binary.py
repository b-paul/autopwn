import cle
from pwn import ELF

class Binary():
    def __init__(self, path: str):
        self.path = path

        self.loader = cle.Loader(path)

        elf = ELF(path)

        self.relro = elf.relro
        self.canary = elf.canary
        self.nx = elf.nx
        self.pie = elf.pie
