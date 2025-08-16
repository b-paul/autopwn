from binary import Binary

class Vulnerability():
    """Abstract class for potentially usable vulnerabilities"""

class DirectFgetsStackOverflow(Vulnerability):
    """A call to fgets into a stack buffer that overflows which has no reach condition"""
    def __init__(self, buf_size: int, write_size: int):
        self._buf_size = buf_size
        self._write_size = write_size

def find_vulns(bin: Binary) -> list[Vulnerability]:
    pass
