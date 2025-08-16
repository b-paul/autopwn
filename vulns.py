from binary import Binary
from dataclasses import dataclass
from typing import Optional

class Vulnerability():
    """Abstract class for potentially usable vulnerabilities"""

@dataclass
class StackBufferOverflow(Vulnerability):
    addr: int
    saved_rip_offset: int
    max_write_size: Optional[int]

def find_vulns(bin: Binary) -> list[Vulnerability]:
    pass
