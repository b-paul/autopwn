import asyncio
from textual.app import App, ComposeResult
from textual.containers import Grid
from textual.widgets import Header, Footer, Log, Label, Markdown, ListView, ListItem

from binary import Binary
from goals import Goal, WinFunction, SystemFunction, find_goals
from vulns import Vulnerability, StackBufferOverflow, WinFunctionCall, UnconstrainedPrintf, BufferWrite, find_vulns

class SecurityFeatures(Markdown):
    def __init__(self, binary: Binary) -> None:
        super().__init__(f"""- RELRO: {binary.relro}
- PIE: {binary.pie}
- Canaries: {binary.canary}
- NX: {binary.nx}
""")
        self.border_title = "Security Features"


class GoalItem(ListItem):
    def __init__(self, goal: Goal) -> None:
        super().__init__()
        self.goal = goal

    def compose(self) -> ComposeResult:
        match self.goal:
            case WinFunction():
                yield Label(f"Win function: {self.goal.name} @ {self.goal.addr:x}")
            case SystemFunction():
                yield Label(f"system() PLT entry @ {self.goal.addr:x}")


class Goals(ListView):
    def __init__(self, goals: list[Goal]) -> None:
        super().__init__(*[
            GoalItem(goal) for goal in goals
        ])
        self.border_title = "Found goals"


class VulnItem(ListItem):
    def __init__(self, vuln: Vulnerability) -> None:
        super().__init__()
        self.vuln = vuln
        self.border_title = "Found vulnerabilities"

    def compose(self) -> ComposeResult:
        match self.vuln:
            case StackBufferOverflow():
                yield Label(f"Stack Buffer Overflow @ {self.vuln.addr:x} (rip offset: {self.vuln.saved_rip_offset:x}, max write size: {self.vuln.max_write_size})")
            case WinFunctionCall():
                yield Label(f"Win Function Call: {self.vuln.name}")
            case UnconstrainedPrintf():
                yield Label(f"Unconstrained printf() call @ {self.vuln.addr:x}")
            case BufferWrite():
                yield Label(f"Buffer write @ {self.vuln.instruction_addr:x} (type: {self.vuln.buffer_type}, addr: {self.vuln.buffer_addr:x}, len: {self.vuln.buffer_len})")
            

class Vulns(ListView):
    def __init__(self, vulns: list[Vulnerability]) -> None:
        super().__init__(*[
            VulnItem(vuln) for vuln in vulns
        ])


class Autopwn(App):
    CSS_PATH = "autopwn.tcss"

    def __init__(self, args) -> None:
        super().__init__()
        self.binary_path = args.path[0]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Grid(id="content")
        yield Log(id="log")
        yield Footer()

    def on_mount(self) -> None:
        asyncio.create_task(self._load_binary())

    async def _load_binary(self) -> None:
        self.query_one("#log").write_line("Loading binary...")
        self.binary = await asyncio.to_thread(lambda: Binary(self.binary_path))
        self.query_one("#log").write_line("Loaded!")

        self.query_one("#content").border_title = f"Binary: {self.binary.path}"
        self.query_one("#content").mount(SecurityFeatures(self.binary))

        self.query_one("#log").write_line("Finding goals...")
        self.goals = await asyncio.to_thread(lambda: find_goals(self.binary))
        self.query_one("#content").mount(Goals(self.goals))

        self.query_one("#log").write_line("Finding vulnerabilities...")
        self.vulns = await asyncio.to_thread(lambda: find_vulns(self.binary, self.goals))
        self.query_one("#content").mount(Vulns(self.vulns))
