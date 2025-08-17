import asyncio
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Grid
from textual.widgets import Header, Footer, Log, Label, Markdown, ListView, ListItem, Collapsible

from binary import Binary
from exploit import exploit, Remote, ExploitProgress
from goals import Goal, WinFunction, SystemFunction, find_goals
from vulns import Vulnerability, StackBufferOverflow, WinFunctionCall, UnconstrainedPrintf, BufferWrite, ShString, find_vulns

class SecurityFeatures(Grid):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.border_title = "Security Features"

    def compose(self) -> ComposeResult:
        yield Label("RELRO:")
        yield Label("(No binary loaded)", id="relro")
        yield Label("PIE:")
        yield Label("(No binary loaded)", id="pie")
        yield Label("Canaries:")
        yield Label("(No binary loaded)", id="canaries")
        yield Label("NX:")
        yield Label("(No binary loaded)", id="nx")

    def update_binary(self, binary: Binary):
        if binary.relro == "Full":
            self.query_one("#relro").styles.color = "lime"
        elif binary.relro == "Partial":
            self.query_one("#relro").styles.color = "yellow"
        else:
            self.query_one("#relro").styles.color = "red"
        self.query_one("#relro").update(str(binary.relro))

        if binary.pie:
            self.query_one("#pie").styles.color = "lime"
        else:
            self.query_one("#pie").styles.color = "red"
        self.query_one("#pie").update(str(binary.pie))

        if binary.canary:
            self.query_one("#canaries").styles.color = "lime"
        else:
            self.query_one("#canaries").styles.color = "red"
        self.query_one("#canaries").update(str(binary.canary))

        if binary.nx:
            self.query_one("#nx").styles.color = "lime"
        else:
            self.query_one("#nx").styles.color = "red"
        self.query_one("#nx").update(str(binary.nx))


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
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.border_title = "Found goals"

    def append(self, goal: Goal):
        super().append(GoalItem(goal))


class VulnItem(ListItem):
    def __init__(self, vuln: Vulnerability) -> None:
        super().__init__()
        self.vuln = vuln

    def compose(self) -> ComposeResult:
        match self.vuln:
            case StackBufferOverflow():
                with Collapsible(title=f"Stack Buffer Overflow @ 0x{self.vuln.addr:x}"):
                    yield Label(f"rip offset: {self.vuln.saved_rip_offset:x}")
                    yield Label(f"Max write size: {self.vuln.max_write_size}")
            case WinFunctionCall():
                with Collapsible(title=f"Win Function Call @ ???"):
                    yield Label(f"Win function: {self.vuln.name}")
            case UnconstrainedPrintf():
                with Collapsible(title=f"Unconstrained printf() call @ 0x{self.vuln.addr:x}"):
                    pass
            case BufferWrite():
                with Collapsible(title=f"Buffer write @ 0x{self.vuln.instruction_addr:x}"):
                    yield Label(f"Buffer type: {self.vuln.buffer_type}")
                    yield Label(f"Buffer address: 0x{self.vuln.buffer_addr:x}")
                    yield Label(f"Buffer length: {self.vuln.buffer_len}")
            case ShString():
                with Collapsible(title=f"\"sh\" string @ {self.vuln.addr:x}"):
                    pass
            

class Vulns(ListView):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.border_title = "Found vulnerabilities"

    def append(self, vuln: Vulnerability):
        super().append(VulnItem(vuln))


class TuiExploitProgress(ExploitProgress):
    def __init__(self, log: Log) -> None:
        super().__init__(True)
        self.log = log

    def starting_goal(self, goal: Goal):
        self.log.write_line(f"Starting goal {goal}")

    def achieved_goal(self, goal: Goal):
        self.log.write_line(f"Achieved goal {goal}")

    def starting_vuln(self, vuln: Vulnerability):
        self.log.write_line(f"Using primitive {vuln}")

    def giving_up_on_vuln(self, vuln: Vulnerability):
        self.log.write_line(f"Gave up on using primitive {vuln}")

    def print(self, message: str):
        self.log.write_line(message)


class Autopwn(App):
    CSS_PATH = "autopwn.tcss"
    BINDINGS = [("l", "load_binary", "Load binary"), ("e", "exploit_binary", "Exploit binary")]

    def __init__(self, binary_path: str, remote: Remote) -> None:
        super().__init__()
        self.binary_path = binary_path
        self.remote = remote
        self.ready = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="content"):
            with Horizontal(id="info"):
                yield SecurityFeatures(id="security")
            with Horizontal(id="exploits"):
                yield Goals(id="goals")
                yield Vulns(id="vulns")
        yield Log(id="log")
        yield Footer()

    def on_mount(self) -> None:
        asyncio.create_task(self._load_binary())

    async def action_exploit_binary(self) -> None:
        self.ready = False
        self.refresh_bindings()
        output = await asyncio.to_thread(lambda: exploit(self.binary, self.goals, self.vulns, self.remote, TuiExploitProgress(self.query_one("#log"))))
        if output is not None:
            self.query_one("#log").write_line(f"Flag: {output.decode()}")
        self.ready = True
        self.refresh_bindings()

    def check_action(self, action: str, parameters: tuple[object, ...]):
        if action == "exploit_binary" and not self.ready:
            return False
        return True

    async def _load_binary(self) -> None:
        self.query_one("#log").write_line("Loading binary...")
        self.binary = await asyncio.to_thread(lambda: Binary(self.binary_path))
        self.query_one("#log").write_line("Loaded!")

        self.query_one("#content").border_title = f"Binary: {self.binary.path}"
        self.query_one("#security").update_binary(self.binary)

        self.query_one("#log").write_line("Finding goals...")
        self.goals = list(await asyncio.to_thread(lambda: find_goals(self.binary)))
        for goal in self.goals:
            self.query_one("#goals").append(goal)

        self.query_one("#log").write_line("Finding vulnerabilities...")
        self.vulns = list(await asyncio.to_thread(lambda: find_vulns(self.binary, self.goals)))
        for vuln in self.vulns:
            self.query_one("#vulns").append(vuln)

        self.query_one("#log").write_line("Done!")
        self.ready = True
        self.refresh_bindings()
