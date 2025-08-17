import asyncio
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, Log, Static, Markdown

from binary import Binary

class BinaryInfo(Markdown):
    def __init__(self, binary: Binary) -> None:
        super().__init__(f"""# Binary: {binary.path}

## Security features:

- RELRO: {binary.relro}
- PIE: {binary.pie}
- Canaries: {binary.canary}
- NX: {binary.nx}
""")

class Autopwn(App):
    CSS_PATH = "autopwn.tcss"

    def __init__(self, args) -> None:
        super().__init__()
        self.binary_path = args.path[0]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(id="content")
        yield Log(id="log")
        yield Footer()

    def on_mount(self) -> None:
        asyncio.create_task(self._load_binary())

    async def _load_binary(self) -> None:
        self.query_one("#log").write_line("Loading binary...")
        self.binary = await asyncio.to_thread(lambda: Binary(self.binary_path))
        self.query_one("#log").write_line("Loaded!")

        self.query_one("#content").mount(BinaryInfo(self.binary))
