from textual.app import App, ComposeResult
from textual.widgets import Header, Footer

class Autopwn(App):
    def __init__(self, args):
        super().__init__()
        self.binary_path = args.path

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()
