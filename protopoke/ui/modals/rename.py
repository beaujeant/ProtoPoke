"""RenameModal — simple single-input modal for renaming a forge tab."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label
from textual.containers import Horizontal, Vertical


class RenameModal(ModalScreen[str | None]):
    """
    Minimal modal that prompts for a new name.

    Dismisses with the new name string, or None if cancelled.
    """

    DEFAULT_CSS = """
    RenameModal > Vertical {
        width: 50;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    RenameModal Label {
        margin-bottom: 1;
    }
    RenameModal .buttons {
        height: 3;
        margin-top: 1;
        align: right middle;
    }
    RenameModal Button {
        margin-left: 1;
    }
    """

    def __init__(self, current_name: str) -> None:
        super().__init__()
        self._current_name = current_name

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Rename request tab:")
            yield Input(self._current_name, id="rename-input")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Rename", variant="primary", id="btn-ok")

    def on_mount(self) -> None:
        inp = self.query_one("#rename-input", Input)
        inp.focus()
        inp.action_select_all()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-ok":
            name = self.query_one("#rename-input", Input).value.strip()
            self.dismiss(name or None)
        else:
            self.dismiss(None)

    def on_key(self, event) -> None:
        if event.key == "enter":
            name = self.query_one("#rename-input", Input).value.strip()
            self.dismiss(name or None)
        elif event.key == "escape":
            self.dismiss(None)
