"""FrameEditModal — edit a playbook frame's label and direction."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static
from textual.containers import Horizontal, Vertical


class FrameEditModal(ModalScreen[tuple[str, str] | None]):
    """
    Modal for editing a PlaybookFrame's label and direction.

    Dismisses with ``(label, direction)`` on save, or ``None`` if cancelled.
    ``direction`` is one of ``"client_to_server"`` or ``"server_to_client"``.
    """

    DEFAULT_CSS = """
    FrameEditModal > Vertical {
        width: 52;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    FrameEditModal .modal-title {
        text-style: bold;
        margin-bottom: 1;
    }
    FrameEditModal Label {
        margin-top: 1;
        margin-bottom: 0;
    }
    FrameEditModal Input {
        margin-bottom: 1;
    }
    FrameEditModal #dir-row {
        height: 3;
        align: left middle;
        margin-bottom: 1;
    }
    FrameEditModal #dir-row Label {
        margin-top: 0;
        margin-right: 1;
        width: 11;
    }
    FrameEditModal .buttons {
        height: 3;
        margin-top: 1;
        align: right middle;
    }
    FrameEditModal Button {
        margin-left: 1;
    }
    """

    def __init__(self, label: str, direction: str) -> None:
        super().__init__()
        self._label = label
        self._direction = direction  # "client_to_server" | "server_to_client"

    def _dir_label(self) -> str:
        return "→C→S" if self._direction == "client_to_server" else "←S→C"

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("Edit Frame", classes="modal-title")
            yield Label("Label:")
            yield Input(self._label, id="frame-label-input", placeholder="frame name")
            with Horizontal(id="dir-row"):
                yield Label("Direction:")
                yield Button(self._dir_label(), id="btn-dir-toggle", compact=True)
            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Save",   variant="primary",  id="btn-save")

    def on_mount(self) -> None:
        inp = self.query_one("#frame-label-input", Input)
        inp.focus()
        inp.action_select_all()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == "btn-dir-toggle":
            event.stop()
            self._direction = (
                "server_to_client"
                if self._direction == "client_to_server"
                else "client_to_server"
            )
            self.query_one("#btn-dir-toggle", Button).label = self._dir_label()
        elif bid == "btn-save":
            label = self.query_one("#frame-label-input", Input).value.strip()
            self.dismiss((label, self._direction))
        else:
            self.dismiss(None)

    def on_key(self, event) -> None:
        if event.key == "enter":
            label = self.query_one("#frame-label-input", Input).value.strip()
            self.dismiss((label, self._direction))
        elif event.key == "escape":
            self.dismiss(None)
