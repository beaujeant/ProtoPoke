"""Generic yes/no confirmation modal."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static
from textual.containers import Horizontal, Vertical


class ConfirmModal(ModalScreen[bool]):
    """
    A simple yes/no confirmation dialog.

    Dismisses with ``True`` when the user confirms, ``False`` otherwise.
    """

    DEFAULT_CSS = """
    ConfirmModal {
        align: center middle;
    }
    ConfirmModal > Vertical {
        width: 60;
        height: auto;
        border: thick $warning;
        padding: 1 2;
        background: $surface;
    }
    ConfirmModal .modal-title {
        text-style: bold;
        margin-bottom: 1;
        color: $warning;
    }
    ConfirmModal .modal-body {
        margin-bottom: 1;
        color: $text;
    }
    ConfirmModal .buttons {
        height: 3;
        margin-top: 1;
        align: right middle;
    }
    ConfirmModal .buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        title: str,
        body: str,
        confirm_label: str = "Yes",
        cancel_label: str = "Cancel",
        confirm_variant: str = "error",
    ) -> None:
        super().__init__()
        self._title = title
        self._body = body
        self._confirm_label = confirm_label
        self._cancel_label = cancel_label
        self._confirm_variant = confirm_variant

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._title, classes="modal-title")
            yield Static(self._body, classes="modal-body")
            with Horizontal(classes="buttons"):
                yield Button(self._cancel_label, variant="default", id="btn-cancel")
                yield Button(self._confirm_label, variant=self._confirm_variant, id="btn-confirm")

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "btn-confirm")
