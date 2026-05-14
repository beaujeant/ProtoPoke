"""CreateSessionModal — prompt for host/port/TLS to open a persistent TCP forge session."""

from __future__ import annotations

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Switch
from textual.containers import Horizontal, Vertical


@dataclass
class CreateSessionResult:
    """Returned by CreateSessionModal when the user confirms."""
    host: str
    port: int
    tls:  bool


class CreateSessionModal(ModalScreen["CreateSessionResult | None"]):
    """
    Modal that prompts for host, port, and TLS to open a new persistent
    TCP session.  Dismisses with a :class:`CreateSessionResult` or ``None``
    if cancelled.
    """

    DEFAULT_CSS = """
    CreateSessionModal {
        align: center middle;
    }
    CreateSessionModal > Vertical {
        width: 56;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    CreateSessionModal Label {
        margin-top: 1;
    }
    CreateSessionModal .modal-title {
        text-style: bold;
        margin-bottom: 1;
        margin-top: 0;
        color: $text;
    }
    CreateSessionModal .row {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    CreateSessionModal .buttons {
        height: 3;
        margin-top: 2;
        align: right middle;
    }
    CreateSessionModal Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        host: str  = "",
        port: int  = 80,
        tls:  bool = False,
    ) -> None:
        super().__init__()
        self._host = host
        self._port = port
        self._tls  = tls

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Create TCP Session", classes="modal-title")

            yield Label("Host:")
            yield Input(self._host, placeholder="127.0.0.1", id="cs-host")

            with Horizontal(classes="row"):
                yield Label("Port: ")
                yield Input(
                    str(self._port) if self._port else "",
                    placeholder="8080",
                    id="cs-port",
                    restrict=r"\d*",
                )

            with Horizontal(classes="row"):
                yield Label("TLS:  ")
                yield Switch(id="cs-tls", value=self._tls)

            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="cs-btn-cancel")
                yield Button("Create", variant="primary", id="cs-btn-create")

    def on_mount(self) -> None:
        self.query_one("#cs-host", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cs-btn-cancel":
            self.dismiss(None)
            return
        if event.button.id == "cs-btn-create":
            self._submit()

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)
        elif event.key == "enter":
            self._submit()

    def _submit(self) -> None:
        host = self.query_one("#cs-host", Input).value.strip()
        port_str = self.query_one("#cs-port", Input).value.strip()
        tls = self.query_one("#cs-tls", Switch).value

        if not host:
            self.app.notify("Host is required", severity="error")
            return
        try:
            port = int(port_str)
        except ValueError:
            self.app.notify("Port must be a number", severity="error")
            return
        if not (0 < port < 65536):
            self.app.notify("Port must be between 1 and 65535", severity="error")
            return

        self.dismiss(CreateSessionResult(host=host, port=port, tls=tls))
