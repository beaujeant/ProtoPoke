"""NewRequestModal — create a repeater request from scratch or from a session."""

from __future__ import annotations

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Switch, Static
from textual.containers import Horizontal, Vertical


@dataclass
class NewRequestResult:
    """Returned by NewRequestModal when the user confirms."""
    label:      str
    host:       str
    port:       int
    tls:        bool
    # If derived from an existing session, these are set:
    session_id: str | None = None


class NewRequestModal(ModalScreen[NewRequestResult | None]):
    """
    Modal to configure a new Repeater request.

    The user can either:
      (a) Select an existing session as the destination (host:port pre-filled)
      (b) Enter an arbitrary host:port

    Dismisses with a NewRequestResult, or None if cancelled.
    """

    DEFAULT_CSS = """
    NewRequestModal > Vertical {
        width: 72;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    NewRequestModal Label {
        margin-top: 1;
    }
    NewRequestModal Input {
        margin-bottom: 0;
    }
    NewRequestModal Select {
        margin-bottom: 0;
    }
    NewRequestModal .row {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    NewRequestModal .tls-row {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    NewRequestModal .buttons {
        height: 3;
        margin-top: 2;
        align: right middle;
    }
    NewRequestModal Button {
        margin-left: 1;
    }
    NewRequestModal .section-title {
        color: $text-muted;
        margin-top: 1;
    }
    """

    def __init__(
        self,
        sessions: list[tuple[str, str, str, int]],  # (id, label, host, port)
    ) -> None:
        super().__init__()
        # sessions: list of (session_id, display_label, host, port)
        self._sessions = sessions

    def compose(self) -> ComposeResult:
        session_options: list[tuple[str, str]] = [("", "— custom host:port —")]
        for sid, label, host, port in self._sessions:
            session_options.append((sid, f"{label}  ({host}:{port})"))

        with Vertical():
            yield Label("New Repeater Request", classes="modal-title")

            yield Label("Label (tab name):")
            yield Input(placeholder="My Request", id="req-label")

            yield Label("From session (or leave blank for custom):", classes="section-title")
            yield Select(
                [(lbl, sid) for sid, lbl in session_options],
                value="",
                id="session-select",
            )

            yield Label("Host:", classes="section-title")
            yield Input(placeholder="127.0.0.1", id="req-host")

            with Horizontal(classes="row"):
                yield Label("Port: ")
                yield Input(placeholder="8080", id="req-port", restrict=r"\d*")

            with Horizontal(classes="tls-row"):
                yield Label("TLS: ")
                yield Switch(id="req-tls", value=False)

            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Create", variant="primary", id="btn-create")

    def on_mount(self) -> None:
        self.query_one("#req-label", Input).focus()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "session-select":
            return
        sid = event.value
        if not sid:
            return
        # Pre-fill host/port from the selected session
        for session_id, _label, host, port in self._sessions:
            if session_id == sid:
                self.query_one("#req-host", Input).value = host
                self.query_one("#req-port", Input).value = str(port)
                break

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
            return

        label = self.query_one("#req-label", Input).value.strip() or "Request"
        host  = self.query_one("#req-host", Input).value.strip()
        port_str = self.query_one("#req-port", Input).value.strip()
        tls   = self.query_one("#req-tls", Switch).value
        sid   = self.query_one("#session-select", Select).value or None

        if not host:
            self.notify("Host is required.", severity="error")
            return
        try:
            port = int(port_str) if port_str else 80
        except ValueError:
            self.notify("Port must be a number.", severity="error")
            return

        self.dismiss(NewRequestResult(
            label=label,
            host=host,
            port=port,
            tls=tls,
            session_id=sid if sid != "" else None,
        ))
