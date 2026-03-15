"""EditRequestModal — edit an existing repeater request's name and target settings."""

from __future__ import annotations

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Switch
from textual.containers import Horizontal, Vertical

# Sentinel for the "Custom host:port" option
_CUSTOM = "custom"


@dataclass
class EditRequestResult:
    """Returned by EditRequestModal when the user confirms."""
    label:      str
    host:       str
    port:       int
    tls:        bool
    direction:  str
    session_id: str | None = None


class EditRequestModal(ModalScreen[EditRequestResult | None]):
    """
    Modal to edit an existing Repeater request.

    Allows changing:
      - Name (tab label)
      - Session (active session or Custom for manual host:port)
      - Host / Port / TLS  (disabled when an active session is selected)
      - Direction (to_server / to_client)

    If Custom is selected the user enters host/port manually and a new
    dedicated repeater session is created on the next send.

    Dismisses with an EditRequestResult, or None if cancelled.
    """

    DEFAULT_CSS = """
    EditRequestModal > Vertical {
        width: 72;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    EditRequestModal Label {
        margin-top: 1;
    }
    EditRequestModal Input {
        margin-bottom: 0;
    }
    EditRequestModal Select {
        margin-bottom: 0;
    }
    EditRequestModal .row {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    EditRequestModal .tls-row {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    EditRequestModal .buttons {
        height: 3;
        margin-top: 2;
        align: right middle;
    }
    EditRequestModal Button {
        margin-left: 1;
    }
    EditRequestModal .section-title {
        color: $text-muted;
        margin-top: 1;
    }
    EditRequestModal #session-select {
        width: 1fr;
    }
    EditRequestModal #direction-select {
        width: 1fr;
    }
    """

    def __init__(
        self,
        current_label:     str,
        current_host:      str,
        current_port:      int,
        current_tls:       bool,
        current_direction: str,
        current_session_id: str | None,
        sessions: list[tuple[str, str, str, int]],  # (id, display_label, host, port)
    ) -> None:
        super().__init__()
        self._current_label     = current_label
        self._current_host      = current_host
        self._current_port      = current_port
        self._current_tls       = current_tls
        self._current_direction = current_direction
        self._current_session_id = current_session_id
        self._sessions          = sessions

    def compose(self) -> ComposeResult:
        session_options: list[tuple[str, str]] = [
            ("Custom (manual host:port)", _CUSTOM),
        ]
        for sid, lbl, host, port in self._sessions:
            session_options.append((f"{lbl}  ({host}:{port})", sid))

        # Determine which session to pre-select
        initial_session = _CUSTOM
        if self._current_session_id:
            if any(sid == self._current_session_id for sid, *_ in self._sessions):
                initial_session = self._current_session_id

        with Vertical():
            yield Label("Edit Request", classes="modal-title")

            yield Label("Name:")
            yield Input(self._current_label, id="req-label")

            yield Label("Session:", classes="section-title")
            yield Select(
                session_options,
                value=initial_session,
                id="session-select",
            )

            yield Label("Host:", classes="section-title")
            yield Input(
                self._current_host,
                placeholder="127.0.0.1",
                id="req-host",
            )

            with Horizontal(classes="row"):
                yield Label("Port: ")
                yield Input(
                    str(self._current_port),
                    placeholder="8080",
                    id="req-port",
                    restrict=r"\d*",
                )

            with Horizontal(classes="tls-row"):
                yield Label("TLS: ")
                yield Switch(id="req-tls", value=self._current_tls)

            yield Label("Direction:", classes="section-title")
            yield Select(
                [
                    ("→ To Server", "to_server"),
                    ("← To Client", "to_client"),
                ],
                value=self._current_direction,
                id="direction-select",
            )

            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Save",   variant="primary",  id="btn-save")

    def on_mount(self) -> None:
        # Disable host/port/TLS if an existing session is already selected
        if self._current_session_id:
            self._set_fields_from_session(self._current_session_id)
        self.query_one("#req-label", Input).focus()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _set_fields_from_session(self, session_id: str) -> None:
        """Pre-fill host/port from *session_id* and disable the fields."""
        for sid, _lbl, host, port in self._sessions:
            if sid == session_id:
                self.query_one("#req-host", Input).value = host
                self.query_one("#req-port", Input).value = str(port)
                break
        self.query_one("#req-host",  Input).disabled  = True
        self.query_one("#req-port",  Input).disabled  = True
        self.query_one("#req-tls",   Switch).disabled = True

    def _enable_custom_fields(self) -> None:
        """Re-enable host/port/TLS for manual entry."""
        self.query_one("#req-host",  Input).disabled  = False
        self.query_one("#req-port",  Input).disabled  = False
        self.query_one("#req-tls",   Switch).disabled = False

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "session-select":
            return
        value = event.value
        if value is Select.BLANK or value == _CUSTOM:
            self._enable_custom_fields()
        else:
            self._set_fields_from_session(str(value))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
            return

        label     = self.query_one("#req-label", Input).value.strip() or self._current_label
        host      = self.query_one("#req-host",  Input).value.strip()
        port_str  = self.query_one("#req-port",  Input).value.strip()
        tls       = self.query_one("#req-tls",   Switch).value
        direction = str(self.query_one("#direction-select", Select).value)

        sid_val    = self.query_one("#session-select", Select).value
        session_id = None if (sid_val is Select.BLANK or sid_val == _CUSTOM) else str(sid_val)

        # When a session is selected, derive host/port from the sessions list
        if session_id:
            for s_id, _lbl, s_host, s_port in self._sessions:
                if s_id == session_id:
                    host = s_host
                    port_str = str(s_port)
                    break
        else:
            if not host:
                self.notify("Host is required.", severity="error")
                return

        try:
            port = int(port_str) if port_str else self._current_port
        except ValueError:
            self.notify("Port must be a number.", severity="error")
            return

        if direction is Select.BLANK:
            direction = self._current_direction

        self.dismiss(EditRequestResult(
            label=label,
            host=host,
            port=port,
            tls=tls,
            direction=direction,
            session_id=session_id,
        ))

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)
