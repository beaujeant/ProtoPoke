"""RequestModal — unified create/edit modal for a forge request."""

from __future__ import annotations

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Switch
from textual.containers import Horizontal, Vertical

# Sentinel value for the "Custom host:port" option in the session selector.
_CUSTOM = "custom"


@dataclass
class RequestResult:
    """Returned by RequestModal when the user confirms."""
    label:      str
    host:       str
    port:       int
    tls:        bool
    direction:  str
    session_id: str | None = None
    window:     float = 1.0


class RequestModal(ModalScreen[RequestResult | None]):
    """
    Modal to create or edit a Forge request.

    Pass ``edit=True`` together with pre-filled keyword arguments to open in
    edit mode; omit them (leave defaults) for create mode.

    In both modes the user can:
      - Set a name / label for the tab
      - Pick an existing session (host:port pre-filled and locked) or enter a
        custom host:port
      - Toggle TLS
      - Choose the injection direction (→ To Server / ← To Client)

    Dismisses with a RequestResult, or None if cancelled.
    """

    DEFAULT_CSS = """
    RequestModal > Vertical {
        width: 72;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    RequestModal Label {
        margin-top: 1;
    }
    RequestModal Input {
        margin-bottom: 0;
    }
    RequestModal Select {
        margin-bottom: 0;
    }
    RequestModal .row {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    RequestModal .tls-row {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    RequestModal .buttons {
        height: 3;
        margin-top: 2;
        align: right middle;
    }
    RequestModal Button {
        margin-left: 1;
    }
    RequestModal .section-title {
        color: $text-muted;
        margin-top: 1;
    }
    RequestModal #session-select {
        width: 1fr;
    }
    RequestModal #direction-select {
        width: 1fr;
    }
    """

    def __init__(
        self,
        sessions: list[tuple[str, str, str, int]],  # (id, display_label, host, port)
        *,
        label:      str       = "",
        host:       str       = "",
        port:       int       = 80,
        tls:        bool      = False,
        direction:  str       = "to_server",
        session_id: str | None = None,
        window:     float     = 1.0,
        edit:       bool      = False,
    ) -> None:
        super().__init__()
        self._sessions   = sessions
        self._label      = label
        self._host       = host
        self._port       = port
        self._tls        = tls
        self._direction  = direction
        self._session_id = session_id
        self._window     = window
        self._edit       = edit

    def compose(self) -> ComposeResult:
        session_options: list[tuple[str, str]] = [
            ("Custom (manual host:port)", _CUSTOM),
        ]
        for sid, lbl, host, port in self._sessions:
            session_options.append((f"{lbl}  ({host}:{port})", sid))

        # Determine which session to pre-select
        initial_session = _CUSTOM
        if self._session_id:
            if any(sid == self._session_id for sid, *_ in self._sessions):
                initial_session = self._session_id

        title         = "Edit Request" if self._edit else "New Forge Request"
        confirm_label = "Save"         if self._edit else "Create"

        # In create mode show an empty port field (placeholder visible);
        # in edit mode pre-fill with the current port value.
        port_display = str(self._port) if self._edit else ""

        with Vertical():
            yield Label(title, classes="modal-title")

            yield Label("Name:")
            yield Input(self._label, placeholder="My Request", id="req-label")

            yield Label("Session:", classes="section-title")
            yield Select(
                session_options,
                value=initial_session,
                id="session-select",
            )

            yield Label("Host:", classes="section-title")
            yield Input(self._host, placeholder="127.0.0.1", id="req-host")

            with Horizontal(classes="row"):
                yield Label("Port: ")
                yield Input(port_display, placeholder="8080", id="req-port", restrict=r"\d*")

            with Horizontal(classes="tls-row"):
                yield Label("TLS: ")
                yield Switch(id="req-tls", value=self._tls)

            yield Label("Direction:", classes="section-title")
            yield Select(
                [
                    ("→ To Server", "to_server"),
                    ("← To Client", "to_client"),
                ],
                value=self._direction,
                id="direction-select",
            )

            with Horizontal(classes="row"):
                yield Label("Window (s): ")
                yield Input(str(self._window), placeholder="1.0", id="req-window", restrict=r"[\d.]*")

            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button(confirm_label, variant="primary", id="btn-confirm")

    def on_mount(self) -> None:
        if self._session_id:
            self._set_fields_from_session(self._session_id)
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
        self.query_one("#req-host", Input).disabled  = True
        self.query_one("#req-port", Input).disabled  = True
        self.query_one("#req-tls",  Switch).disabled = True

    def _enable_custom_fields(self) -> None:
        """Re-enable host/port/TLS for manual entry."""
        self.query_one("#req-host", Input).disabled  = False
        self.query_one("#req-port", Input).disabled  = False
        self.query_one("#req-tls",  Switch).disabled = False

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

        label      = self.query_one("#req-label",       Input).value.strip() or (self._label or "Request")
        host       = self.query_one("#req-host",        Input).value.strip()
        port_str   = self.query_one("#req-port",        Input).value.strip()
        tls        = self.query_one("#req-tls",         Switch).value
        direction  = str(self.query_one("#direction-select", Select).value)
        window_str = self.query_one("#req-window",      Input).value.strip()

        sid_val    = self.query_one("#session-select", Select).value
        session_id = None if (sid_val is Select.BLANK or sid_val == _CUSTOM) else str(sid_val)

        # When a session is selected, derive host/port from that session.
        if session_id:
            for s_id, _lbl, s_host, s_port in self._sessions:
                if s_id == session_id:
                    host     = s_host
                    port_str = str(s_port)
                    break
        else:
            if not host:
                self.notify("Host is required.", severity="error")
                return

        try:
            port = int(port_str) if port_str else self._port
        except ValueError:
            self.notify("Port must be a number.", severity="error")
            return

        if direction is Select.BLANK:
            direction = self._direction

        try:
            window = max(0.0, float(window_str)) if window_str else self._window
        except ValueError:
            window = self._window

        self.dismiss(RequestResult(
            label=label,
            host=host,
            port=port,
            tls=tls,
            direction=direction,
            session_id=session_id,
            window=window,
        ))

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)
