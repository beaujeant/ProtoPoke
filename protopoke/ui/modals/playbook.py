"""PlaybookModal — create/edit modal for a Playbook configuration."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Switch
from textual.containers import Horizontal, Vertical

logger = logging.getLogger(__name__)

# Sentinel value for the "Custom host:port" option in the session selector.
_CUSTOM = "custom"


@dataclass
class PlaybookResult:
    """Returned by PlaybookModal when the user confirms."""
    label:      str
    host:       str
    port:       int
    tls:        bool
    session_id: str | None
    window:     float
    transport:  str = "tcp"   # "tcp" | "udp"


class PlaybookModal(ModalScreen[PlaybookResult | None]):
    """
    Modal to create or edit a Playbook's connection configuration.

    The user can pick an existing proxy session (host/port/tls pre-filled and
    locked) or choose "Custom" to enter connection details manually.

    Dismisses with a PlaybookResult, or None if cancelled.
    """

    DEFAULT_CSS = """
    PlaybookModal {
        align: center middle;
    }
    PlaybookModal > Vertical {
        width: 72;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    PlaybookModal Label {
        margin-top: 1;
    }
    PlaybookModal Input {
        margin-bottom: 0;
    }
    PlaybookModal Select {
        margin-bottom: 0;
    }
    PlaybookModal .row {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    PlaybookModal .tls-row {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    PlaybookModal .buttons {
        height: 3;
        margin-top: 2;
        align: right middle;
    }
    PlaybookModal Button {
        margin-left: 1;
    }
    PlaybookModal .section-title {
        color: $text-muted;
        margin-top: 1;
    }
    PlaybookModal #session-select {
        width: 1fr;
    }
    """

    def __init__(
        self,
        sessions: list[tuple],  # (id, display_label, host, port[, transport])
        *,
        label:      str        = "",
        host:       str        = "",
        port:       int        = 80,
        tls:        bool       = False,
        session_id: str | None = None,
        window:     float      = 1.0,
        edit:       bool       = False,
        transport:  str        = "tcp",
    ) -> None:
        super().__init__()
        # Normalise sessions to a 5-tuple including transport (default "tcp")
        # so older callers passing (id, label, host, port) still work.
        self._sessions: list[tuple[str, str, str, int, str]] = []
        for entry in sessions:
            if len(entry) >= 5:
                sid, lbl, h, p, tr = entry[0], entry[1], entry[2], entry[3], entry[4]
            else:
                sid, lbl, h, p = entry[0], entry[1], entry[2], entry[3]
                tr = "tcp"
            self._sessions.append((sid, lbl, h, p, tr))
        self._label      = label
        self._host       = host
        self._port       = port
        self._tls        = tls
        self._session_id = session_id
        self._window     = window
        self._edit       = edit
        self._transport  = transport if transport in ("tcp", "udp") else "tcp"

    def compose(self) -> ComposeResult:
        # Filter sessions to those whose transport matches the current
        # playbook transport — UDP playbooks can only bind to UDP sessions
        # and vice versa.
        matching = [s for s in self._sessions if s[4] == self._transport]

        session_options: list[tuple[str, str]] = [
            ("Custom (manual host:port)", _CUSTOM),
        ]
        for sid, lbl, host, port, _tr in matching:
            session_options.append((f"{lbl}  ({host}:{port})", sid))

        initial_session = _CUSTOM
        if self._session_id:
            if any(s[0] == self._session_id for s in matching):
                initial_session = self._session_id

        title         = "Edit Playbook" if self._edit else "New Playbook"
        confirm_label = "Save"
        port_display  = str(self._port) if self._edit and self._port else ""

        with Vertical():
            yield Label(title, classes="modal-title")

            yield Label("Name:")
            yield Input(self._label, placeholder="My Playbook", id="pb-label")

            yield Label("Transport:", classes="section-title")
            yield Select(
                [("TCP", "tcp"), ("UDP", "udp")],
                value=self._transport,
                id="pb-transport",
                allow_blank=False,
            )

            yield Label("Session:", classes="section-title")
            yield Select(
                session_options,
                value=initial_session,
                id="session-select",
            )

            yield Label("Host:", classes="section-title")
            yield Input(self._host, placeholder="127.0.0.1", id="pb-host")

            with Horizontal(classes="row"):
                yield Label("Port: ")
                yield Input(port_display, placeholder="8080", id="pb-port", restrict=r"\d*")

            with Horizontal(classes="tls-row", id="pb-tls-row"):
                yield Label("TLS: ")
                yield Switch(id="pb-tls", value=self._tls)

            with Horizontal(classes="row"):
                yield Label("Window (s): ")
                yield Input(
                    str(self._window),
                    placeholder="1.0",
                    id="pb-window",
                    restrict=r"[\d.]*",
                )

            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button(confirm_label, variant="primary", id="btn-confirm")

    def on_mount(self) -> None:
        self._apply_transport_visibility(self._transport)
        if self._session_id and self._session_id != _CUSTOM:
            self._set_fields_from_session(self._session_id)
        self.query_one("#pb-label", Input).focus()

    def _apply_transport_visibility(self, transport: str) -> None:
        """Hide TLS row for UDP playbooks (no DTLS support)."""
        try:
            self.query_one("#pb-tls-row").display = (transport == "tcp")
        except Exception:
            pass

    def _rebuild_session_options(self) -> None:
        """Rebuild the session selector to match the current transport."""
        select = self.query_one("#session-select", Select)
        matching = [s for s in self._sessions if s[4] == self._transport]
        options: list[tuple[str, str]] = [("Custom (manual host:port)", _CUSTOM)]
        for sid, lbl, host, port, _tr in matching:
            options.append((f"{lbl}  ({host}:{port})", sid))
        select.set_options(options)
        select.value = _CUSTOM
        self._enable_custom_fields()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _set_fields_from_session(self, session_id: str) -> None:
        """Pre-fill host/port from *session_id* and disable those fields."""
        for sid, _lbl, host, port, _tr in self._sessions:
            if sid == session_id:
                self.query_one("#pb-host", Input).value = host
                self.query_one("#pb-port", Input).value = str(port)
                break
        self.query_one("#pb-host", Input).disabled  = True
        self.query_one("#pb-port", Input).disabled  = True
        self.query_one("#pb-tls",  Switch).disabled = True

    def _enable_custom_fields(self) -> None:
        """Re-enable host/port/TLS for manual entry."""
        self.query_one("#pb-host", Input).disabled  = False
        self.query_one("#pb-port", Input).disabled  = False
        self.query_one("#pb-tls",  Switch).disabled = False

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "pb-transport":
            value = event.value
            new_transport = "tcp" if value is Select.BLANK else str(value)
            if new_transport != self._transport:
                self._transport = new_transport
                self._apply_transport_visibility(new_transport)
                self._rebuild_session_options()
            return
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

        label      = self.query_one("#pb-label",  Input).value.strip() or (self._label or "Playbook")
        host       = self.query_one("#pb-host",   Input).value.strip()
        port_str   = self.query_one("#pb-port",   Input).value.strip()
        tls        = self.query_one("#pb-tls",    Switch).value
        window_str = self.query_one("#pb-window", Input).value.strip()

        sid_val    = self.query_one("#session-select", Select).value
        session_id = None if (sid_val is Select.BLANK or sid_val == _CUSTOM) else str(sid_val)

        transport_val = self.query_one("#pb-transport", Select).value
        transport = "tcp" if transport_val is Select.BLANK else str(transport_val)

        if session_id:
            for s_id, _lbl, s_host, s_port, _tr in self._sessions:
                if s_id == session_id:
                    host     = s_host
                    port_str = str(s_port)
                    break
        else:
            if not host:
                logger.error("Host is required for custom connections")
                return

        try:
            port = int(port_str) if port_str else self._port
        except ValueError:
            logger.error("Port must be a number")
            return

        try:
            window = max(0.0, float(window_str)) if window_str else self._window
        except ValueError:
            window = self._window

        # UDP playbooks ignore the TLS toggle.
        if transport == "udp":
            tls = False

        self.dismiss(PlaybookResult(
            label=label,
            host=host,
            port=port,
            tls=tls,
            session_id=session_id,
            window=window,
            transport=transport,
        ))

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)
