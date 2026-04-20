"""ConfigTab — forwarder configuration panel (DataTable + modal editor)."""

from __future__ import annotations

import logging

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input, Label, Select, Static, Switch
from textual.containers import Horizontal, Vertical
from textual.message import Message

from ...config import ForwarderConfig
from ...mcp.host import MCPSettings
from ..modals.forwarder_edit import ForwarderEditModal

logger = logging.getLogger(__name__)


_LOG_LEVEL_OPTIONS = [
    ("DEBUG", "DEBUG"),
    ("INFO", "INFO"),
    ("WARNING", "WARNING"),
    ("ERROR", "ERROR"),
]


class ConfigTab(Widget):
    """
    Tab 1 — Forwarder configuration.

    A DataTable lists all configured forwarders.  Below the table are
    Add / Edit / Delete / On-Off buttons, and beneath those the global
    log-level selector.

    Posts messages for all user actions so the app can react (start/stop
    forwarders, rebuild the API, persist project state, etc.).
    """

    # -- Messages -----------------------------------------------------------

    class ForwarderAdded(Message):
        """User added a new forwarder via the Add modal."""
        def __init__(self, forwarder: ForwarderConfig) -> None:
            super().__init__()
            self.forwarder = forwarder

    class ForwarderRemoved(Message):
        """User removed a forwarder."""
        def __init__(self, forwarder_name: str) -> None:
            super().__init__()
            self.forwarder_name = forwarder_name

    class ForwarderApplied(Message):
        """User edited and saved a forwarder."""
        def __init__(self, old_name: str, forwarder: ForwarderConfig) -> None:
            super().__init__()
            self.old_name = old_name
            self.forwarder = forwarder

    class ForwarderEnabled(Message):
        """User toggled a forwarder's enabled state."""
        def __init__(self, forwarder_name: str, enabled: bool) -> None:
            super().__init__()
            self.forwarder_name = forwarder_name
            self.enabled = enabled

    class MCPSettingsChanged(Message):
        """User changed the embedded MCP server settings."""
        def __init__(self, settings: MCPSettings) -> None:
            super().__init__()
            self.settings = settings


    # -- CSS ----------------------------------------------------------------

    DEFAULT_CSS = """
    ConfigTab .pane-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
        text-style: bold;
    }
    ConfigTab #cfg-table {
        height: 1fr;
        min-height: 6;
    }
    ConfigTab .cfg-buttons {
        height: 3;
        margin: 1;
        align: left middle;
    }
    ConfigTab .cfg-buttons Button {
        margin-right: 1;
    }
    ConfigTab .cfg-spacer {
        width: 1fr;
    }
    ConfigTab .cfg-buttons Label {
        width: auto;
        padding: 0 1;
    }
    ConfigTab .cfg-buttons Select {
        width: 20;
    }
    ConfigTab .mcp-row {
        height: 3;
        margin: 0 1;
        align: left middle;
    }
    ConfigTab .mcp-row Label {
        width: auto;
        padding: 0 1;
    }
    ConfigTab .mcp-row Switch {
        padding: 0;
        border: none;
    }
    ConfigTab .mcp-row Switch > .switch--slider {
        color: dodgerblue;
        background: darkslateblue;
    }
    ConfigTab .mcp-row Input {
        width: 20;
        margin-right: 1;
    }
    ConfigTab #mcp-url {
        width: 1fr;
        color: $text-muted;
    }
    """

    def __init__(
        self,
        forwarders: list[ForwarderConfig],
        mcp_settings: MCPSettings | None = None,
        *,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self._forwarders: list[ForwarderConfig] = list(forwarders)
        # Track running state per forwarder name → listen address string
        self._running_fwds: dict[str, str] = {}
        # Track last upstream error per forwarder name (empty string = no error)
        self._fwd_errors: dict[str, str] = {}
        self._mcp_settings: MCPSettings = mcp_settings or MCPSettings()

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("  Forwarders", classes="pane-header")
            yield DataTable(id="cfg-table", cursor_type="row")

            with Horizontal(classes="cfg-buttons"):
                yield Button("+ Add", variant="success", id="btn-cfg-add")
                yield Button("✎ Edit", variant="primary", id="btn-cfg-edit")
                yield Button("✕ Delete", variant="error", id="btn-cfg-remove")
                yield Button("⏻ On/Off", id="btn-cfg-toggle")
                yield Static("", classes="cfg-spacer")
                yield Label("Log level:")
                yield Select(
                    [(lbl, val) for lbl, val in _LOG_LEVEL_OPTIONS],
                    value="INFO",
                    id="cfg-log-level",
                )

            yield Static("  MCP (AI control)", classes="pane-header")
            with Horizontal(classes="mcp-row"):
                yield Label("Enabled:")
                yield Switch(value=self._mcp_settings.enabled, id="mcp-enabled")
                yield Label("Host:")
                yield Input(value=self._mcp_settings.host, id="mcp-host", compact=True)
                yield Label("Port:")
                yield Input(value=str(self._mcp_settings.port), id="mcp-port", compact=True)
            yield Static(self._format_mcp_url(), id="mcp-url")

    def on_mount(self) -> None:
        dt = self.query_one("#cfg-table", DataTable)
        dt.add_column("Enabled", key="enabled")
        dt.add_column("Name", key="name")
        dt.add_column("Listen", key="listen")
        dt.add_column("Upstream", key="upstream")
        dt.add_column("TLS Client", key="tls_client")
        dt.add_column("TLS Upstream", key="tls_upstream")
        dt.add_column("Status", key="status")
        self._refresh_table()

    # ------------------------------------------------------------------
    # Table helpers
    # ------------------------------------------------------------------

    def _row_values(self, fwd: ForwarderConfig) -> tuple:
        status = "stopped"
        if fwd.name in self._running_fwds:
            addr = self._running_fwds[fwd.name]
            status = f"listening on {addr}" if addr else "running"
            err = self._fwd_errors.get(fwd.name, "")
            if err:
                status += f"  ⚠ {err}"
        return (
            "On" if fwd.enabled else "Off",
            fwd.name,
            f"{fwd.listen_host}:{fwd.listen_port}",
            f"{fwd.upstream_host}:{fwd.upstream_port}",
            "Yes" if fwd.tls_listen else "No",
            "Yes" if fwd.tls_upstream else "No",
            status,
        )

    def _refresh_table(self) -> None:
        dt = self.query_one("#cfg-table", DataTable)
        saved_row = dt.cursor_row
        dt.clear()
        for fwd in self._forwarders:
            dt.add_row(*self._row_values(fwd), key=fwd.name)
        if self._forwarders:
            dt.move_cursor(row=min(saved_row, len(self._forwarders) - 1))

    def _selected_forwarder(self) -> ForwarderConfig | None:
        dt = self.query_one("#cfg-table", DataTable)
        if dt.cursor_row < 0 or dt.cursor_row >= len(self._forwarders):
            return None
        return self._forwarders[dt.cursor_row]

    def _unique_forwarder_name(self, base: str = "Forwarder") -> str:
        existing = {f.name for f in self._forwarders}
        if base not in existing:
            return base
        i = 2
        while f"{base} {i}" in existing:
            i += 1
        return f"{base} {i}"

    # ------------------------------------------------------------------
    # Button handling
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id

        if btn_id == "btn-cfg-add":
            self._open_add_modal()
        elif btn_id == "btn-cfg-edit":
            self._open_edit_modal()
        elif btn_id == "btn-cfg-toggle":
            self._toggle_selected()
        elif btn_id == "btn-cfg-remove":
            self._remove_selected()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Double-click or Enter on a row → open edit modal."""
        self._open_edit_modal()

    # ------------------------------------------------------------------
    # Add / Edit modals
    # ------------------------------------------------------------------

    def _open_add_modal(self) -> None:
        existing_names = {f.name for f in self._forwarders}
        new_name = self._unique_forwarder_name()
        new_fwd = ForwarderConfig(name=new_name, enabled=True)

        # Apply current global log level to the new forwarder
        try:
            log_val = self.query_one("#cfg-log-level", Select).value
            if log_val and log_val is not Select.BLANK:
                new_fwd.log_level = str(log_val)
        except Exception:
            pass

        self.app.push_screen(
            ForwarderEditModal(new_fwd, existing_names=existing_names),
            self._on_add_result,
        )

    def _on_add_result(self, result: ForwarderConfig | None) -> None:
        if result is None:
            return
        self._forwarders.append(result)
        self._refresh_table()
        self.post_message(self.ForwarderAdded(result))

    def _open_edit_modal(self) -> None:
        fwd = self._selected_forwarder()
        if fwd is None:
            return
        # Remember the old name so we can find the entry after the modal returns
        self._edit_old_name = fwd.name
        existing_names = {f.name for f in self._forwarders}
        is_running = fwd.name in self._running_fwds
        self.app.push_screen(
            ForwarderEditModal(fwd, existing_names=existing_names, is_running=is_running),
            self._on_edit_result,
        )

    def _on_edit_result(self, result: ForwarderConfig | None) -> None:
        if result is None:
            return
        old_name = getattr(self, "_edit_old_name", result.name)
        # If the forwarder was renamed, migrate running/error state to the new name
        if result.name != old_name:
            if old_name in self._running_fwds:
                self._running_fwds[result.name] = self._running_fwds.pop(old_name)
            if old_name in self._fwd_errors:
                self._fwd_errors[result.name] = self._fwd_errors.pop(old_name)
        for i, fwd in enumerate(self._forwarders):
            if fwd.name == old_name:
                self._forwarders[i] = result
                break
        self._refresh_table()
        self.post_message(self.ForwarderApplied(old_name, result))

    def _toggle_selected(self) -> None:
        fwd = self._selected_forwarder()
        if fwd is None:
            return
        fwd.enabled = not fwd.enabled
        self._refresh_table()
        self.post_message(self.ForwarderEnabled(fwd.name, fwd.enabled))
        self.query_one("#cfg-table", DataTable).focus()

    def _remove_selected(self) -> None:
        fwd = self._selected_forwarder()
        if fwd is None:
            return
        self.post_message(self.ForwarderRemoved(fwd.name))

    # ------------------------------------------------------------------
    # Log level change
    # ------------------------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "cfg-log-level":
            val = event.value
            if val and val is not Select.BLANK:
                level = str(val)
                # Apply to all forwarders
                for fwd in self._forwarders:
                    fwd.log_level = level
                # Apply immediately to the root logger
                logging.getLogger().setLevel(level)
                logger.info("Log level changed to %s", level)

    # ------------------------------------------------------------------
    # MCP settings
    # ------------------------------------------------------------------

    def _format_mcp_url(self) -> str:
        status = "[enabled]" if self._mcp_settings.enabled else "[disabled]"
        return f"  URL: {self._mcp_settings.url()}   {status}"

    def _refresh_mcp_url(self) -> None:
        try:
            self.query_one("#mcp-url", Static).update(self._format_mcp_url())
        except Exception:
            pass

    def _emit_mcp_settings(self) -> None:
        self.post_message(self.MCPSettingsChanged(self._mcp_settings))
        self._refresh_mcp_url()

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id == "mcp-enabled":
            self._mcp_settings.enabled = event.value
            self._emit_mcp_settings()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Apply host/port changes on Enter."""
        if event.input.id == "mcp-host":
            new_host = event.value.strip() or "127.0.0.1"
            if new_host == self._mcp_settings.host:
                return
            self._mcp_settings.host = new_host
            self._emit_mcp_settings()
        elif event.input.id == "mcp-port":
            try:
                new_port = int(event.value.strip())
            except ValueError:
                logger.warning("Invalid MCP port: %r", event.value)
                return
            if not (1 <= new_port <= 65535):
                logger.warning("MCP port out of range: %d", new_port)
                return
            if new_port == self._mcp_settings.port:
                return
            self._mcp_settings.port = new_port
            self._emit_mcp_settings()

    # ------------------------------------------------------------------
    # Public API (called by app.py)
    # ------------------------------------------------------------------

    def load_mcp_settings(self, settings: MCPSettings) -> None:
        """Replace the displayed MCP settings (e.g. after project open)."""
        self._mcp_settings = settings
        try:
            self.query_one("#mcp-enabled", Switch).value = settings.enabled
            self.query_one("#mcp-host",    Input).value  = settings.host
            self.query_one("#mcp-port",    Input).value  = str(settings.port)
        except Exception:
            # Widgets not yet composed — _refresh_mcp_url runs after on_mount.
            pass
        self._refresh_mcp_url()

    def confirm_remove_forwarder(self, name: str) -> None:
        """Remove a forwarder from the UI list after the user has confirmed deletion."""
        self._forwarders = [f for f in self._forwarders if f.name != name]
        self._running_fwds.pop(name, None)
        self._fwd_errors.pop(name, None)
        self._refresh_table()

    def load_forwarders(self, forwarders: list[ForwarderConfig]) -> None:
        """Replace the entire forwarder list (e.g. after project open/new)."""
        self._forwarders = list(forwarders)
        self._running_fwds.clear()
        self.call_after_refresh(self._refresh_table)

    def notify_forwarder_running(
        self, name: str, running: bool, address: str = ""
    ) -> None:
        """Update the running state for a forwarder."""
        if running:
            self._running_fwds[name] = address
        else:
            self._running_fwds.pop(name, None)
            self._fwd_errors.pop(name, None)
        try:
            self._refresh_table()
        except Exception:
            pass

    def notify_forwarder_error(self, name: str, error: str) -> None:
        """Set (or clear) the upstream error annotation on a running forwarder."""
        if error:
            self._fwd_errors[name] = error
        else:
            self._fwd_errors.pop(name, None)
        try:
            self._refresh_table()
        except Exception:
            pass
