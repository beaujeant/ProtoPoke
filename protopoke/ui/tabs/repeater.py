"""RepeaterTab — hand-craft and replay single frames with history."""

from __future__ import annotations

import time as _time

from textual.app import ComposeResult
from textual.binding import Binding
from textual.widget import Widget
from textual.widgets import DataTable, TextArea, Button, Label, Static, Input, Select, Switch
from textual.containers import Horizontal, Vertical

from ...models import Direction, Frame
from ...replay.models import RepeaterRequest, SendRecord
from ..modals.rename import RenameModal

# Direction mapping for replace-rule scope application
_DIR_MAP = {
    "to_server": Direction.CLIENT_TO_SERVER,
    "to_client": Direction.SERVER_TO_CLIENT,
}

# Sentinel value used as the Select option for "Custom host:port"
_CUSTOM = "custom"


class RepeaterTab(Widget):
    """
    Tab 4 — Repeater: send single frames to the target.

    Layout:
      ┌─────────────────────────────────────────┐
      │ Request tabs: [1] [2] [+ New]           │  tab strip
      ├─────────────────────────────────────────┤
      │ [Session ▼]  Host: <input>  Port: <in>  │  target bar
      │ TLS: [sw]  Dir: [→ To Server ▼]         │
      ├──────────────────────┬──────────────────┤
      │ Hex editor (editable)│ Response packets  │  editor pane
      │                      │ ┌──────────────┐ │
      │                      │ │ packet list  │ │
      │                      │ ├──────────────┤ │
      │                      │ │ hex viewer   │ │
      │                      │ └──────────────┘ │
      ├──────────────────────┴──────────────────┤
      │ [Send]  [Clear]  Window(s): [1.0]        │  action bar
      ├─────────────────────────────────────────┤
      │ History (DataTable of send records)      │  history pane
      └─────────────────────────────────────────┘

    Keyboard:
      R       — rename the current request tab (when a text editor is not focused)
      Ctrl+R  — send current Logs frame to Repeater (handled at app level)
    """

    BINDINGS = [
        Binding("r", "rename_request", "Rename tab", show=False),
    ]

    DEFAULT_CSS = """
    RepeaterTab {
        layout: vertical;
    }
    RepeaterTab .tab-strip {
        height: 3;
        align: left middle;
        background: $surface-darken-1;
        padding: 0 1;
    }
    RepeaterTab .tab-strip Button {
        margin-right: 1;
    }
    RepeaterTab .target-bar {
        height: 3;
        align: left middle;
        background: $surface-darken-2;
        padding: 0 1;
    }
    RepeaterTab .target-bar Label {
        margin-right: 1;
    }
    RepeaterTab .target-bar #session-select {
        width: 30;
        margin-right: 2;
    }
    RepeaterTab .target-bar #target-host-input {
        width: 18;
        margin-right: 1;
    }
    RepeaterTab .target-bar #target-port-input {
        width: 7;
        margin-right: 1;
    }
    RepeaterTab .target-bar #target-tls-switch {
        margin-right: 2;
    }
    RepeaterTab .target-bar #direction-select {
        width: 18;
    }
    RepeaterTab #editor-pane {
        height: 40%;
        border-bottom: solid $primary-darken-2;
        layout: horizontal;
    }
    RepeaterTab #request-editor {
        width: 1fr;
        border-right: solid $primary-darken-2;
    }
    RepeaterTab #response-view {
        width: 1fr;
        layout: vertical;
    }
    RepeaterTab #resp-packets-table {
        height: 7;
        border-bottom: solid $primary-darken-2;
    }
    RepeaterTab #resp-view {
        height: 1fr;
    }
    RepeaterTab .pane-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
        text-style: bold;
    }
    RepeaterTab #request-editor TextArea {
        height: 1fr;
    }
    RepeaterTab .action-bar {
        height: 3;
        align: left middle;
        padding: 0 1;
        background: $surface-darken-1;
    }
    RepeaterTab .action-bar Button {
        margin-right: 1;
    }
    RepeaterTab .action-bar Label {
        margin-right: 1;
    }
    RepeaterTab .action-bar #resp-window {
        width: 6;
        margin-right: 1;
    }
    RepeaterTab #history-pane {
        height: 1fr;
    }
    RepeaterTab DataTable {
        height: 1fr;
    }
    RepeaterTab #resp-packets-table {
        height: 7;
    }
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._requests: list[RepeaterRequest] = []
        self._current_idx: int = -1
        # Response packets for the currently displayed send record
        self._current_response_packets: list[bytes] = []
        # Auto-incremented counter for new request labels
        self._request_counter: int = 0

    def compose(self) -> ComposeResult:
        # Tab strip
        with Horizontal(classes="tab-strip"):
            yield Label("Requests:", id="tab-label")
            yield Button("[+ New]", id="btn-new-request", variant="success", compact=True)

        # Target bar — session dropdown + host/port/tls + direction
        with Horizontal(classes="target-bar"):
            yield Select(
                options=[("Custom (manual host:port)", _CUSTOM)],
                value=_CUSTOM,
                id="session-select",
                prompt="Target session",
            )
            yield Label("Host:")
            yield Input("", id="target-host-input", placeholder="host")
            yield Label("Port:")
            yield Input("", id="target-port-input", placeholder="port")
            yield Label("TLS:")
            yield Switch(False, id="target-tls-switch")
            yield Select(
                options=[
                    ("→ To Server", "to_server"),
                    ("← To Client", "to_client"),
                ],
                value="to_server",
                id="direction-select",
            )

        # Request / Response editors side by side
        with Horizontal(id="editor-pane"):
            with Vertical(id="request-editor"):
                yield Static("  Request (hex — editable)", classes="pane-header")
                yield TextArea("", id="req-editor", theme="monokai")
            with Vertical(id="response-view"):
                yield Static("  Response frames  ↓ server→client", classes="pane-header")
                yield DataTable(id="resp-packets-table", cursor_type="row")
                yield Static("  Packet view (hex)", classes="pane-header")
                yield TextArea("", id="resp-view", theme="monokai", read_only=True)

        # Action bar
        with Horizontal(classes="action-bar"):
            yield Button("▶ Send", variant="success", id="btn-send",       compact=True)
            yield Button("Clear Request",              id="btn-clear-req",  compact=True)
            yield Button("Clear History",              id="btn-clear-hist", compact=True)
            yield Label("  Window (s):")
            yield Input("1.0", id="resp-window")

        # History pane
        with Vertical(id="history-pane"):
            yield Static("  Send History", classes="pane-header")
            yield DataTable(id="history-table", cursor_type="row")

    def on_mount(self) -> None:
        dt = self.query_one("#history-table", DataTable)
        dt.add_column("#", key="num")
        dt.add_column("Time", key="time")
        dt.add_column("Host:Port", key="dest")
        dt.add_column("Sent (B)", key="sent")
        dt.add_column("Recv (B)", key="recv")
        dt.add_column("OK", key="ok")
        dt.add_column("Error", key="err")

        rpt = self.query_one("#resp-packets-table", DataTable)
        rpt.add_column("Frame", key="num")
        rpt.add_column("Size (B)", key="size")

    # ------------------------------------------------------------------
    # Request tab management
    # ------------------------------------------------------------------

    def add_request(self, req: RepeaterRequest, _preserve_label: bool = False) -> None:
        """Add a new repeater request and switch to it.

        When *_preserve_label* is False (default), the request label is
        overwritten with the next auto-incremented number.
        """
        if not _preserve_label:
            self._request_counter += 1
            req.label = str(self._request_counter)

        self._requests.append(req)
        idx = len(self._requests) - 1
        btn = Button(req.label, id=f"req-tab-{idx}", compact=True)
        self.query_one(".tab-strip", Horizontal).mount(btn, before="#btn-new-request")
        self._switch_to(idx)

    def _switch_to(self, idx: int) -> None:
        """Switch the editor view to request at *idx*."""
        if idx < 0 or idx >= len(self._requests):
            return
        self._current_idx = idx
        req = self._requests[idx]

        # Refresh session dropdown options and set correct value
        self._rebuild_session_dropdown(req)

        # Direction
        try:
            self.query_one("#direction-select", Select).value = req.direction
        except Exception:
            pass

        # Sync the response-window input
        self.query_one("#resp-window", Input).value = str(req.response_window)

        # Populate editor
        if req.current_bytes:
            pairs = [req.current_bytes.hex()[i:i+2] for i in range(0, len(req.current_bytes.hex()), 2)]
            self.query_one("#req-editor", TextArea).load_text(" ".join(pairs))
        else:
            self.query_one("#req-editor", TextArea).load_text("")

        # Populate response from last history entry
        if req.history:
            self._display_record_response(req.history[-1])
        else:
            self._refresh_response_packets([])

        # Refresh history table
        self._refresh_history(req)

    def _rebuild_session_dropdown(self, req: RepeaterRequest) -> None:
        """Rebuild the session Select options and set the correct value."""
        try:
            sessions = self.app.api.list_sessions()
        except Exception:
            sessions = []

        options: list[tuple[str, str]] = [("Custom (manual host:port)", _CUSTOM)]
        for s in sessions:
            label = f"Session {s.id[:8]}: {s.info.server_host}:{s.info.server_port}"
            options.append((label, s.id))

        sel = self.query_one("#session-select", Select)
        sel.set_options(options)

        if req.source_session_id and any(v == req.source_session_id for _, v in options):
            sel.value = req.source_session_id
            self._apply_session_mode(req.source_session_id)
        else:
            sel.value = _CUSTOM
            self._apply_custom_mode(req)

    def _apply_custom_mode(self, req: RepeaterRequest) -> None:
        """Show editable host/port/TLS fields from req."""
        host_input = self.query_one("#target-host-input", Input)
        port_input = self.query_one("#target-port-input", Input)
        tls_switch = self.query_one("#target-tls-switch", Switch)

        host_input.value = req.host
        port_input.value = str(req.port)
        tls_switch.value = req.tls

        host_input.disabled = False
        port_input.disabled = False
        tls_switch.disabled = False

    def _apply_session_mode(self, session_id: str) -> None:
        """Show read-only host/port/TLS derived from the given session."""
        try:
            session = self.app.api.get_session(session_id)
        except Exception:
            session = None

        host_input = self.query_one("#target-host-input", Input)
        port_input = self.query_one("#target-port-input", Input)
        tls_switch = self.query_one("#target-tls-switch", Switch)

        if session:
            host_input.value = session.info.server_host
            port_input.value = str(session.info.server_port)
            try:
                tls_switch.value = self.app.api.config.tls_upstream
            except Exception:
                tls_switch.value = False
        else:
            host_input.value = "—"
            port_input.value = "—"
            tls_switch.value = False

        host_input.disabled = True
        port_input.disabled = True
        tls_switch.disabled = True

    def refresh_session_dropdown(self) -> None:
        """Called by the app when a session opens or closes."""
        if self._current_idx < 0 or self._current_idx >= len(self._requests):
            return
        req = self._requests[self._current_idx]
        self._rebuild_session_dropdown(req)

    def _display_record_response(self, record: SendRecord) -> None:
        """Populate the response packet list and viewer from a SendRecord."""
        self._refresh_response_packets(record.response_packets)

    def _refresh_response_packets(self, packets: list[bytes]) -> None:
        """
        Repopulate the response-packet DataTable with *packets*.

        Arrow keys and single clicks navigate immediately (RowHighlighted).
        The first frame is auto-selected so the hex viewer populates at once.
        """
        rpt = self.query_one("#resp-packets-table", DataTable)
        rpt.clear()
        self._current_response_packets = packets

        if not packets:
            self.query_one("#resp-view", TextArea).load_text("# (no frames received)")
            return

        for i, pkt in enumerate(packets):
            rpt.add_row(str(i + 1), str(len(pkt)), key=str(i))

        # Auto-select and display the first frame
        rpt.move_cursor(row=0)
        self._show_packet(0)

    def _show_packet(self, idx: int) -> None:
        """Display packet *idx* from _current_response_packets in hex."""
        packets = self._current_response_packets
        if not (0 <= idx < len(packets)):
            return
        pkt = packets[idx]
        pairs = [pkt.hex()[i:i+2] for i in range(0, len(pkt.hex()), 2)]
        self.query_one("#resp-view", TextArea).load_text(" ".join(pairs))

    def _refresh_history(self, req: RepeaterRequest) -> None:
        dt = self.query_one("#history-table", DataTable)
        dt.clear()
        for i, record in enumerate(req.history, 1):
            t = _time.strftime("%H:%M:%S", _time.localtime(record.timestamp))
            dest = f"{record.host}:{record.port}"
            ok = "✓" if record.success else "✗"
            err = record.error or ""
            dt.add_row(
                str(i), t, dest,
                str(len(record.sent_bytes)),
                str(len(record.received_bytes)),
                ok, err,
                key=record.id,
            )

    def load_requests(self, requests: list[RepeaterRequest]) -> None:
        """Reload all requests (e.g. after project open)."""
        for btn in self.query(".tab-strip Button"):
            if btn.id and btn.id.startswith("req-tab-"):
                btn.remove()
        self._requests = []
        self._current_idx = -1
        for req in requests:
            self.add_request(req, _preserve_label=True)
        # Sync counter so new requests continue from the highest saved number
        max_num = 0
        for req in self._requests:
            try:
                max_num = max(max_num, int(req.label))
            except (ValueError, TypeError):
                pass
        self._request_counter = max(len(self._requests), max_num)

    # ------------------------------------------------------------------
    # Rename action (R key)
    # ------------------------------------------------------------------

    def action_rename_request(self) -> None:
        """Open the rename modal for the current request tab."""
        if self._current_idx < 0:
            return
        req = self._requests[self._current_idx]
        self.app.push_screen(RenameModal(req.label), self._on_rename)

    def _on_rename(self, new_name: str | None) -> None:
        if not new_name:
            return
        req = self._requests[self._current_idx]
        req.label = new_name
        try:
            self.query_one(f"#req-tab-{self._current_idx}", Button).label = new_name
        except Exception:
            pass
        if hasattr(self.app, "mark_dirty"):
            self.app.mark_dirty()

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""

        if bid == "btn-new-request":
            event.stop()
            self.app.open_new_request_modal()

        elif bid.startswith("req-tab-"):
            event.stop()
            idx = int(bid.removeprefix("req-tab-"))
            self._switch_to(idx)

        elif bid == "btn-send":
            event.stop()
            self._do_send()

        elif bid == "btn-clear-req":
            event.stop()
            self.query_one("#req-editor", TextArea).load_text("")

        elif bid == "btn-clear-hist":
            event.stop()
            if 0 <= self._current_idx < len(self._requests):
                self._requests[self._current_idx].history.clear()
                self.query_one("#history-table", DataTable).clear()

    def _get_response_window(self) -> float:
        """Return the configured response-capture window in seconds."""
        try:
            val = float(self.query_one("#resp-window", Input).value)
            return max(0.0, val)
        except (ValueError, Exception):
            return 1.0

    # ------------------------------------------------------------------
    # Select / Input / Switch event handlers
    # ------------------------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        if self._current_idx < 0:
            return
        req = self._requests[self._current_idx]

        if event.select.id == "session-select":
            value = event.value
            if value is Select.BLANK or value == _CUSTOM:
                req.source_session_id = None
                self._apply_custom_mode(req)
            else:
                req.source_session_id = str(value)
                self._apply_session_mode(str(value))
            if hasattr(self.app, "mark_dirty"):
                self.app.mark_dirty()

        elif event.select.id == "direction-select":
            if event.value is not Select.BLANK:
                req.direction = str(event.value)
                if hasattr(self.app, "mark_dirty"):
                    self.app.mark_dirty()

    def on_input_changed(self, event: Input.Changed) -> None:
        if self._current_idx < 0:
            return
        req = self._requests[self._current_idx]

        if event.input.id == "resp-window":
            try:
                req.response_window = max(0.0, float(event.value))
            except ValueError:
                pass

        elif event.input.id == "target-host-input":
            if not event.input.disabled:
                req.host = event.value
                if hasattr(self.app, "mark_dirty"):
                    self.app.mark_dirty()

        elif event.input.id == "target-port-input":
            if not event.input.disabled:
                try:
                    req.port = int(event.value)
                    if hasattr(self.app, "mark_dirty"):
                        self.app.mark_dirty()
                except ValueError:
                    pass

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id != "target-tls-switch":
            return
        if self._current_idx < 0 or event.switch.disabled:
            return
        self._requests[self._current_idx].tls = event.value
        if hasattr(self.app, "mark_dirty"):
            self.app.mark_dirty()

    # ------------------------------------------------------------------
    # DataTable navigation — highlighted (arrow / single-click)
    # ------------------------------------------------------------------

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """
        Arrow key navigation and single-click selection — display content
        immediately for both the response packets table and the history table.
        No Enter / double-click required.
        """
        if event.row_key is None:
            return

        if event.data_table.id == "resp-packets-table":
            idx = int(str(event.row_key.value))
            self._show_packet(idx)

        elif event.data_table.id == "history-table":
            if self._current_idx < 0:
                return
            req = self._requests[self._current_idx]
            record_id = str(event.row_key.value)
            for record in req.history:
                if record.id == record_id:
                    pairs = [record.sent_bytes.hex()[i:i+2]
                             for i in range(0, len(record.sent_bytes.hex()), 2)]
                    self.query_one("#req-editor", TextArea).load_text(" ".join(pairs))
                    self._display_record_response(record)
                    break

    # on_data_table_row_selected is no longer used for navigation (both tables
    # respond to RowHighlighted); kept empty to avoid accidental double-loads.
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        pass

    # ------------------------------------------------------------------
    # Send logic
    # ------------------------------------------------------------------

    def _do_send(self) -> None:
        if self._current_idx < 0:
            self.notify("No request selected. Create one with [+ New].", severity="warning")
            return

        req = self._requests[self._current_idx]
        hex_text = self.query_one("#req-editor", TextArea).text
        hex_clean = hex_text.replace(" ", "").replace("\n", "").strip()
        try:
            data = bytes.fromhex(hex_clean)
        except ValueError as exc:
            self.notify(f"Invalid hex: {exc}", severity="error")
            return

        req.current_bytes = data
        if hasattr(self.app, "mark_dirty"):
            self.app.mark_dirty()

        # Apply replace rules (repeater scope) before sending
        try:
            _direction = _DIR_MAP.get(req.direction, Direction.CLIENT_TO_SERVER)
            data = self.app.api.rules_engine.apply_bytes(data, _direction, scope="repeater")
        except Exception:
            pass  # Don't block the send if rule application fails

        self.run_worker(self._async_send(req, data), exclusive=True)

    async def _async_send(self, req: RepeaterRequest, data: bytes) -> None:
        import time as _t

        response_window = self._get_response_window()

        # ------------------------------------------------------------------
        # Path 1: session-linked request — inject into existing proxy session
        # ------------------------------------------------------------------
        if req.source_session_id:
            send_time = _t.time()
            injected = False
            to_client = (req.direction == "to_client")
            try:
                if to_client:
                    injected = await self.app.api.inject_to_client(
                        req.source_session_id, data
                    )
                else:
                    injected = await self.app.api.inject_to_server(
                        req.source_session_id, data
                    )
            except OSError:
                pass

            if injected:
                await __import__("asyncio").sleep(response_window)
                session = self.app.api.get_session(req.source_session_id)
                response_packets: list[bytes] = []
                if session:
                    # Collect the reply direction: if we injected to server, server
                    # replies to client; if we injected to client, client replies to server.
                    reply_direction = (
                        Direction.CLIENT_TO_SERVER if to_client
                        else Direction.SERVER_TO_CLIENT
                    )
                    response_packets = [
                        f.raw_bytes for f in session.frames
                        if f.direction is reply_direction
                        and f.timestamp >= send_time
                    ]
                record = SendRecord.create(
                    sent_bytes=data,
                    received_bytes=b"".join(response_packets),
                    response_packets=response_packets,
                    host=req.host,
                    port=req.port,
                    tls=req.tls,
                    success=True,
                )
            else:
                # Inject failed (session closed) — fall back to one-shot send
                record = await self.app.api.send_frame(
                    data=data,
                    host=req.host,
                    port=req.port,
                    tls=req.tls,
                    receive_timeout=response_window,
                )

        # ------------------------------------------------------------------
        # Path 2: custom host:port — use (or create) a persistent session
        # ------------------------------------------------------------------
        else:
            if req.repeater_session_id:
                session = self.app.api.get_session(req.repeater_session_id)
                if not (session and session.is_active()):
                    req.repeater_session_id = None

            if not req.repeater_session_id:
                try:
                    req.repeater_session_id = await self.app.api.open_repeater_session(
                        req.host, req.port, req.tls
                    )
                except Exception as exc:
                    record = await self.app.api.send_frame(
                        data=data,
                        host=req.host,
                        port=req.port,
                        tls=req.tls,
                        receive_timeout=response_window,
                    )
                    req.add_record(record)
                    self._display_record_response(record)
                    self._refresh_history(req)
                    self.notify(f"Send complete (no persistent session): {exc}", severity="warning")
                    return

            record = await self.app.api.send_on_repeater_session(
                session_id=req.repeater_session_id,
                data=data,
                receive_timeout=response_window,
            )

            if req.repeater_session_id:
                session = self.app.api.get_session(req.repeater_session_id)
                if session and not session.is_active():
                    req.repeater_session_id = None

        req.add_record(record)
        self._display_record_response(record)
        self._refresh_history(req)
        n_frames = len(record.response_packets)
        status = "OK" if record.success else f"Error: {record.error}"
        self.notify(f"Send complete: {status} — {n_frames} frame(s) received")
