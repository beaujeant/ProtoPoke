"""RepeaterTab — hand-craft and replay single frames with history."""

from __future__ import annotations

import time as _time

from textual.app import ComposeResult
from textual.binding import Binding
from textual.widget import Widget
from textual.widgets import DataTable, TextArea, Button, Label, Static
from textual.containers import Horizontal, Vertical

from ...models import Direction
from ...replay.models import RepeaterRequest, SendRecord
from ..modals.request_modal import RequestModal, RequestResult
from ..utils.frame_codec import bytes_to_str, str_to_bytes, hex_pairs_to_str, str_to_hex_pairs

# Direction mapping for replace-rule scope application
_DIR_MAP = {
    "to_server": Direction.CLIENT_TO_SERVER,
    "to_client": Direction.SERVER_TO_CLIENT,
}


class RepeaterTab(Widget):
    """
    Tab 4 — Repeater: send single frames to the target.

    Layout:
      ┌─────────────────────────────────────────┐
      │ Forged Frames (DataTable list)  h=20%   │  req-list-pane
      │  #   Name     Host:Port   Dir           │
      ├─────────────────────────────────────────┤
      │ [+ New]  [Edit (E)]             h=3     │  req-controls
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
      E       — edit the selected forged frame (when a text editor is not focused)
      Ctrl+R  — send current Logs frame to Repeater (handled at app level)
    """

    BINDINGS = [
        Binding("e", "edit_request", "Edit", show=False),
    ]

    DEFAULT_CSS = """
    RepeaterTab {
        layout: vertical;
    }
    RepeaterTab .req-list-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
        text-style: bold;
    }
    RepeaterTab #req-list-pane {
        height: 20%;
    }
    RepeaterTab #req-list-pane DataTable {
        height: 1fr;
    }
    RepeaterTab .req-controls {
        height: 3;
        align: left middle;
        padding: 0 1;
        background: $surface-darken-1;
    }
    RepeaterTab .req-controls Button {
        margin-right: 1;
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
    RepeaterTab #request-editor .pane-header {
        height: 1;
        align: left middle;
    }
    RepeaterTab #request-editor .pane-header Static {
        width: 1fr;
    }
    RepeaterTab #request-editor .pane-header Button {
        width: 5;
    }
    RepeaterTab #response-view {
        width: 1fr;
        layout: vertical;
    }
    RepeaterTab #resp-packets-table {
        height: 7;
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
        # "hex" or "str" — controls how the request editor displays / parses content
        self._editor_mode: str = "hex"

    def compose(self) -> ComposeResult:
        # Frames list pane
        with Vertical(id="req-list-pane"):
            yield Static("  Frames", classes="req-list-header")
            yield DataTable(id="req-table", cursor_type="row")

        # Request controls
        with Horizontal(classes="req-controls"):
            yield Button("+ New", id="btn-new-request", variant="success", flat=True)
            yield Button("Edit",  id="btn-edit-request", flat=True)

        # Request / Response editors side by side
        with Horizontal(id="editor-pane"):
            with Vertical(id="request-editor"):
                with Horizontal(classes="pane-header"):
                    yield Static("  Request (editable)", markup=False)
                    yield Button("HEX", id="btn-req-mode", compact=True)
                yield TextArea("", id="req-editor")
            with Vertical(id="response-view"):
                yield Static("  Response frames  ↓ server→client", classes="pane-header")
                yield DataTable(id="resp-packets-table", cursor_type="row")
                yield Static("  Packet view (hex)", classes="pane-header")
                yield TextArea("", id="resp-view", read_only=True)

        # Action bar
        with Horizontal(classes="action-bar"):
            yield Button("▶ Send",        variant="success", id="btn-send",       compact=True)
            yield Button("Clear History",                    id="btn-clear-hist", compact=True)

        # History pane
        with Vertical(id="history-pane"):
            yield Static("  Send History", classes="pane-header")
            yield DataTable(id="history-table", cursor_type="row")

    def on_mount(self) -> None:
        rt = self.query_one("#req-table", DataTable)
        rt.add_column("Name",      key="name")
        rt.add_column("Session",   key="session")
        rt.add_column("Host",      key="host")
        rt.add_column("Port",      key="port")
        rt.add_column("Direction", key="dir")
        rt.add_column("Window",    key="window")
        rt.add_column("Preview",   key="preview")

        dt = self.query_one("#history-table", DataTable)
        dt.add_column("#",        key="num")
        dt.add_column("Time",     key="time")
        dt.add_column("Session",  key="session")
        dt.add_column("Host",     key="host")
        dt.add_column("Port",     key="port")
        dt.add_column("Send (B)", key="sent")
        dt.add_column("Recv (B)", key="recv")
        dt.add_column("Ok",       key="ok")
        dt.add_column("Error",    key="err")
        dt.add_column("Preview",  key="preview")

        rpt = self.query_one("#resp-packets-table", DataTable)
        rpt.add_column("Frame", key="num")
        rpt.add_column("Size (B)", key="size")

    # ------------------------------------------------------------------
    # Request list management
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

        rt = self.query_one("#req-table", DataTable)
        session_display = req.source_session_id[:8] if req.source_session_id else "—"
        host_display    = req.host or "—"
        port_display    = str(req.port) if req.port else "—"
        dir_symbol      = "←" if req.direction == "to_client" else "→"
        window_display  = str(req.response_window)
        preview         = " ".join(f"{b:02x}" for b in req.current_bytes[:8]) if req.current_bytes else "—"
        rt.add_row(req.label, session_display, host_display, port_display, dir_symbol, window_display, preview, key=req.id)

        self._switch_to(idx)

    def _switch_to(self, idx: int) -> None:
        """Switch the editor view to request at *idx*."""
        if idx < 0 or idx >= len(self._requests):
            return
        self._current_idx = idx
        req = self._requests[idx]

        # Move the cursor in the list to the selected row
        try:
            self.query_one("#req-table", DataTable).move_cursor(row=idx)
        except Exception:
            pass

        # Populate editor
        if req.current_bytes:
            self._load_bytes_into_editor(req.current_bytes)
        else:
            self.query_one("#req-editor", TextArea).load_text("")

        # Populate response from last history entry
        if req.history:
            self._display_record_response(req.history[-1])
        else:
            self._refresh_response_packets([])

        # Refresh history table — select last entry to match the displayed response
        self._refresh_history(req, select_last=True)

    def refresh_session_dropdown(self) -> None:
        """Called by the app when a session opens or closes (no-op: sessions are fetched fresh when the Edit modal opens)."""

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

    def _refresh_history(
        self,
        req: RepeaterRequest,
        *,
        select_last: bool = False,
        preserve_cursor: bool = False,
    ) -> None:
        dt = self.query_one("#history-table", DataTable)
        saved_row = dt.cursor_row if preserve_cursor else -1
        dt.clear()
        for i, record in enumerate(req.history, 1):
            t               = _time.strftime("%H:%M:%S", _time.localtime(record.timestamp))
            session_display = record.session_id[:8] if record.session_id else "—"
            ok              = "✓" if record.success else "✗"
            err             = record.error or ""
            preview         = " ".join(f"{b:02x}" for b in record.sent_bytes[:8]) if record.sent_bytes else "—"
            dt.add_row(
                str(i), t, session_display,
                record.host, str(record.port),
                str(len(record.sent_bytes)),
                str(len(record.received_bytes)),
                ok, err, preview,
                key=record.id,
            )
        if not req.history:
            return
        if select_last:
            dt.move_cursor(row=len(req.history) - 1)
        elif preserve_cursor and saved_row >= 0:
            dt.move_cursor(row=min(saved_row, len(req.history) - 1))

    def _update_req_list_row(self, idx: int) -> None:
        """Refresh the row in the request list for the given index."""
        if idx < 0 or idx >= len(self._requests):
            return
        req = self._requests[idx]
        session_display = req.source_session_id[:8] if req.source_session_id else "—"
        host_display    = req.host or "—"
        port_display    = str(req.port) if req.port else "—"
        dir_symbol      = "←" if req.direction == "to_client" else "→"
        window_display  = str(req.response_window)
        preview         = " ".join(f"{b:02x}" for b in req.current_bytes[:8]) if req.current_bytes else "—"
        try:
            rt = self.query_one("#req-table", DataTable)
            rt.update_cell(req.id, "name",    req.label,       update_width=False)
            rt.update_cell(req.id, "session", session_display, update_width=False)
            rt.update_cell(req.id, "host",    host_display,    update_width=False)
            rt.update_cell(req.id, "port",    port_display,    update_width=False)
            rt.update_cell(req.id, "dir",     dir_symbol,      update_width=False)
            rt.update_cell(req.id, "window",  window_display,  update_width=False)
            rt.update_cell(req.id, "preview", preview,         update_width=False)
        except Exception:
            pass

    def load_requests(self, requests: list[RepeaterRequest]) -> None:
        """Reload all requests (e.g. after project open)."""
        rt = self.query_one("#req-table", DataTable)
        rt.clear()
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
    # Edit action (E key)
    # ------------------------------------------------------------------

    def action_edit_request(self) -> None:
        """Open the edit modal for the current request."""
        if self._current_idx < 0:
            return
        req = self._requests[self._current_idx]

        try:
            all_sessions = self.app.api.list_sessions()
        except Exception:
            all_sessions = []

        sessions = [
            (
                s.id,
                f"Session {s.id[:8]}",
                s.info.server_host,
                s.info.server_port,
            )
            for s in all_sessions
        ]

        self.app.push_screen(
            RequestModal(
                sessions,
                label=req.label,
                host=req.host,
                port=req.port,
                tls=req.tls,
                direction=req.direction,
                session_id=req.source_session_id,
                window=req.response_window,
                edit=True,
            ),
            self._on_edit_request,
        )

    def _on_edit_request(self, result: RequestResult | None) -> None:
        if result is None:
            return
        req = self._requests[self._current_idx]

        req.label           = result.label
        req.direction       = result.direction
        req.response_window = result.window

        # If the session or connection target changed, reset the persistent
        # repeater session so a new connection is opened on the next send.
        if (
            result.session_id != req.source_session_id
            or result.host != req.host
            or result.port != req.port
            or result.tls  != req.tls
        ):
            req.repeater_session_id = None

        req.source_session_id = result.session_id
        req.host  = result.host
        req.port  = result.port
        req.tls   = result.tls

        self._update_req_list_row(self._current_idx)
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

        elif bid == "btn-edit-request":
            event.stop()
            self.action_edit_request()

        elif bid == "btn-req-mode":
            event.stop()
            self._toggle_editor_mode()
            return

        elif bid == "btn-send":
            event.stop()
            self._do_send()

        elif bid == "btn-clear-hist":
            event.stop()
            if 0 <= self._current_idx < len(self._requests):
                self._requests[self._current_idx].history.clear()
                self.query_one("#history-table", DataTable).clear()

    def _get_response_window(self) -> float:
        """Return the configured response-capture window in seconds."""
        if 0 <= self._current_idx < len(self._requests):
            return self._requests[self._current_idx].response_window
        return 1.0

    # ------------------------------------------------------------------
    # DataTable navigation — highlighted (arrow / single-click)
    # ------------------------------------------------------------------

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """
        Arrow key navigation and single-click selection — display content
        immediately for both the request list, response packets table and the
        history table. No Enter / double-click required.
        """
        if event.row_key is None:
            return

        if event.data_table.id == "req-table":
            req_id = str(event.row_key.value)
            for i, req in enumerate(self._requests):
                if req.id == req_id:
                    if i != self._current_idx:
                        self._switch_to(i)
                    break

        elif event.data_table.id == "resp-packets-table":
            idx = int(str(event.row_key.value))
            self._show_packet(idx)

        elif event.data_table.id == "history-table":
            if self._current_idx < 0:
                return
            req = self._requests[self._current_idx]
            record_id = str(event.row_key.value)
            for record in req.history:
                if record.id == record_id:
                    self._load_bytes_into_editor(record.sent_bytes)
                    self._display_record_response(record)
                    break

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "req-table":
            req_id = str(event.row_key.value)
            for i, req in enumerate(self._requests):
                if req.id == req_id:
                    self._switch_to(i)
                    break

    # ------------------------------------------------------------------
    # Send logic
    # ------------------------------------------------------------------

    def _load_bytes_into_editor(self, data: bytes) -> None:
        """Display *data* in the request editor respecting the current mode."""
        if self._editor_mode == "str":
            text = bytes_to_str(data)
        else:
            text = " ".join(f"{b:02x}" for b in data)
        self.query_one("#req-editor", TextArea).load_text(text)

    def _read_bytes_from_editor(self) -> bytes:
        """Parse the request editor content and return bytes. Raises ValueError on bad input."""
        text = self.query_one("#req-editor", TextArea).text
        if self._editor_mode == "str":
            return str_to_bytes(text)
        hex_clean = text.replace(" ", "").replace("\n", "").strip()
        return bytes.fromhex(hex_clean) if hex_clean else b""

    def _toggle_editor_mode(self) -> None:
        """Switch the request editor between HEX and STR (python-like) display."""
        editor = self.query_one("#req-editor", TextArea)
        current_text = editor.text

        if self._editor_mode == "hex":
            try:
                new_text = hex_pairs_to_str(current_text)
            except ValueError as exc:
                self.notify(f"Cannot switch to STR: {exc}", severity="error")
                return
            self._editor_mode = "str"
            self.query_one("#btn-req-mode", Button).label = "STR"
        else:
            try:
                new_text = str_to_hex_pairs(current_text)
            except ValueError as exc:
                self.notify(f"Cannot switch to HEX: {exc}", severity="error")
                return
            self._editor_mode = "hex"
            self.query_one("#btn-req-mode", Button).label = "HEX"

        editor.load_text(new_text)

    def _do_send(self) -> None:
        if self._current_idx < 0:
            self.notify("No request selected. Create one with [+ New].", severity="warning")
            return

        req = self._requests[self._current_idx]
        try:
            data = self._read_bytes_from_editor()
        except ValueError as exc:
            mode = "STR" if self._editor_mode == "str" else "hex"
            self.notify(f"Invalid {mode}: {exc}", severity="error")
            return

        req.current_bytes = data
        self._update_req_list_row(self._current_idx)
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
        import asyncio as _asyncio
        import time as _t

        response_window = self._get_response_window()

        # Add a provisional record immediately so the history entry appears
        # before the response window runs, giving real-time feedback.
        record = SendRecord.create(
            sent_bytes=data,
            received_bytes=b"",
            response_packets=[],
            host=req.host,
            port=req.port,
            tls=req.tls,
            success=True,
            session_id=req.source_session_id,
        )
        req.add_record(record)
        self._refresh_history(req, select_last=True)
        self._display_record_response(record)

        def _on_packet(pkt: bytes) -> None:
            """Called for each incoming frame during the send window so the
            user sees responses arrive in real time."""
            record.response_packets.append(pkt)
            record.received_bytes = record.received_bytes + pkt
            self._refresh_response_packets(record.response_packets)

        # ------------------------------------------------------------------
        # Path 1: session-linked request — inject into existing proxy session
        # ------------------------------------------------------------------
        if req.source_session_id:
            send_time = _t.time()
            to_client = (req.direction == "to_client")
            injected = False
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
                # Collect the reply direction: if we injected to server, server
                # replies to client; if we injected to client, client replies to server.
                reply_direction = (
                    Direction.CLIENT_TO_SERVER if to_client
                    else Direction.SERVER_TO_CLIENT
                )
                # Poll session frames during the window so frames appear as they arrive.
                deadline = _asyncio.get_event_loop().time() + response_window
                poll_interval = 0.1
                while True:
                    remaining = deadline - _asyncio.get_event_loop().time()
                    if remaining <= 0:
                        break
                    await _asyncio.sleep(min(poll_interval, remaining))
                    session = self.app.api.get_session(req.source_session_id)
                    if session:
                        current_packets = [
                            f.raw_bytes for f in session.frames
                            if f.direction is reply_direction
                            and f.timestamp >= send_time
                        ]
                        for pkt in current_packets[len(record.response_packets):]:
                            _on_packet(pkt)
                # Final sweep to catch any frames that arrived at the deadline.
                session = self.app.api.get_session(req.source_session_id)
                if session:
                    current_packets = [
                        f.raw_bytes for f in session.frames
                        if f.direction is reply_direction
                        and f.timestamp >= send_time
                    ]
                    for pkt in current_packets[len(record.response_packets):]:
                        _on_packet(pkt)
            else:
                # Inject failed (session closed) — fall back to one-shot send
                final = await self.app.api.send_frame(
                    data=data,
                    host=req.host,
                    port=req.port,
                    tls=req.tls,
                    receive_timeout=response_window,
                    packet_callback=_on_packet,
                )
                record.received_bytes = final.received_bytes
                record.response_packets = final.response_packets
                record.success = final.success
                record.error = final.error

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
                    final = await self.app.api.send_frame(
                        data=data,
                        host=req.host,
                        port=req.port,
                        tls=req.tls,
                        receive_timeout=response_window,
                        packet_callback=_on_packet,
                    )
                    record.received_bytes = final.received_bytes
                    record.response_packets = final.response_packets
                    record.success = final.success
                    record.error = final.error
                    self._refresh_history(req, preserve_cursor=True)
                    self._display_record_response(record)
                    self.notify(f"Send complete (no persistent session): {exc}", severity="warning")
                    return

            final = await self.app.api.send_on_repeater_session(
                session_id=req.repeater_session_id,
                data=data,
                receive_timeout=response_window,
                packet_callback=_on_packet,
            )
            # Sync from the authoritative engine result (covers edge cases where
            # the framer flushes bytes that weren't emitted via the callback).
            record.received_bytes = final.received_bytes
            record.response_packets = final.response_packets
            record.success = final.success
            record.error = final.error

            if req.repeater_session_id:
                session = self.app.api.get_session(req.repeater_session_id)
                if session and not session.is_active():
                    req.repeater_session_id = None

        # Refresh history to update the recv-bytes column, preserving the
        # user's current selection in case they navigated while waiting.
        self._refresh_history(req, preserve_cursor=True)
        self._display_record_response(record)
        n_frames = len(record.response_packets)
        status = "OK" if record.success else f"Error: {record.error}"
        self.notify(f"Send complete: {status} — {n_frames} frame(s) received")
