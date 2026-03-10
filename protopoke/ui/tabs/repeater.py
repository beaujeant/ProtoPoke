"""RepeaterTab — hand-craft and replay single frames with history."""

from __future__ import annotations

import time as _time

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, TextArea, Button, Label, Static, Input
from textual.containers import Horizontal, Vertical

from ...models import Direction, Frame
from ...replay.models import RepeaterRequest, SendRecord


class RepeaterTab(Widget):
    """
    Tab 4 — Repeater: send single frames to the target.

    Layout:
      ┌─────────────────────────────────────────┐
      │ Request tabs: [Tab 1] [Tab 2] [+ New]   │  tab strip
      ├─────────────────────────────────────────┤
      │ Target: host:port  [TLS switch]          │  per-request header
      ├──────────────────────┬──────────────────┤
      │ Hex editor (editable)│ Response packets  │  editor pane
      │                      │ ┌──────────────┐ │
      │                      │ │ packet list  │ │  ← individual read() chunks
      │                      │ │ (DataTable)  │ │    received within window
      │                      │ ├──────────────┤ │
      │                      │ │ hex viewer   │ │  ← selected packet bytes
      │                      │ └──────────────┘ │
      ├──────────────────────┴──────────────────┤
      │ [Send]  [Clear]  Window(s): [1.0]        │  action bar
      ├─────────────────────────────────────────┤
      │ History (DataTable of send records)      │  history pane
      └─────────────────────────────────────────┘
    """

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

    def compose(self) -> ComposeResult:
        # Tab strip
        with Horizontal(classes="tab-strip"):
            yield Label("Requests:", id="tab-label")
            yield Button("[+ New]", id="btn-new-request", variant="success")

        # Target bar
        with Horizontal(classes="target-bar"):
            yield Label("Host:", id="target-host-label")
            yield Label("—", id="target-host")
            yield Label("  Port:", id="target-port-label")
            yield Label("—", id="target-port")
            yield Label("  TLS:", id="target-tls-label")
            yield Label("No", id="target-tls")

        # Request / Response editors side by side
        with Horizontal(id="editor-pane"):
            with Vertical(id="request-editor"):
                yield Static("  Request (hex — editable)", classes="pane-header")
                yield TextArea("", id="req-editor", theme="monokai")
            with Vertical(id="response-view"):
                yield Static("  Response packets  ↓ server→client", classes="pane-header")
                yield DataTable(id="resp-packets-table", cursor_type="row")
                yield Static("  Packet view (hex)", classes="pane-header")
                yield TextArea("", id="resp-view", theme="monokai", read_only=True)

        # Action bar
        with Horizontal(classes="action-bar"):
            yield Button("▶ Send", variant="success", id="btn-send")
            yield Button("Clear Request", id="btn-clear-req")
            yield Button("Clear History", id="btn-clear-hist")
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
        rpt.add_column("#", key="num")
        rpt.add_column("Δt (ms)", key="delta")
        rpt.add_column("Size (B)", key="size")

    # ------------------------------------------------------------------
    # Request tab management
    # ------------------------------------------------------------------

    def add_request(self, req: RepeaterRequest) -> None:
        """Add a new repeater request and switch to it."""
        self._requests.append(req)
        # Add a button for this tab in the strip
        idx = len(self._requests) - 1
        btn = Button(req.label, id=f"req-tab-{idx}")
        self.query_one(".tab-strip", Horizontal).mount(btn, before="#btn-new-request")
        self._switch_to(idx)

    def _switch_to(self, idx: int) -> None:
        """Switch the editor view to request at *idx*."""
        if idx < 0 or idx >= len(self._requests):
            return
        self._current_idx = idx
        req = self._requests[idx]

        # Update target bar
        self.query_one("#target-host", Label).update(req.host)
        self.query_one("#target-port", Label).update(str(req.port))
        self.query_one("#target-tls", Label).update("Yes" if req.tls else "No")

        # Sync the response-window input with this tab's configured value
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

    def _display_record_response(self, record: SendRecord) -> None:
        """Populate the response packet list and viewer from a SendRecord."""
        self._refresh_response_packets(record.response_packets)

    def _refresh_response_packets(self, packets: list[bytes], send_ts: float = 0.0) -> None:
        """
        Repopulate the response-packet DataTable with *packets*.

        Each row shows the packet index, elapsed time since send (ms),
        and byte count.  The first packet is auto-selected so the hex
        viewer is populated immediately.
        """
        rpt = self.query_one("#resp-packets-table", DataTable)
        rpt.clear()
        self._current_response_packets = packets

        if not packets:
            self.query_one("#resp-view", TextArea).load_text("# (no packets received)")
            return

        base_ts = send_ts if send_ts else _time.time()
        for i, pkt in enumerate(packets):
            delta_ms = ""  # timing not tracked per-packet; placeholder
            rpt.add_row(str(i + 1), delta_ms, str(len(pkt)), key=str(i))

        # Auto-select and display the first packet
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
        # Remove existing tab buttons
        for btn in self.query(".tab-strip Button"):
            if btn.id and btn.id.startswith("req-tab-"):
                btn.remove()
        self._requests = []
        self._current_idx = -1
        for req in requests:
            self.add_request(req)

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

    def on_input_changed(self, event: Input.Changed) -> None:
        """Persist the response_window value into the current request."""
        if event.input.id != "resp-window":
            return
        if self._current_idx < 0:
            return
        try:
            val = float(event.value)
            self._requests[self._current_idx].response_window = max(0.0, val)
        except ValueError:
            pass

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

        # Save current bytes to request
        req.current_bytes = data
        self.app.api.mark_dirty() if hasattr(self.app, "mark_dirty") else None

        # Run as a background worker
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
            try:
                injected = await self.app.api.inject_to_server(
                    req.source_session_id, data
                )
            except OSError:
                pass

            if injected:
                # Wait for the response window, then harvest SERVER_TO_CLIENT
                # frames that the relay captured after our inject.
                await __import__("asyncio").sleep(response_window)
                session = self.app.api.get_session(req.source_session_id)
                response_packets: list[bytes] = []
                if session:
                    response_packets = [
                        f.raw_bytes for f in session.frames
                        if f.direction is Direction.SERVER_TO_CLIENT
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
            # Check whether the existing persistent session is still alive
            if req.repeater_session_id:
                session = self.app.api.get_session(req.repeater_session_id)
                if not (session and session.is_active()):
                    req.repeater_session_id = None

            # Open a new persistent session if we don't have one
            if not req.repeater_session_id:
                try:
                    req.repeater_session_id = await self.app.api.open_repeater_session(
                        req.host, req.port, req.tls
                    )
                except Exception as exc:
                    # Could not connect — fall back to old one-shot behaviour
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

            # If the session was closed by the server during this send, clear
            # the reference so the next send opens a fresh connection
            if req.repeater_session_id:
                session = self.app.api.get_session(req.repeater_session_id)
                if session and not session.is_active():
                    req.repeater_session_id = None

        req.add_record(record)

        # Update response pane
        self._display_record_response(record)

        self._refresh_history(req)
        n_pkts = len(record.response_packets)
        status = "OK" if record.success else f"Error: {record.error}"
        self.notify(f"Send complete: {status} — {n_pkts} packet(s) received")

    # ------------------------------------------------------------------
    # DataTable row selection
    # ------------------------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        table_id = event.data_table.id

        # Response packet list — show that packet in the hex viewer
        if table_id == "resp-packets-table":
            idx = int(str(event.row_key.value))
            self._show_packet(idx)
            return

        # History table — restore sent bytes and response packets
        if table_id != "history-table":
            return
        if self._current_idx < 0:
            return
        req = self._requests[self._current_idx]
        record_id = str(event.row_key.value)
        for record in req.history:
            if record.id == record_id:
                # Show sent bytes in editor
                pairs = [record.sent_bytes.hex()[i:i+2]
                         for i in range(0, len(record.sent_bytes.hex()), 2)]
                self.query_one("#req-editor", TextArea).load_text(" ".join(pairs))
                # Restore response packets
                self._display_record_response(record)
                break
