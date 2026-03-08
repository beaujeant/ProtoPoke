"""LogsTab — session list, frame list, and hex/parsed detail pane."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, Static, Button, Label
from textual.containers import Horizontal, Vertical
from textual.message import Message

from ...models import Frame, Direction
from ...core.session import Session
from ..widgets.hex_view import HexView


class LogsTab(Widget):
    """
    Tab 2 — Live capture log.

    Layout (vertical split):
      ┌─────────────────────────────────────┐
      │ Sessions (DataTable)                │  top ~40%
      ├─────────────────────────────────────┤
      │ Frames for selected session         │  middle ~30%
      ├─────────────────────────────────────┤
      │ Hex / parsed view for selected frame│  bottom ~30%
      └─────────────────────────────────────┘

    Both DataTables are updated via ``add_session()`` / ``add_frame()``
    which are called from the main app in response to EventBus events.
    """

    DEFAULT_CSS = """
    LogsTab {
        layout: vertical;
    }
    LogsTab .pane-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
        text-style: bold;
    }
    LogsTab #sessions-pane {
        height: 35%;
        border-bottom: solid $primary-darken-2;
    }
    LogsTab #frames-pane {
        height: 30%;
        border-bottom: solid $primary-darken-2;
    }
    LogsTab #detail-pane {
        height: 35%;
    }
    LogsTab DataTable {
        height: 1fr;
    }
    LogsTab .toolbar {
        height: 3;
        align: right middle;
        padding: 0 1;
    }
    LogsTab Button {
        margin-left: 1;
    }
    LogsTab HexView {
        height: 1fr;
        overflow-y: auto;
    }
    """

    def compose(self) -> ComposeResult:
        # Sessions pane
        with Vertical(id="sessions-pane"):
            yield Static("  Sessions", classes="pane-header")
            yield DataTable(id="sessions-table", cursor_type="row")

        # Frames pane
        with Vertical(id="frames-pane"):
            with Horizontal(classes="toolbar"):
                yield Static("  Frames", classes="pane-header")
                yield Button("Send to Repeater", id="btn-to-repeater", variant="default")
                yield Button("Send to Intercept", id="btn-to-intercept", variant="default")
            yield DataTable(id="frames-table", cursor_type="row")

        # Detail pane
        with Vertical(id="detail-pane"):
            yield Static("  Frame Detail (hex dump)", classes="pane-header")
            yield HexView(id="hex-view")

    def on_mount(self) -> None:
        # Sessions table columns
        sessions_dt = self.query_one("#sessions-table", DataTable)
        sessions_dt.add_column("ID", key="id")
        sessions_dt.add_column("Client", key="client")
        sessions_dt.add_column("Server", key="server")
        sessions_dt.add_column("State", key="state")
        sessions_dt.add_column("Frames", key="frames")
        sessions_dt.add_column("Started", key="started")

        # Frames table columns
        frames_dt = self.query_one("#frames-table", DataTable)
        frames_dt.add_column("#", key="seq")
        frames_dt.add_column("Dir", key="dir")
        frames_dt.add_column("Len", key="len")
        frames_dt.add_column("Framer", key="framer")
        frames_dt.add_column("Preview", key="preview")

    # ------------------------------------------------------------------
    # Public API — called by the app in response to proxy events
    # ------------------------------------------------------------------

    def add_session(self, session: Session) -> None:
        """Append a newly opened session row."""
        dt = self.query_one("#sessions-table", DataTable)
        info = session.info
        import time
        started = time.strftime("%H:%M:%S", time.localtime(info.created_at))
        dt.add_row(
            info.id[:8],
            f"{info.client_host}:{info.client_port}",
            f"{info.server_host}:{info.server_port}",
            info.state.value,
            "0",
            started,
            key=info.id,
        )

    def update_session(self, session: Session) -> None:
        """Refresh a session row (state change, frame count, etc.)."""
        info = session.info
        dt = self.query_one("#sessions-table", DataTable)
        try:
            row_key = info.id
            dt.update_cell(row_key, "state", info.state.value)
            dt.update_cell(row_key, "frames", str(len(session.frames)))
        except Exception:
            pass  # Row may not exist yet

    def show_frames(self, session: Session) -> None:
        """Populate the frames pane with all frames from *session*."""
        dt = self.query_one("#frames-table", DataTable)
        dt.clear()
        for frame in session.frames:
            self._add_frame_row(dt, frame)
        # Clear detail pane
        self.query_one("#hex-view", HexView).clear()
        # Store session ref for later updates
        self._current_session_id = session.id

    def add_frame_to_current(self, frame: Frame) -> None:
        """Append a new frame to the frames pane (if it belongs to the current session)."""
        if getattr(self, "_current_session_id", None) != frame.session_id:
            return
        dt = self.query_one("#frames-table", DataTable)
        self._add_frame_row(dt, frame)

    def _add_frame_row(self, dt: DataTable, frame: Frame) -> None:
        direction = "→" if frame.direction is Direction.CLIENT_TO_SERVER else "←"
        preview = frame.raw_bytes[:24].hex()
        if len(frame.raw_bytes) > 24:
            preview += "…"
        dt.add_row(
            str(frame.sequence_number),
            direction,
            str(len(frame.raw_bytes)),
            frame.framer_name,
            preview,
            key=frame.id,
        )

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        dt = event.data_table
        if dt.id == "sessions-table":
            # User selected a session — show its frames
            app = self.app
            session = None
            for s in app.api.list_sessions():
                if s.id.startswith(str(event.row_key.value)):
                    session = s
                    break
                if s.id == event.row_key.value:
                    session = s
                    break
            if session:
                self.show_frames(session)
        elif dt.id == "frames-table":
            # User selected a frame — show hex dump
            frame_id = str(event.row_key.value)
            sid = getattr(self, "_current_session_id", None)
            if sid:
                session = self.app.api.get_session(sid)
                if session:
                    for frame in session.frames:
                        if frame.id == frame_id:
                            self.query_one("#hex-view", HexView).show_frame(frame)
                            self._current_frame_id = frame_id
                            break

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-to-repeater":
            event.stop()
            self._send_to_repeater()
        elif event.button.id == "btn-to-intercept":
            event.stop()

    def _send_to_repeater(self) -> None:
        frame_id = getattr(self, "_current_frame_id", None)
        sid = getattr(self, "_current_session_id", None)
        if not frame_id or not sid:
            self.notify("Select a frame first.", severity="warning")
            return
        # Delegate to the app — it will handle the repeater tab
        self.app.send_frame_to_repeater(sid, frame_id)
