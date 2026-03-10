"""LogsTab — session list, frame list, and hex / parsed detail pane."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, Static, Button
from textual.containers import Horizontal, Vertical

from ...models import Frame, Direction
from ...core.session import Session
from ..widgets.parsed_view import ParsedView


class LogsTab(Widget):
    """
    Tab 2 — Live capture log.

    Layout (vertical):
      ┌─────────────────────────────────────────┐
      │ Sessions (DataTable)              ~35%  │
      ├─────────────────────────────────────────┤
      │ Frames for selected session       ~30%  │
      ├─────────────────────────────────────────┤
      │ ParsedView (hex ↔ field tree)     ~35%  │
      └─────────────────────────────────────────┘
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
    }
    LogsTab #detail-pane {
        height: 35%;
    }
    LogsTab DataTable {
        height: 1fr;
    }
    LogsTab .toolbar {
        height: 3;
        background: $primary-darken-2;
        align: left middle;
        padding: 0 1;
    }
    LogsTab .toolbar Button {
        margin-right: 1;
    }
    LogsTab .toolbar Static {
        width: 1fr;
        color: $text;
        text-style: bold;
    }
    LogsTab ParsedView {
        height: 1fr;
    }
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._current_session_id: str | None = None
        self._current_frame_id: str | None = None

    def compose(self) -> ComposeResult:
        # Sessions pane
        with Vertical(id="sessions-pane"):
            yield Static("  Sessions", classes="pane-header")
            yield DataTable(id="sessions-table", cursor_type="row")

        # Frames pane
        with Vertical(id="frames-pane"):
            with Horizontal(classes="toolbar"):
                yield Static("  Frames")
                yield Button("→ Repeater", id="btn-to-repeater", variant="default")
            yield DataTable(id="frames-table", cursor_type="row")

        # Detail pane with hex↔parsed toggle
        with Vertical(id="detail-pane"):
            yield ParsedView(title="  Frame Detail", id="parsed-view")

    def on_mount(self) -> None:
        # Sessions table
        sdt = self.query_one("#sessions-table", DataTable)
        sdt.add_column("ID",      key="id")
        sdt.add_column("Client",  key="client")
        sdt.add_column("Server",  key="server")
        sdt.add_column("State",   key="state")
        sdt.add_column("Frames",  key="frames")
        sdt.add_column("Started", key="started")

        # Frames table
        fdt = self.query_one("#frames-table", DataTable)
        fdt.add_column("#",       key="seq")
        fdt.add_column("Dir",     key="dir")
        fdt.add_column("Len",     key="len")
        fdt.add_column("Framer",  key="framer")
        fdt.add_column("Preview", key="preview")

    # ------------------------------------------------------------------
    # Public API — driven by app event bridge
    # ------------------------------------------------------------------

    def add_session(self, session: Session) -> None:
        """Append a newly opened session row."""
        import time as _time
        info    = session.info
        started = _time.strftime("%H:%M:%S", _time.localtime(info.created_at))
        dt = self.query_one("#sessions-table", DataTable)
        dt.add_row(
            info.id[:8],
            f"{info.client_host}:{info.client_port}",
            f"{info.server_host}:{info.server_port}",
            info.state.value,
            "0",
            started,
            key=info.id,       # full UUID as row key
        )

    def update_session(self, session: Session) -> None:
        """Refresh a session row (state, frame count)."""
        info = session.info
        dt   = self.query_one("#sessions-table", DataTable)
        try:
            dt.update_cell(info.id, "state",  info.state.value,        update_width=False)
            dt.update_cell(info.id, "frames", str(len(session.frames)), update_width=False)
        except Exception:
            pass

    def show_frames(self, session: Session) -> None:
        """Populate the frames pane with all frames from *session*."""
        dt = self.query_one("#frames-table", DataTable)
        dt.clear()
        for frame in session.frames:
            self._add_frame_row(dt, frame)
        self._current_session_id = session.id
        self._current_frame_id   = None
        self.query_one("#parsed-view", ParsedView).clear()

    def add_frame_to_current(self, frame: Frame) -> None:
        """Append a new frame if it belongs to the currently displayed session."""
        if self._current_session_id != frame.session_id:
            return
        self._add_frame_row(self.query_one("#frames-table", DataTable), frame)

    def _add_frame_row(self, dt: DataTable, frame: Frame) -> None:
        direction = "→" if frame.direction is Direction.CLIENT_TO_SERVER else "←"
        preview   = frame.raw_bytes[:24].hex()
        if len(frame.raw_bytes) > 24:
            preview += "…"
        dt.add_row(
            str(frame.sequence_number),
            direction,
            str(len(frame.raw_bytes)),
            frame.framer_name,
            preview,
            key=frame.id,      # full UUID as row key
        )

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_id = str(event.row_key.value)

        if event.data_table.id == "sessions-table":
            # row_key is the full session UUID
            session = self.app.api.get_session(row_id)
            if session:
                self.show_frames(session)

        elif event.data_table.id == "frames-table":
            # row_key is the full frame UUID
            self._current_frame_id = row_id
            if self._current_session_id:
                session = self.app.api.get_session(self._current_session_id)
                if session:
                    for frame in session.frames:
                        if frame.id == row_id:
                            # Try to get a parsed message if a decoder is loaded
                            message = None
                            try:
                                message = self.app.api.decode_frame(frame)
                                # PassthroughDecoder returns a message with no fields
                                if not message.fields and not message.message_type:
                                    message = None
                            except Exception:
                                pass
                            self.query_one("#parsed-view", ParsedView).show_frame(frame, message)
                            break

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-to-repeater":
            event.stop()
            if self._current_frame_id and self._current_session_id:
                self.app.send_frame_to_repeater(
                    self._current_session_id, self._current_frame_id
                )
            else:
                self.notify("Select a frame first.", severity="warning")
