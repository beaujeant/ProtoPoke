"""LogsTab — session list, frame list, and hex / parsed detail pane."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.events import MouseDown
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

    Session / frame navigation:
      • Single click or arrow keys highlight a row → auto-selects it.
      • First session created is selected automatically.
      • First frame captured for the current session is selected automatically.
      • Shift+click in the Frames table extends the selection range from the
        anchor row to the clicked row.
        The direction of the first selected frame determines which direction is
        sent when using "→ Sequencer".
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
        height: 100%;
        color: $text;
        text-style: bold;
        content-align-horizontal: left;
        content-align-vertical: middle;
    }
    LogsTab ParsedView {
        height: 1fr;
    }
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._current_session_id: str | None = None
        self._current_frame_id: str | None = None

        # Ordered list of frame IDs matching the current frames-table rows.
        # Kept in sync whenever frames are loaded or appended.
        self._frame_rows: list[str] = []

        # Index of the anchor row (first clicked / selected frame) for
        # shift-range selection.  -1 means no anchor is set.
        self._anchor_frame_idx: int = -1

        # IDs of all currently selected frames (ordered from top to bottom).
        self._selected_frame_ids: list[str] = []

        # True during the processing of a RowHighlighted event that was
        # triggered by a shift+key press — causes range extension instead of
        # single selection.  Reset to False after each RowHighlighted.
        self._extending_selection: bool = False

        # Label widget reference for the frames toolbar (shows selection count).
        self._frames_label: Static | None = None

    def compose(self) -> ComposeResult:
        # Sessions pane
        with Vertical(id="sessions-pane"):
            with Horizontal(classes="toolbar"):
                yield Static("  Sessions")
                yield Button("✖ Terminate", id="btn-terminate-session", variant="warning")
                yield Button("✗ Delete",    id="btn-delete-session",    variant="error")
            yield DataTable(id="sessions-table", cursor_type="row")

        # Frames pane
        with Vertical(id="frames-pane"):
            with Horizontal(classes="toolbar"):
                lbl = Static("  Frames")
                self._frames_label = lbl
                yield lbl
                yield Button("→ Repeater",  id="btn-to-repeater",  variant="default")
                yield Button("→ Sequencer", id="btn-to-sequencer", variant="default")
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
        """Append a newly opened session row. Auto-selects the first session."""
        import time as _time
        info    = session.info
        started = _time.strftime("%H:%M:%S", _time.localtime(info.created_at))
        dt = self.query_one("#sessions-table", DataTable)
        is_first = dt.row_count == 0
        dt.add_row(
            info.id[:8],
            f"{info.client_host}:{info.client_port}",
            f"{info.server_host}:{info.server_port}",
            info.state.value,
            "0",
            started,
            key=info.id,       # full UUID as row key
        )
        # Auto-select the first session that arrives
        if is_first:
            dt.move_cursor(row=0)
            self.show_frames(session)

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
        self._frame_rows = []
        self._anchor_frame_idx = -1
        self._selected_frame_ids = []
        self._current_session_id = session.id
        self._current_frame_id   = None
        self.query_one("#parsed-view", ParsedView).clear()
        self._update_frames_label()

        for frame in session.frames:
            self._add_frame_row(dt, frame)

    def add_frame_to_current(self, frame: Frame) -> None:
        """Append a new frame if it belongs to the currently displayed session."""
        if self._current_session_id != frame.session_id:
            return
        if frame.id in self._frame_rows:
            return
        dt = self.query_one("#frames-table", DataTable)
        is_first = dt.row_count == 0
        self._add_frame_row(dt, frame)
        # Auto-select and show the first frame that arrives
        if is_first:
            self._anchor_frame_idx = 0
            self._selected_frame_ids = [frame.id]
            self._current_frame_id = frame.id
            dt.move_cursor(row=0)
            self._show_frame_in_detail(frame.id)
            self._update_frames_label()

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
        self._frame_rows.append(frame.id)

    def _show_frame_in_detail(self, frame_id: str) -> None:
        """Look up *frame_id* in the current session and display it."""
        if not self._current_session_id:
            return
        session = self.app.api.get_session(self._current_session_id)
        if not session:
            return
        for frame in session.frames:
            if frame.id == frame_id:
                message = None
                try:
                    message = self.app.api.decode_frame(frame)
                    if not message.fields and not message.message_type:
                        message = None
                except Exception:
                    pass
                self.query_one("#parsed-view", ParsedView).show_frame(frame, message)
                return

    def _update_frames_label(self) -> None:
        """Update the toolbar label to reflect the current selection count."""
        try:
            lbl = self.query_one(".toolbar Static", Static)
            n = len(self._selected_frame_ids)
            if n > 1:
                lbl.update(f"  Frames  [{n} selected]")
            else:
                lbl.update("  Frames")
        except Exception:
            pass

    def on_mouse_down(self, event: MouseDown) -> None:
        """
        Detect Shift+click on the frames table to extend the selection range.

        Flow (why this works and why we use MouseDown instead of Click):
          1. User shift+clicks a row in the frames DataTable.
          2. MouseDown bubbles up to LogsTab (DataTable has no _on_mouse_down,
             so it does not stop propagation). We set _extending_selection here.
          3. User releases mouse → Click is dispatched to DataTable.
          4. DataTable._on_click moves cursor → posts RowHighlighted to the
             message queue → calls event.stop() (Click never bubbles further).
          5. RowHighlighted is dequeued. on_data_table_row_highlighted sees
             _extending_selection=True and extends the selection.

        A plain click (no shift) sets the flag to False so the next
        RowHighlighted does a normal single-row selection.
        """
        focused = self.app.focused
        if focused and getattr(focused, "id", None) == "frames-table":
            self._extending_selection = event.shift

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """
        Single click or arrow key navigation selects a row immediately.

        For the frames table, shift+click extends the selection range from the
        anchor row to the clicked row.
        """
        if event.row_key is None:
            return
        row_id = str(event.row_key.value)

        if event.data_table.id == "sessions-table":
            # A session was highlighted — load its frames
            session = self.app.api.get_session(row_id)
            if session:
                self.show_frames(session)

        elif event.data_table.id == "frames-table":
            current_idx = next(
                (i for i, fid in enumerate(self._frame_rows) if fid == row_id), -1
            )
            if current_idx < 0:
                self._extending_selection = False
                return

            if self._extending_selection and self._anchor_frame_idx >= 0:
                # Extend / shrink the selection range from anchor to current
                lo = min(self._anchor_frame_idx, current_idx)
                hi = max(self._anchor_frame_idx, current_idx)
                self._selected_frame_ids = self._frame_rows[lo : hi + 1]
            else:
                # Single selection — reset anchor
                self._anchor_frame_idx = current_idx
                self._selected_frame_ids = [row_id]
                self._current_frame_id = row_id
                self._show_frame_in_detail(row_id)

            self._extending_selection = False
            self._update_frames_label()

    def remove_session(self, session_id: str) -> None:
        """Remove a session row (and clear frames/detail if it was selected)."""
        dt = self.query_one("#sessions-table", DataTable)
        try:
            dt.remove_row(session_id)
        except Exception:
            pass
        if self._current_session_id == session_id:
            self._current_session_id = None
            self._current_frame_id   = None
            self._frame_rows         = []
            self._selected_frame_ids = []
            self._anchor_frame_idx   = -1
            self.query_one("#frames-table", DataTable).clear()
            self.query_one("#parsed-view", ParsedView).clear()
            self._update_frames_label()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-terminate-session":
            event.stop()
            if self._current_session_id:
                self.app.terminate_session(self._current_session_id)
            else:
                self.notify("Select a session first.", severity="warning")

        elif event.button.id == "btn-delete-session":
            event.stop()
            if self._current_session_id:
                self.app.delete_session(self._current_session_id)
            else:
                self.notify("Select a session first.", severity="warning")

        elif event.button.id == "btn-to-repeater":
            event.stop()
            if self._current_frame_id and self._current_session_id:
                self.app.send_frame_to_repeater(
                    self._current_session_id, self._current_frame_id
                )
            else:
                self.notify("Select a frame first.", severity="warning")

        elif event.button.id == "btn-to-sequencer":
            event.stop()
            if self._selected_frame_ids and self._current_session_id:
                self.app.send_frames_to_sequencer(
                    self._current_session_id, list(self._selected_frame_ids)
                )
            else:
                self.notify("Select a frame first.", severity="warning")
