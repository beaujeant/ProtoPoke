"""TrafficTab — session list, frame list, and hex / parsed detail pane."""

from __future__ import annotations

import logging

from textual.app import ComposeResult
from textual.binding import Binding
from textual.widget import Widget
from textual.widgets import DataTable, Static, Button
from textual.containers import Horizontal, Vertical

from rich.text import Text

from ...filters.frame_filter import HIDE, SHOW, FrameDisplayFilter
from ...models import Frame, Direction
from ...core.session import Session
from ..modals.create_session import CreateSessionModal, CreateSessionResult
from ..modals.frame_filter_modal import FrameFilterModal
from ..widgets.parsed_view import ParsedView

logger = logging.getLogger(__name__)


class _FramesTable(DataTable):
    """DataTable that supports shift+arrow range selection.

    Shift+Up / Shift+Down move the cursor while signalling the parent
    :class:`TrafficTab` to extend the selection range instead of resetting it.
    """

    BINDINGS = [
        Binding("shift+up", "shift_up", show=False),
        Binding("shift+down", "shift_down", show=False),
        Binding("escape", "cancel_selection", show=False),
    ]

    def _traffic_tab(self) -> "TrafficTab":
        node = self.parent
        while node is not None:
            if isinstance(node, TrafficTab):
                return node
            node = node.parent
        raise RuntimeError("_FramesTable must be a descendant of TrafficTab")

    def action_shift_up(self) -> None:
        self._traffic_tab()._extending_selection = True
        self.action_cursor_up()

    def action_shift_down(self) -> None:
        self._traffic_tab()._extending_selection = True
        self.action_cursor_down()

    def action_cancel_selection(self) -> None:
        self._traffic_tab()._cancel_frame_selection()



class TrafficTab(Widget):
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
      • Shift+Up/Down in the Frames table extends the selection range from the
        anchor row.  The direction of the first selected frame determines which
        direction is sent when using "→ Forge".
    """

    DEFAULT_CSS = """
    TrafficTab {
        layout: vertical;
    }
    TrafficTab .pane-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
        text-style: bold;
    }
    TrafficTab #sessions-pane {
        height: 35%;
    }
    TrafficTab #frames-pane {
        height: 30%;
    }
    TrafficTab #detail-pane {
        height: 35%;
    }
    TrafficTab DataTable {
        height: 1fr;
    }
    TrafficTab .toolbar {
        height: 3;
        background: $primary-darken-2;
        align: left middle;
        padding: 0;
    }
    TrafficTab .toolbar Button {
        margin: 0 1;
        padding: 0;
    }
    TrafficTab .toolbar Static {
        width: 1fr;
        height: 100%;
        color: $text;
        text-style: bold;
        content-align-horizontal: left;
        content-align-vertical: middle;
    }
    TrafficTab ParsedView {
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

        # Plain cell values per frame ID — used for applying / removing Rich
        # Text highlight styles without losing the original data.
        self._row_data: dict[str, tuple[str, ...]] = {}

        # Direction per frame ID — used to re-apply the green/cyan tint when
        # toggling multi-select highlighting.
        self._row_directions: dict[str, Direction] = {}

        # Frame IDs that currently have highlight styling applied.  Used to
        # compute the diff so we only update changed rows.
        self._prev_highlighted: set[str] = set()

        # Active frame display filters.
        self._frame_filters: list[FrameDisplayFilter] = []

        # Reference to the Filters button for label updates.
        self._filter_button: Button | None = None

    def compose(self) -> ComposeResult:
        # Sessions pane
        with Vertical(id="sessions-pane"):
            with Horizontal(classes="toolbar"):
                yield Static("  Sessions")
                yield Button("+ Create",    id="btn-create-session",    variant="success", flat=True)
                yield Button("✖ Terminate", id="btn-terminate-session", variant="warning", flat=True)
                yield Button("✖ Remove",    id="btn-delete-session",    variant="error", flat=True)
            yield DataTable(id="sessions-table", cursor_type="row")

        # Frames pane
        with Vertical(id="frames-pane"):
            with Horizontal(classes="toolbar"):
                lbl = Static("  Frames  [Shift+↑↓ to multi-select]")
                self._frames_label = lbl
                yield lbl
                btn = Button("Filters [0]", id="btn-frame-filters", variant="primary", flat=True)
                self._filter_button = btn
                yield btn
                yield Button("→ Forge", id="btn-to-forge", variant="primary", flat=True)
            yield _FramesTable(id="frames-table", cursor_type="row")

        # Detail pane with hex↔parsed toggle
        with Vertical(id="detail-pane"):
            yield ParsedView(title="  Frame Detail", id="parsed-view")

    def on_mount(self) -> None:
        # Sessions table
        sdt = self.query_one("#sessions-table", DataTable)
        sdt.add_column("ID",      key="id")
        sdt.add_column("Type",    key="type")
        sdt.add_column("Client",  key="client")
        sdt.add_column("Server",  key="server")
        sdt.add_column("State",   key="state")
        sdt.add_column("Frames",  key="frames")
        sdt.add_column("Started", key="started")

        # Frames table
        fdt = self.query_one("#frames-table", DataTable)
        fdt.add_column("#",       key="seq_c2s")
        fdt.add_column("Dir",     key="dir")
        fdt.add_column("#",       key="seq_s2c")
        fdt.add_column("Framer",  key="framer")
        fdt.add_column("Len",     key="len")
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
            info.transport.upper(),
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
        self._row_data = {}
        self._row_directions = {}
        self._prev_highlighted = set()
        self._anchor_frame_idx = -1
        self._selected_frame_ids = []
        self._current_session_id = session.id
        self._current_frame_id   = None
        self.query_one("#parsed-view", ParsedView).clear()
        self._update_frames_label()

        for frame in session.frames:
            if self._passes_filters(frame):
                self._add_frame_row(dt, frame)

    def add_frame_to_current(self, frame: Frame) -> None:
        """Append a new frame if it belongs to the currently displayed session."""
        if self._current_session_id != frame.session_id:
            return
        if frame.id in self._frame_rows:
            return
        if not self._passes_filters(frame):
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
        is_c2s    = frame.direction is Direction.CLIENT_TO_SERVER
        seq_c2s   = str(frame.sequence_number) if is_c2s else ""
        seq_s2c   = str(frame.sequence_number) if not is_c2s else ""
        direction = "→" if is_c2s else "←"
        preview   = frame.raw_bytes[:24].hex()
        if len(frame.raw_bytes) > 24:
            preview += "…"
        values = (
            seq_c2s,
            direction,
            seq_s2c,
            frame.framer_name,
            str(len(frame.raw_bytes)),
            preview,
        )
        self._row_data[frame.id] = values
        self._row_directions[frame.id] = frame.direction
        cells = tuple(
            self._styled_cell(col_key, val, frame.direction, selected=False)
            for col_key, val in zip(self._COL_KEYS, values)
        )
        dt.add_row(*cells, key=frame.id)
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

    _COL_KEYS = ("seq_c2s", "dir", "seq_s2c", "framer", "len", "preview")
    _SELECTED_STYLE = "bold underline"
    _DIR_TINTED_KEYS = frozenset({"seq_c2s", "dir", "seq_s2c"})
    _C2S_STYLE = "green"
    _S2C_STYLE = "cyan"

    def _direction_style(self, direction: Direction) -> str:
        return self._C2S_STYLE if direction is Direction.CLIENT_TO_SERVER else self._S2C_STYLE

    def _styled_cell(
        self, col_key: str, value: str, direction: Direction, *, selected: bool
    ) -> Text | str:
        """Return the Rich Text (or plain str) to render for a cell.

        Direction-tinted columns get a green/cyan foreground; selected rows
        additionally get bold+underline. A plain string is returned only when
        no styling applies, to keep DataTable column-width measurement happy.
        """
        styles: list[str] = []
        if col_key in self._DIR_TINTED_KEYS and value:
            styles.append(self._direction_style(direction))
        if selected:
            styles.append(self._SELECTED_STYLE)
        if not styles:
            return value
        return Text(value, style=" ".join(styles))

    def _highlight_selection(self) -> None:
        """Apply / remove bold styling on multi-selected rows.

        When only a single row is selected the DataTable cursor already
        provides a blue highlight, so no extra styling is applied. The
        per-direction colour tint on Dir / # columns is preserved either way.
        """
        dt = self.query_one("#frames-table", DataTable)
        # If 0 or 1 selected, clear any previous highlights and bail out.
        new_sel = set(self._selected_frame_ids) if len(self._selected_frame_ids) > 1 else set()
        to_style   = new_sel - self._prev_highlighted
        to_unstyle = self._prev_highlighted - new_sel

        for fid in to_style | to_unstyle:
            data = self._row_data.get(fid)
            if data is None:
                continue
            direction = self._row_directions.get(fid, Direction.CLIENT_TO_SERVER)
            is_sel = fid in new_sel
            for col_key, val in zip(self._COL_KEYS, data):
                cell = self._styled_cell(col_key, val, direction, selected=is_sel)
                try:
                    dt.update_cell(fid, col_key, cell, update_width=False)
                except Exception:
                    pass

        self._prev_highlighted = new_sel

    def _update_frames_label(self) -> None:
        """Update the frames toolbar label to reflect the current selection count."""
        if self._frames_label is None:
            return
        n = len(self._selected_frame_ids)
        if n > 1:
            self._frames_label.update(f"  Frames  [{n} selected — Esc to cancel]")
        else:
            self._frames_label.update("  Frames  [Shift+↑↓ to multi-select]")

    def _cancel_frame_selection(self) -> None:
        """Collapse a multi-frame selection back to just the current single frame."""
        if len(self._selected_frame_ids) <= 1:
            return
        # Keep the anchor frame as the single selected frame
        if self._anchor_frame_idx >= 0 and self._anchor_frame_idx < len(self._frame_rows):
            single_id = self._frame_rows[self._anchor_frame_idx]
        elif self._current_frame_id:
            single_id = self._current_frame_id
        else:
            return
        self._selected_frame_ids = [single_id]
        self._current_frame_id = single_id
        self._highlight_selection()
        self._update_frames_label()

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
            self._highlight_selection()

    def _passes_filters(self, frame: Frame) -> bool:
        """Return True if *frame* should be shown given the active filters.

        Hide filters take priority: if any enabled hide-filter matches, the
        frame is excluded regardless of show-filters.

        Show filters use OR logic: if at least one enabled show-filter exists,
        the frame must match at least one of them.

        If no filters are enabled the frame is always shown.
        """
        active = [f for f in self._frame_filters if f.enabled]
        if not active:
            return True

        hide_filters = [f for f in active if f.mode == HIDE]
        show_filters = [f for f in active if f.mode == SHOW]

        if any(f.matches_frame(frame) for f in hide_filters):
            return False

        if show_filters:
            return any(f.matches_frame(frame) for f in show_filters)

        return True

    def _update_filter_button(self) -> None:
        """Keep the Filters button label in sync with the active filter count."""
        if self._filter_button is None:
            return
        n = sum(1 for f in self._frame_filters if f.enabled)
        self._filter_button.label = f"Filters [{n}]"

    def load_filters(self, filters: list[FrameDisplayFilter]) -> None:
        """Load filters from a project state (called on project open / new)."""
        self._frame_filters = list(filters)
        self._update_filter_button()

    def clear_all(self) -> None:
        """Remove all sessions, frames, and reset the detail pane."""
        self.query_one("#sessions-table", DataTable).clear()
        self.query_one("#frames-table", DataTable).clear()
        self.query_one("#parsed-view", ParsedView).clear()
        self._current_session_id = None
        self._current_frame_id   = None
        self._frame_rows         = []
        self._row_data           = {}
        self._row_directions     = {}
        self._prev_highlighted   = set()
        self._selected_frame_ids = []
        self._anchor_frame_idx   = -1
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
            self._row_data           = {}
            self._row_directions     = {}
            self._prev_highlighted   = set()
            self._selected_frame_ids = []
            self._anchor_frame_idx   = -1
            self.query_one("#frames-table", DataTable).clear()
            self.query_one("#parsed-view", ParsedView).clear()
            self._update_frames_label()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-create-session":
            event.stop()
            self.app.push_screen(CreateSessionModal(), self._on_create_session_done)

        elif event.button.id == "btn-terminate-session":
            event.stop()
            if self._current_session_id:
                self.app.terminate_session(self._current_session_id)
            else:
                logger.warning("Select a session first")

        elif event.button.id == "btn-delete-session":
            event.stop()
            if self._current_session_id:
                self.app.delete_session(self._current_session_id)
            else:
                logger.warning("Select a session first")

        elif event.button.id == "btn-frame-filters":
            event.stop()
            def _on_filters_done(result: list[FrameDisplayFilter] | None) -> None:
                if result is not None:
                    self._frame_filters = result
                    self._update_filter_button()
                    if self._current_session_id:
                        session = self.app.api.get_session(self._current_session_id)
                        if session:
                            self.show_frames(session)
            self.app.push_screen(FrameFilterModal(list(self._frame_filters)), _on_filters_done)

        elif event.button.id == "btn-to-forge":
            event.stop()
            if not self._current_session_id:
                logger.warning("Select a frame first")
            elif len(self._selected_frame_ids) > 1:
                self.app.send_frames_to_forge(
                    self._current_session_id, list(self._selected_frame_ids)
                )
            elif self._current_frame_id:
                self.app.send_frame_to_forge(
                    self._current_session_id, self._current_frame_id
                )
            else:
                logger.warning("Select a frame first")

    def _on_create_session_done(self, result: CreateSessionResult | None) -> None:
        """Handle the CreateSessionModal result by opening a forge session."""
        if result is None:
            return
        self.run_worker(self._open_session(result), exclusive=False, thread=False)

    async def _open_session(self, result: CreateSessionResult) -> None:
        try:
            session_id = await self.app.api.open_forge_session(
                result.host, result.port, result.tls
            )
            logger.info(
                "Created session %s -> %s:%d%s",
                session_id[:8], result.host, result.port,
                " [TLS]" if result.tls else "",
            )
        except ConnectionError as exc:
            logger.error("Could not create session: %s", exc)
            self.app.notify(f"Connection failed: {exc}", severity="error")
        except Exception as exc:
            logger.exception("Create session failed")
            self.app.notify(f"Create session failed: {exc}", severity="error")
