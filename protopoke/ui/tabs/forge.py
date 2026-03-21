"""ForgeTab — unified playbook-based frame sending with live traffic and history."""

from __future__ import annotations

import json
import logging
import time as _time

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Button, DataTable, Static, TextArea
from textual.containers import Horizontal, Vertical

from rich.text import Text
from textual.binding import Binding

from ...forge.models import Playbook, PlaybookFrame, PlaybookRun, TrafficEntry
from ..modals.playbook_modal import PlaybookModal, PlaybookResult
from ..modals.frame_edit import FrameEditModal
from ..modals.copy_frame_modal import CopyFrameModal
from ..modals.format_help import FormatHelpModal
from ..utils.frame_codec import (
    hex_template_to_str, str_to_hex_template, hex_pairs_to_str,
)

logger = logging.getLogger(__name__)


class _ForgeFramesTable(DataTable):
    """DataTable with shift+arrow range selection (mirrors traffic tab)."""

    BINDINGS = [
        Binding("shift+up", "shift_up", show=False),
        Binding("shift+down", "shift_down", show=False),
        Binding("escape", "cancel_selection", show=False),
    ]

    def _forge_tab(self) -> "ForgeTab":
        node = self.parent
        while node is not None:
            if isinstance(node, ForgeTab):
                return node
            node = node.parent
        raise RuntimeError("_ForgeFramesTable must be a descendant of ForgeTab")

    def action_shift_up(self) -> None:
        self._forge_tab()._extending_selection = True
        self.action_cursor_up()

    def action_shift_down(self) -> None:
        self._forge_tab()._extending_selection = True
        self.action_cursor_down()

    def action_cancel_selection(self) -> None:
        self._forge_tab()._cancel_frame_selection()


class ForgeTab(Widget):
    """
    Tab 4 — Forge: playbook-based ordered frame sending.

    Layout:
      ┌─────────────────────────────────────────────────────────┐
      │ Playbooks (DataTable)                       h=20%       │
      │  Name  Session  Host  Port  Window  Frames              │
      ├─────────────────────────────────────────────────────────┤
      │ [+ New]  [Edit]  [Import]  [Export]          h=3        │
      ├─────────────────────────────┬───────────────────────────┤
      │ LEFT COLUMN (40%)           │ RIGHT COLUMN (1fr)        │
      │  Frame List (h=40%)         │  "Playbook Traffic"       │
      │  [↑Up][↓Dn][+Add][-Rem]     │  DataTable#traffic-table  │
      │  "Frame Editor ({{VAR}}…)"  │  "Frame View (hex)"       │
      │  Label:[____][→C→S][HEX]    │  TextArea#frame-view      │
      │  TextArea#frame-editor      │                           │
      ├─────────────────────────────┴───────────────────────────┤
      │ [▶ Run Playbook]  [■ Stop]  [Clear Traffic]   h=3      │
      ├─────────────────────────────────────────────────────────┤
      │ Playbook History (DataTable)                 h=20%      │
      │  #  Name  Time  Frames  Sent  Rcvd                      │
      └─────────────────────────────────────────────────────────┘
    """

    DEFAULT_CSS = """
    ForgeTab {
        layout: vertical;
    }
    ForgeTab .pane-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
        text-style: bold;
    }
    ForgeTab #playbook-list-pane {
        height: 20%;
    }
    ForgeTab #playbook-list-pane DataTable {
        height: 1fr;
    }
    ForgeTab .playbook-controls {
        height: 3;
        align: left middle;
        padding: 0 1;
        background: $surface-darken-1;
    }
    ForgeTab .playbook-controls Button {
        margin-right: 1;
    }
    ForgeTab #middle-pane {
        height: 1fr;
        layout: horizontal;
    }
    ForgeTab #left-col {
        width: 1fr;
        layout: vertical;
        border-right: solid $primary-darken-2;
    }
    ForgeTab #frames-list-pane {
        height: 1fr;
    }
    ForgeTab #frames-list-pane DataTable {
        height: 1fr;
    }
    ForgeTab .frame-controls {
        height: 3;
        align: left middle;
        padding: 0 1;
        background: $surface-darken-1;
    }
    ForgeTab .frame-controls Button {
        margin-right: 1;
    }
    ForgeTab .btn-tiny {
        min-width: 5;
        width: 5;
    }
    ForgeTab #frame-editor-pane {
        height: 1fr;
        layout: vertical;
    }
    ForgeTab #frame-editor-pane .pane-header {
        height: 1;
        align: left middle;
    }
    ForgeTab #frame-editor-pane .pane-header Static {
        width: 1fr;
    }
    ForgeTab #frame-editor-pane .pane-header Button {
        width: 9;
        min-width: 9;
        margin: 0;
    }
    ForgeTab #frame-editor-pane .pane-header Button.btn-help {
        width: 5;
        min-width: 5;
        background: $surface-darken-1;
        color: $text-muted;
        margin-right: 1;
    }
    ForgeTab #frame-editor-pane .pane-header Button.mode-active {
        background: $surface;
        color: $text;
    }
    ForgeTab #frame-editor-pane .pane-header Button.mode-inactive {
        background: $primary;
        color: $text-muted;
    }
    ForgeTab #frame-view-pane .pane-header {
        height: 1;
        align: left middle;
    }
    ForgeTab #frame-view-pane .pane-header Static {
        width: 1fr;
    }
    ForgeTab #frame-view-pane .pane-header Button {
        width: 9;
        min-width: 9;
        margin: 0;
    }
    ForgeTab #frame-view-pane .pane-header Button.mode-active {
        background: $surface;
        color: $text;
    }
    ForgeTab #frame-view-pane .pane-header Button.mode-inactive {
        background: $primary;
        color: $text-muted;
    }
    ForgeTab #frame-editor {
        height: 1fr;
    }
    ForgeTab #right-col {
        width: 1fr;
        layout: vertical;
    }
    ForgeTab #traffic-pane {
        height: 1fr;
    }
    ForgeTab #traffic-table {
        height: 1fr;
    }
    ForgeTab #frame-view-pane {
        height: 1fr;
    }
    ForgeTab #frame-view {
        height: 1fr;
    }
    ForgeTab .run-bar {
        height: 3;
        align: left middle;
        padding: 0 1;
        background: $surface-darken-1;
    }
    ForgeTab .run-bar Button {
        margin-right: 1;
    }
    ForgeTab #history-pane {
        height: 20%;
    }
    ForgeTab #history-pane DataTable {
        height: 1fr;
    }
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._playbooks:          list[Playbook] = []
        self._current_idx:        int  = -1
        self._selected_frame_idx: int  = -1
        self._history_view_mode:  bool = False
        self._frame_editor_mode:  str  = "hex"   # "hex" | "str"
        self._frame_view_mode:    str  = "hex"   # "hex" | "str"
        self._running:            bool = False

        # Multi-select state for the frames table (mirrors TrafficTab)
        self._frame_rows: list[str] = []              # frame IDs in table order
        self._anchor_frame_idx: int = -1              # anchor for shift-range
        self._selected_frame_ids: list[str] = []      # ordered selected IDs
        self._extending_selection: bool = False        # set by shift+key
        self._frames_label: Static | None = None      # toolbar label widget
        self._row_data: dict[str, tuple[str, ...]] = {}   # plain cell values
        self._prev_highlighted: set[str] = set()      # currently styled rows

        # Currently displayed traffic entry (for frame-view hex/str toggle)
        self._current_traffic_entry: TrafficEntry | None = None

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Vertical(id="playbook-list-pane"):
            yield Static("  Playbooks", classes="pane-header")
            yield DataTable(id="playbook-table", cursor_type="row")

        with Horizontal(classes="playbook-controls"):
            yield Button("+ New",    id="btn-new-pb",    variant="success", flat=True)
            yield Button("✖ Remove", id="btn-delete-pb", variant="error",   flat=True)
            yield Button("✎ Edit",   id="btn-edit-pb",   variant="primary", flat=True)
            yield Button("Import",   id="btn-import-pb", flat=True)
            yield Button("Export",   id="btn-export-pb", flat=True)

        with Horizontal(id="middle-pane"):
            with Vertical(id="left-col"):
                with Vertical(id="frames-list-pane"):
                    lbl = Static("  Frames  [Shift+↑↓ to multi-select]", classes="pane-header")
                    self._frames_label = lbl
                    yield lbl
                    yield _ForgeFramesTable(id="frames-table", cursor_type="row")
                    with Horizontal(classes="frame-controls"):
                        yield Button("↑", id="btn-frame-up", classes="btn-tiny", flat=True)
                        yield Button("↓", id="btn-frame-down", classes="btn-tiny", flat=True)
                        yield Button("+",     id="btn-frame-add", classes="btn-tiny", variant="success", flat=True)
                        yield Button("✖", id="btn-frame-remove", classes="btn-tiny", variant="error",   flat=True)
                        yield Button("✎",   id="btn-frame-edit", classes="btn-tiny",  variant="primary", flat=True)
                        yield Button("⧉", id="btn-frame-copy", classes="btn-tiny",  flat=True)
                with Vertical(id="frame-editor-pane"):
                    with Horizontal(classes="pane-header"):
                        yield Static(
                            "  Frame Editor  ({{VAR}} · {{VAR:uint32be_add(1)}} · {{VAR:xor(ff)}})",
                            markup=False,
                        )
                        yield Button("?",   id="btn-frame-help", classes="btn-help",     compact=True)
                        yield Button("HEX", id="btn-frame-hex", classes="mode-active",   compact=True)
                        yield Button("STR", id="btn-frame-str", classes="mode-inactive", compact=True)
                    yield TextArea("", id="frame-editor")

            with Vertical(id="right-col"):
                with Vertical(id="traffic-pane"):
                    yield Static("  Playbook Traffic", classes="pane-header")
                    yield DataTable(id="traffic-table", cursor_type="row")
                with Vertical(id="frame-view-pane"):
                    with Horizontal(classes="pane-header"):
                        yield Static("  Frame View")
                        yield Button("HEX", id="btn-view-hex", classes="mode-active",   compact=True)
                        yield Button("STR", id="btn-view-str", classes="mode-inactive", compact=True)
                    yield TextArea("", id="frame-view", read_only=True)

        with Horizontal(classes="run-bar"):
            yield Button("▶ Run Playbook", id="btn-run",          variant="success", flat=True)
            yield Button("■ Stop",         id="btn-stop",         variant="error",   flat=True)
            yield Button("Clear Traffic",  id="btn-clear-traffic",                   flat=True)

        with Vertical(id="history-pane"):
            yield Static("  Playbook History", classes="pane-header")
            yield DataTable(id="history-table", cursor_type="row")

    def on_mount(self) -> None:
        pt = self.query_one("#playbook-table", DataTable)
        pt.add_column("Name",    key="name")
        pt.add_column("Session", key="session")
        pt.add_column("Host",    key="host")
        pt.add_column("Port",    key="port")
        pt.add_column("Window",  key="window")
        pt.add_column("Frames",  key="frames")

        ft = self.query_one("#frames-table", DataTable)
        ft.add_column("#",       key="num")
        ft.add_column("Dir",     key="dir")
        ft.add_column("Label",   key="label")
        ft.add_column("Len",     key="len")
        ft.add_column("Preview", key="preview")

        tt = self.query_one("#traffic-table", DataTable)
        tt.add_column("#",       key="num")
        tt.add_column("Dir",     key="dir")
        tt.add_column("Label",   key="label")
        tt.add_column("Len",     key="len")
        tt.add_column("Time",    key="time")
        tt.add_column("Preview", key="preview")

        ht = self.query_one("#history-table", DataTable)
        ht.add_column("#",      key="num")
        ht.add_column("Name",   key="name")
        ht.add_column("Time",   key="time")
        ht.add_column("Frames", key="frames")
        ht.add_column("Sent",   key="sent")
        ht.add_column("Rcvd",   key="rcvd")

    # ------------------------------------------------------------------
    # Playbook list management
    # ------------------------------------------------------------------

    def add_playbook(self, pb: Playbook) -> None:
        """Add a playbook to the list and switch to it."""
        self._playbooks.append(pb)
        idx = len(self._playbooks) - 1
        pt = self.query_one("#playbook-table", DataTable)
        session_display = pb.source_session_id[:8] if pb.source_session_id else "—"
        pt.add_row(
            pb.label,
            session_display,
            pb.host or "—",
            str(pb.port) if pb.port else "—",
            str(pb.response_window),
            str(len(pb.frames)),
            key=pb.id,
        )
        self._switch_playbook(idx)
        try:
            pt.move_cursor(row=idx)
        except Exception:
            pass

    def _switch_playbook(self, idx: int) -> None:
        """Switch to playbook at *idx*, saving any pending editor state first."""
        if idx < 0 or idx >= len(self._playbooks):
            return
        self._save_frame_editor()
        self._current_idx        = idx
        self._selected_frame_idx = -1
        self._history_view_mode  = False

        self._refresh_frames_list()
        self._clear_frame_editor()
        self._clear_traffic()
        self._clear_frame_view()
        self._refresh_history_table()

    def _update_playbook_list_row(self, idx: int) -> None:
        if idx < 0 or idx >= len(self._playbooks):
            return
        pb = self._playbooks[idx]
        session_display = pb.source_session_id[:8] if pb.source_session_id else "—"
        try:
            pt = self.query_one("#playbook-table", DataTable)
            pt.update_cell(pb.id, "name",    pb.label,                    update_width=False)
            pt.update_cell(pb.id, "session", session_display,             update_width=False)
            pt.update_cell(pb.id, "host",    pb.host or "—",              update_width=False)
            pt.update_cell(pb.id, "port",    str(pb.port) if pb.port else "—", update_width=False)
            pt.update_cell(pb.id, "window",  str(pb.response_window),     update_width=False)
            pt.update_cell(pb.id, "frames",  str(len(pb.frames)),         update_width=False)
        except Exception:
            pass

    def load_playbooks(self, playbooks: list[Playbook]) -> None:
        """Reload all playbooks (e.g. after project open)."""
        self._playbooks          = []
        self._current_idx        = -1
        self._selected_frame_idx = -1
        self._history_view_mode  = False

        pt = self.query_one("#playbook-table", DataTable)
        pt.clear()
        self._clear_traffic()
        self._clear_frame_view()
        self.query_one("#frames-table",  DataTable).clear()
        self.query_one("#history-table", DataTable).clear()
        self._clear_frame_editor()

        for pb in playbooks:
            self._playbooks.append(pb)
            session_display = pb.source_session_id[:8] if pb.source_session_id else "—"
            pt.add_row(
                pb.label,
                session_display,
                pb.host or "—",
                str(pb.port) if pb.port else "—",
                str(pb.response_window),
                str(len(pb.frames)),
                key=pb.id,
            )

        if self._playbooks:
            self._switch_playbook(0)
            try:
                pt.move_cursor(row=0)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Frame list
    # ------------------------------------------------------------------

    @staticmethod
    def _dir_symbol(direction: str) -> str:
        return "→" if direction == "client_to_server" else "←"

    def _refresh_frames_list(self) -> None:
        dt = self.query_one("#frames-table", DataTable)
        dt.clear()
        self._frame_rows = []
        self._row_data = {}
        self._prev_highlighted = set()
        self._anchor_frame_idx = -1
        self._selected_frame_ids = []
        self._update_frames_label()
        if self._current_idx < 0:
            return
        pb = self._playbooks[self._current_idx]
        for i, frame in enumerate(pb.frames):
            values = (
                str(i + 1),
                self._dir_symbol(frame.direction),
                frame.label or f"Frame {i+1}",
                str(frame.byte_length()),
                frame.preview(),
            )
            self._row_data[frame.id] = values
            dt.add_row(*values, key=frame.id)
            self._frame_rows.append(frame.id)

    def _update_frame_list_row(self, frame_idx: int) -> None:
        if self._current_idx < 0:
            return
        pb = self._playbooks[self._current_idx]
        if frame_idx < 0 or frame_idx >= len(pb.frames):
            return
        frame = pb.frames[frame_idx]
        values = (
            str(frame_idx + 1),
            self._dir_symbol(frame.direction),
            frame.label or f"Frame {frame_idx+1}",
            str(frame.byte_length()),
            frame.preview(),
        )
        self._row_data[frame.id] = values
        try:
            dt = self.query_one("#frames-table", DataTable)
            for col_key, val in zip(self._FRAME_COL_KEYS, values):
                dt.update_cell(frame.id, col_key, val, update_width=False)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Frame editor
    # ------------------------------------------------------------------

    def _clear_frame_editor(self) -> None:
        self.query_one("#frame-editor", TextArea).load_text("")

    def _load_frame_into_editor(self, frame: PlaybookFrame) -> None:
        if self._frame_editor_mode == "str":
            content = hex_template_to_str(frame.raw_hex)
        else:
            content = frame.raw_hex
        self.query_one("#frame-editor", TextArea).load_text(content)

    def _save_frame_editor(self) -> None:
        """Flush hex content back to the currently selected frame."""
        if self._current_idx < 0 or self._selected_frame_idx < 0:
            return
        pb = self._playbooks[self._current_idx]
        if self._selected_frame_idx >= len(pb.frames):
            return
        frame    = pb.frames[self._selected_frame_idx]
        raw_text = self.query_one("#frame-editor", TextArea).text
        if self._frame_editor_mode == "str":
            try:
                frame.raw_hex = str_to_hex_template(raw_text)
            except ValueError as exc:
                logger.error("STR parse error: %s", exc)
                return
        else:
            frame.raw_hex = raw_text
        self._update_frame_list_row(self._selected_frame_idx)

    def _set_frame_editor_mode(self, mode: str) -> None:
        """Switch the frame editor to the given *mode* ('hex' or 'str')."""
        if mode == self._frame_editor_mode:
            return
        editor = self.query_one("#frame-editor", TextArea)
        current_text = editor.text
        if mode == "str":
            try:
                new_text = hex_template_to_str(current_text)
            except ValueError as exc:
                logger.error("Cannot switch to STR: %s", exc)
                return
        else:
            try:
                new_text = str_to_hex_template(current_text)
            except ValueError as exc:
                logger.error("Cannot switch to HEX: %s", exc)
                return
        self._frame_editor_mode = mode
        editor.load_text(new_text)
        self._update_frame_mode_buttons()

    def _update_frame_mode_buttons(self) -> None:
        btn_hex = self.query_one("#btn-frame-hex", Button)
        btn_str = self.query_one("#btn-frame-str", Button)
        for btn, is_active in [(btn_hex, self._frame_editor_mode == "hex"),
                               (btn_str, self._frame_editor_mode == "str")]:
            btn.set_class(is_active,  "mode-active")
            btn.set_class(not is_active, "mode-inactive")

    # ------------------------------------------------------------------
    # Frame multi-select
    # ------------------------------------------------------------------

    _FRAME_COL_KEYS = ("num", "dir", "label", "len", "preview")
    _SELECTED_STYLE = "bold underline"

    def _highlight_selection(self) -> None:
        """Apply / remove bold styling on multi-selected rows."""
        dt = self.query_one("#frames-table", DataTable)
        new_sel = set(self._selected_frame_ids) if len(self._selected_frame_ids) > 1 else set()
        to_style   = new_sel - self._prev_highlighted
        to_unstyle = self._prev_highlighted - new_sel

        for fid in to_style | to_unstyle:
            data = self._row_data.get(fid)
            if data is None:
                continue
            is_sel = fid in new_sel
            for col_key, val in zip(self._FRAME_COL_KEYS, data):
                cell = Text(val, style=self._SELECTED_STYLE) if is_sel else val
                try:
                    dt.update_cell(fid, col_key, cell, update_width=False)
                except Exception:
                    pass

        self._prev_highlighted = new_sel

    def _update_frames_label(self) -> None:
        if self._frames_label is None:
            return
        n = len(self._selected_frame_ids)
        if n > 1:
            self._frames_label.update(f"  Frames  [{n} selected — Esc to cancel]")
        else:
            self._frames_label.update("  Frames  [Shift+↑↓ to multi-select]")

    def _cancel_frame_selection(self) -> None:
        """Collapse multi-frame selection back to single frame."""
        if len(self._selected_frame_ids) <= 1:
            return
        if self._anchor_frame_idx >= 0 and self._anchor_frame_idx < len(self._frame_rows):
            single_id = self._frame_rows[self._anchor_frame_idx]
        elif self._selected_frame_idx >= 0 and self._current_idx >= 0:
            pb = self._playbooks[self._current_idx]
            if self._selected_frame_idx < len(pb.frames):
                single_id = pb.frames[self._selected_frame_idx].id
            else:
                return
        else:
            return
        self._selected_frame_ids = [single_id]
        self._highlight_selection()
        self._update_frames_label()

    # ------------------------------------------------------------------
    # Frame View mode (hex / str)
    # ------------------------------------------------------------------

    def _set_frame_view_mode(self, mode: str) -> None:
        """Switch frame view between 'hex' and 'str'."""
        if mode == self._frame_view_mode:
            return
        self._frame_view_mode = mode
        self._update_frame_view_mode_buttons()
        # Re-render the current traffic entry if any
        if self._current_traffic_entry is not None:
            self._render_frame_view(self._current_traffic_entry)

    def _update_frame_view_mode_buttons(self) -> None:
        btn_hex = self.query_one("#btn-view-hex", Button)
        btn_str = self.query_one("#btn-view-str", Button)
        for btn, is_active in [(btn_hex, self._frame_view_mode == "hex"),
                               (btn_str, self._frame_view_mode == "str")]:
            btn.set_class(is_active,  "mode-active")
            btn.set_class(not is_active, "mode-inactive")

    def _render_frame_view(self, entry: TrafficEntry) -> None:
        """Display a traffic entry in the frame view using current mode."""
        pairs = " ".join(
            entry.raw_bytes.hex()[i:i+2]
            for i in range(0, len(entry.raw_bytes.hex()), 2)
        )
        if self._frame_view_mode == "str":
            try:
                text = hex_pairs_to_str(pairs)
            except Exception:
                text = pairs
        else:
            text = pairs
        self.query_one("#frame-view", TextArea).load_text(text)

    # ------------------------------------------------------------------
    # Traffic table
    # ------------------------------------------------------------------

    def _clear_traffic(self) -> None:
        self.query_one("#traffic-table", DataTable).clear()

    def _clear_frame_view(self) -> None:
        self._current_traffic_entry = None
        self.query_one("#frame-view", TextArea).load_text("")

    def _append_traffic_row(self, entry: TrafficEntry) -> None:
        tt = self.query_one("#traffic-table", DataTable)
        was_empty = len(tt.rows) == 0
        direction = "→" if entry.direction == "sent" else "←"
        t = _time.strftime("%H:%M:%S", _time.localtime(entry.timestamp))
        # Count existing rows to get sequential number
        num = len(tt.rows) + 1
        _preview = entry.raw_bytes[:16].hex()
        if len(entry.raw_bytes) > 16:
            _preview += "…"
        tt.add_row(
            str(num),
            direction,
            entry.frame_label,
            str(len(entry.raw_bytes)),
            t,
            _preview,
            key=entry.id,
        )
        # Auto-select the first row so the Frame View populates immediately
        if was_empty:
            tt.move_cursor(row=0)
            self._show_traffic_entry(entry.id)

    def _populate_traffic_from_run(self, run: PlaybookRun) -> None:
        self._clear_traffic()
        self._clear_frame_view()
        tt = self.query_one("#traffic-table", DataTable)
        for i, entry in enumerate(run.traffic):
            direction = "→" if entry.direction == "sent" else "←"
            t = _time.strftime("%H:%M:%S", _time.localtime(entry.timestamp))
            _preview = entry.raw_bytes[:16].hex()
            if len(entry.raw_bytes) > 16:
                _preview += "…"
            tt.add_row(
                str(i + 1),
                direction,
                entry.frame_label,
                str(len(entry.raw_bytes)),
                t,
                _preview,
                key=entry.id,
            )

    def _show_traffic_entry(self, entry_id: str) -> None:
        """Display a traffic entry's bytes in the frame view."""
        if self._current_idx < 0:
            return
        pb = self._playbooks[self._current_idx]
        entry = None
        for run in pb.runs:
            for e in run.traffic:
                if e.id == entry_id:
                    entry = e
                    break
            if entry:
                break
        if entry is None:
            return
        self._current_traffic_entry = entry
        self._render_frame_view(entry)

    # ------------------------------------------------------------------
    # History table
    # ------------------------------------------------------------------

    def _refresh_history_table(self) -> None:
        ht = self.query_one("#history-table", DataTable)
        ht.clear()
        if self._current_idx < 0:
            return
        pb = self._playbooks[self._current_idx]
        for i, run in enumerate(pb.runs):
            t = _time.strftime("%H:%M:%S", _time.localtime(run.timestamp))
            ht.add_row(
                str(i + 1),
                run.playbook_label,
                t,
                str(len(run.traffic)),
                str(run.sent_bytes_total()),
                str(run.received_bytes_total()),
                key=run.id,
            )

    # ------------------------------------------------------------------
    # Frame operations
    # ------------------------------------------------------------------

    def _add_blank_frame(self) -> None:
        if self._current_idx < 0:
            logger.warning("Create a playbook first")
            return
        self._save_frame_editor()
        pb = self._playbooks[self._current_idx]
        frame = PlaybookFrame.create(label=f"Frame {len(pb.frames)+1}")
        insert_at = self._selected_frame_idx + 1 if self._selected_frame_idx >= 0 else len(pb.frames)
        pb.frames.insert(insert_at, frame)
        self._selected_frame_idx = insert_at
        self._refresh_frames_list()
        self._load_frame_into_editor(frame)
        try:
            self.query_one("#frames-table", DataTable).move_cursor(row=insert_at)
        except Exception:
            pass
        self._update_playbook_list_row(self._current_idx)
        if hasattr(self.app, "mark_dirty"):
            self.app.mark_dirty()

    def _remove_frame(self) -> None:
        if self._current_idx < 0 or self._selected_frame_idx < 0:
            logger.warning("Select a frame to remove")
            return
        pb = self._playbooks[self._current_idx]
        pb.frames.pop(self._selected_frame_idx)
        new_idx = min(self._selected_frame_idx, len(pb.frames) - 1)
        self._selected_frame_idx = new_idx
        self._refresh_frames_list()
        if new_idx >= 0:
            self._load_frame_into_editor(pb.frames[new_idx])
            try:
                self.query_one("#frames-table", DataTable).move_cursor(row=new_idx)
            except Exception:
                pass
        else:
            self._clear_frame_editor()
        self._update_playbook_list_row(self._current_idx)
        if hasattr(self.app, "mark_dirty"):
            self.app.mark_dirty()

    def _move_frame(self, delta: int) -> None:
        if self._current_idx < 0 or self._selected_frame_idx < 0:
            return
        self._save_frame_editor()
        pb = self._playbooks[self._current_idx]
        i, j = self._selected_frame_idx, self._selected_frame_idx + delta
        if j < 0 or j >= len(pb.frames):
            return
        pb.frames[i], pb.frames[j] = pb.frames[j], pb.frames[i]
        self._selected_frame_idx = j
        self._refresh_frames_list()
        try:
            self.query_one("#frames-table", DataTable).move_cursor(row=j)
        except Exception:
            pass

    def _open_frame_edit_modal(self) -> None:
        if self._current_idx < 0 or self._selected_frame_idx < 0:
            logger.warning("Select a frame to edit")
            return
        pb = self._playbooks[self._current_idx]
        if self._selected_frame_idx >= len(pb.frames):
            return
        frame = pb.frames[self._selected_frame_idx]
        modal = FrameEditModal(label=frame.label, direction=frame.direction)
        self.app.push_screen(modal, self._on_frame_edit_result)

    def _on_frame_edit_result(self, result: tuple[str, str] | None) -> None:
        if result is None or self._current_idx < 0 or self._selected_frame_idx < 0:
            return
        pb = self._playbooks[self._current_idx]
        if self._selected_frame_idx >= len(pb.frames):
            return
        label, direction = result
        frame = pb.frames[self._selected_frame_idx]
        frame.label     = label
        frame.direction = direction
        self._update_frame_list_row(self._selected_frame_idx)
        if hasattr(self.app, "mark_dirty"):
            self.app.mark_dirty()

    # ------------------------------------------------------------------
    # Copy frame to another playbook
    # ------------------------------------------------------------------

    def _open_copy_frame_modal(self) -> None:
        if self._current_idx < 0 or (self._selected_frame_idx < 0 and not self._selected_frame_ids):
            logger.warning("Select a frame to copy")
            return
        self._save_frame_editor()
        targets = [
            (pb.id, pb.label, pb.host or "", pb.port or 0, len(pb.frames))
            for i, pb in enumerate(self._playbooks)
            if i != self._current_idx
        ]
        if not targets:
            logger.warning("No other playbook to copy to")
            return
        self.app.push_screen(CopyFrameModal(targets), self._on_copy_frame_result)

    def _on_copy_frame_result(self, target_id: str | None) -> None:
        if target_id is None or self._current_idx < 0:
            return
        src_pb = self._playbooks[self._current_idx]
        target_pb = next((pb for pb in self._playbooks if pb.id == target_id), None)
        if target_pb is None:
            return

        # Determine which frames to copy: multi-select or single
        if len(self._selected_frame_ids) > 1:
            frames_to_copy = [
                f for f in src_pb.frames if f.id in self._selected_frame_ids
            ]
        elif self._selected_frame_idx >= 0 and self._selected_frame_idx < len(src_pb.frames):
            frames_to_copy = [src_pb.frames[self._selected_frame_idx]]
        else:
            return

        for src_frame in frames_to_copy:
            new_frame = PlaybookFrame.create(
                label=src_frame.label,
                raw_hex=src_frame.raw_hex,
                direction=src_frame.direction,
            )
            target_pb.frames.append(new_frame)

        target_idx = next(i for i, pb in enumerate(self._playbooks) if pb.id == target_id)
        self._update_playbook_list_row(target_idx)
        if hasattr(self.app, "mark_dirty"):
            self.app.mark_dirty()
        n = len(frames_to_copy)
        logger.info("%d frame(s) copied to '%s'", n, target_pb.label)

    # ------------------------------------------------------------------
    # Playbook delete
    # ------------------------------------------------------------------

    def _delete_playbook(self) -> None:
        if self._current_idx < 0:
            logger.warning("No playbook selected")
            return
        pb = self._playbooks[self._current_idx]
        self._playbooks.pop(self._current_idx)
        try:
            self.query_one("#playbook-table", DataTable).remove_row(pb.id)
        except Exception:
            pass
        # Reset state
        new_idx = min(self._current_idx, len(self._playbooks) - 1)
        self._current_idx        = -1
        self._selected_frame_idx = -1
        self._history_view_mode  = False
        self._clear_frame_editor()
        self._clear_traffic()
        self._clear_frame_view()
        self.query_one("#frames-table",  DataTable).clear()
        self.query_one("#history-table", DataTable).clear()
        if new_idx >= 0:
            self._switch_playbook(new_idx)
            try:
                self.query_one("#playbook-table", DataTable).move_cursor(row=new_idx)
            except Exception:
                pass
        if hasattr(self.app, "mark_dirty"):
            self.app.mark_dirty()

    # ------------------------------------------------------------------
    # Playbook modal (New / Edit)
    # ------------------------------------------------------------------

    def _open_playbook_modal(self, edit: bool = False) -> None:
        if edit and self._current_idx < 0:
            logger.warning("No playbook selected")
            return

        try:
            all_sessions = self.app.api.list_active_sessions()
        except Exception:
            all_sessions = []

        sessions = [
            (s.id, f"Session {s.id[:8]}", s.info.server_host, s.info.server_port)
            for s in all_sessions
        ]

        if edit:
            pb = self._playbooks[self._current_idx]
            modal = PlaybookModal(
                sessions,
                label=pb.label,
                host=pb.host,
                port=pb.port,
                tls=pb.tls,
                session_id=pb.source_session_id,
                window=pb.response_window,
                edit=True,
            )
            self.app.push_screen(modal, self._on_edit_playbook)
        else:
            modal = PlaybookModal(sessions, edit=False)
            self.app.push_screen(modal, self._on_new_playbook)

    def _on_new_playbook(self, result: PlaybookResult | None) -> None:
        if result is None:
            return
        pb = Playbook.create(
            label=result.label or f"Playbook {len(self._playbooks)+1}",
            host=result.host,
            port=result.port,
            tls=result.tls,
            source_session_id=result.session_id,
            response_window=result.window,
        )
        self.add_playbook(pb)
        if hasattr(self.app, "mark_dirty"):
            self.app.mark_dirty()

    def _on_edit_playbook(self, result: PlaybookResult | None) -> None:
        if result is None or self._current_idx < 0:
            return
        pb = self._playbooks[self._current_idx]
        pb.label             = result.label or pb.label
        pb.host              = result.host
        pb.port              = result.port
        pb.tls               = result.tls
        pb.source_session_id = result.session_id
        pb.response_window   = result.window
        self._update_playbook_list_row(self._current_idx)
        if hasattr(self.app, "mark_dirty"):
            self.app.mark_dirty()

    # ------------------------------------------------------------------
    # Import / Export
    # ------------------------------------------------------------------

    def _export_playbook(self) -> None:
        if self._current_idx < 0:
            logger.warning("No playbook selected to export")
            return
        self._save_frame_editor()
        pb = self._playbooks[self._current_idx]
        export_data = {
            "label": pb.label,
            "frames": [
                {"label": f.label, "raw_hex": f.raw_hex, "direction": f.direction}
                for f in pb.frames
            ],
        }

        from ..modals.project import SaveAsModal as _SaveModal

        class _ExportModal(_SaveModal):
            def compose(self):
                from textual.app import ComposeResult as CR
                from textual.widgets import Button as Btn, Input as Inp, Label as Lbl, Static as Sta
                from textual.containers import Horizontal as H, Vertical as V
                with V():
                    yield Lbl("Export Playbook", classes="modal-title")
                    yield Lbl("Destination path (.json):")
                    yield Inp(value=self._default_path, placeholder="~/playbook_export.json", id="save-path")
                    yield Sta("Frames and directions will be saved (connection config excluded).", classes="hint")
                    with H(classes="buttons"):
                        yield Btn("Cancel", variant="default", id="btn-cancel")
                        yield Btn("Export", variant="primary",  id="btn-save")

        def _on_path(path: str | None) -> None:
            if not path:
                return
            if not path.endswith(".json"):
                path += ".json"
            try:
                import pathlib
                pathlib.Path(path).write_text(json.dumps(export_data, indent=2), encoding="utf-8")
                logger.info("Playbook exported to %s", path)
            except Exception as exc:
                logger.error("Export failed: %s", exc)

        self.app.push_screen(_ExportModal(""), _on_path)

    def _import_playbook(self) -> None:
        from ..modals.file_picker import FilePickerModal

        def _on_pick(path: str | None) -> None:
            if not path:
                return
            try:
                import pathlib
                raw  = pathlib.Path(path).read_text(encoding="utf-8")
                data = json.loads(raw)
            except Exception as exc:
                logger.error("Import failed (read/parse): %s", exc)
                return

            label       = data.get("label", "Imported Playbook")
            frames_data = data.get("frames", [])
            if not isinstance(frames_data, list):
                logger.error("Import failed: 'frames' must be a list")
                return

            pb = Playbook.create(label=label)
            for fd in frames_data:
                pb.frames.append(PlaybookFrame.create(
                    label=fd.get("label", ""),
                    raw_hex=fd.get("raw_hex", ""),
                    direction=fd.get("direction", "client_to_server"),
                ))
            self.add_playbook(pb)
            if hasattr(self.app, "mark_dirty"):
                self.app.mark_dirty()
            logger.info("Imported '%s' with %d frame(s)", label, len(pb.frames))

        self.app.push_screen(FilePickerModal(None), _on_pick)

    # ------------------------------------------------------------------
    # Run logic
    # ------------------------------------------------------------------

    def _do_run(self) -> None:
        if self._current_idx < 0:
            logger.warning("Create a playbook first")
            return
        self._save_frame_editor()
        pb = self._playbooks[self._current_idx]
        if not pb.frames:
            logger.warning("No frames in the playbook")
            return
        if pb.source_session_id:
            try:
                session = self.app.api.get_session(pb.source_session_id)
            except Exception:
                session = None
            if session is None or not session.is_active():
                logger.error(
                    "Session is closed — cannot run playbook. "
                    "Edit the playbook to select an active session or use a custom destination"
                )
                return
        self._history_view_mode = False
        self._running = True
        self._clear_traffic()
        self._clear_frame_view()
        self.run_worker(self._async_run(pb), exclusive=True)

    async def _async_run(self, pb: Playbook) -> None:
        run = None

        def on_entry(entry: TrafficEntry) -> None:
            if self._running:
                self._append_traffic_row(entry)

        try:
            run = await self.app.api.run_playbook(pb, on_entry=on_entry)
            pb.runs.append(run)
            self._refresh_history_table()
            logger.info("Playbook complete — %d traffic entries", len(run.traffic))
        except Exception as exc:
            logger.error("Playbook error: %s", exc)
        finally:
            self._running = False

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""

        if bid == "btn-new-pb":
            event.stop()
            self._open_playbook_modal(edit=False)

        elif bid == "btn-delete-pb":
            event.stop()
            self._delete_playbook()

        elif bid == "btn-edit-pb":
            event.stop()
            self._open_playbook_modal(edit=True)

        elif bid == "btn-import-pb":
            event.stop()
            self._import_playbook()

        elif bid == "btn-export-pb":
            event.stop()
            self._export_playbook()

        elif bid == "btn-frame-up":
            event.stop()
            self._move_frame(-1)

        elif bid == "btn-frame-down":
            event.stop()
            self._move_frame(1)

        elif bid == "btn-frame-add":
            event.stop()
            self._add_blank_frame()

        elif bid == "btn-frame-remove":
            event.stop()
            self._remove_frame()

        elif bid == "btn-frame-edit":
            event.stop()
            self._open_frame_edit_modal()

        elif bid == "btn-frame-copy":
            event.stop()
            self._open_copy_frame_modal()

        elif bid in ("btn-frame-hex", "btn-frame-str"):
            event.stop()
            self._set_frame_editor_mode("hex" if bid == "btn-frame-hex" else "str")

        elif bid == "btn-frame-help":
            event.stop()
            self.app.push_screen(FormatHelpModal())

        elif bid in ("btn-view-hex", "btn-view-str"):
            event.stop()
            self._set_frame_view_mode("hex" if bid == "btn-view-hex" else "str")

        elif bid == "btn-run":
            event.stop()
            self._do_run()

        elif bid == "btn-stop":
            event.stop()
            self._running = False

        elif bid == "btn-clear-traffic":
            event.stop()
            self._clear_traffic()
            self._clear_frame_view()

    # ------------------------------------------------------------------
    # DataTable events
    # ------------------------------------------------------------------

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        dt_id = event.data_table.id

        if dt_id == "playbook-table":
            pb_id = str(event.row_key.value)
            for i, pb in enumerate(self._playbooks):
                if pb.id == pb_id:
                    if i != self._current_idx:
                        self._switch_playbook(i)
                    break

        elif dt_id == "frames-table":
            if self._current_idx < 0 or self._history_view_mode:
                self._extending_selection = False
                return
            pb = self._playbooks[self._current_idx]
            frame_id = str(event.row_key.value)
            current_idx = next(
                (i for i, fid in enumerate(self._frame_rows) if fid == frame_id), -1
            )
            if current_idx < 0:
                self._extending_selection = False
                return

            if self._extending_selection and self._anchor_frame_idx >= 0:
                # Extend / shrink the selection range
                lo = min(self._anchor_frame_idx, current_idx)
                hi = max(self._anchor_frame_idx, current_idx)
                self._selected_frame_ids = self._frame_rows[lo : hi + 1]
            else:
                # Single selection — reset anchor, load into editor
                self._anchor_frame_idx = current_idx
                self._selected_frame_ids = [frame_id]
                if current_idx != self._selected_frame_idx:
                    self._save_frame_editor()
                    self._selected_frame_idx = current_idx
                    self._load_frame_into_editor(pb.frames[current_idx])
                    self._clear_traffic()
                    self._clear_frame_view()

            self._extending_selection = False
            self._update_frames_label()
            self._highlight_selection()

        elif dt_id == "traffic-table":
            entry_id = str(event.row_key.value)
            self._show_traffic_entry(entry_id)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None:
            return
        dt_id = event.data_table.id

        if dt_id == "history-table":
            if self._current_idx < 0:
                return
            pb = self._playbooks[self._current_idx]
            run_id = str(event.row_key.value)
            for run in pb.runs:
                if run.id == run_id:
                    self._selected_frame_idx = -1
                    self._clear_frame_editor()
                    self._populate_traffic_from_run(run)
                    self._history_view_mode = True
                    break

        elif dt_id == "frames-table":
            if self._current_idx < 0:
                return
            pb = self._playbooks[self._current_idx]
            frame_id = str(event.row_key.value)
            for i, frame in enumerate(pb.frames):
                if frame.id == frame_id:
                    self._save_frame_editor()
                    self._selected_frame_idx = i
                    self._load_frame_into_editor(frame)
                    self._history_view_mode = False
                    self._clear_traffic()
                    self._clear_frame_view()
                    break

    # ------------------------------------------------------------------
    # Public: called from app when importing frames from Traffic tab
    # ------------------------------------------------------------------

    def add_playbook_from_bytes(
        self,
        raw_bytes: bytes,
        label:     str,
        host:      str  = "",
        port:      int  = 0,
        tls:       bool = False,
        source_session_id: str | None = None,
        direction: str  = "client_to_server",
    ) -> None:
        """Create a new playbook with one frame from raw bytes (Traffic tab → Forge)."""
        pb = Playbook.create(
            label=label,
            host=host,
            port=port,
            tls=tls,
            source_session_id=source_session_id,
        )
        hex_str = " ".join(f"{b:02x}" for b in raw_bytes)
        pb.frames.append(PlaybookFrame.create(
            label=label,
            raw_hex=hex_str,
            direction=direction,
        ))
        self.add_playbook(pb)

    def add_frames_to_playbook(
        self,
        frames_data: list[tuple[bytes, str, str]],  # (raw_bytes, label, direction)
        host:        str  = "",
        port:        int  = 0,
        tls:         bool = False,
        source_session_id: str | None = None,
        playbook_label:    str        = "",
    ) -> None:
        """Create a new playbook with multiple frames (Traffic tab multi-select → Forge)."""
        pb = Playbook.create(
            label=playbook_label or f"Playbook {len(self._playbooks)+1}",
            host=host,
            port=port,
            tls=tls,
            source_session_id=source_session_id,
        )
        for raw_bytes, frame_label, direction in frames_data:
            hex_str = " ".join(f"{b:02x}" for b in raw_bytes)
            pb.frames.append(PlaybookFrame.create(
                label=frame_label,
                raw_hex=hex_str,
                direction=direction,
            ))
        self.add_playbook(pb)
