"""ForgeTab — unified playbook-based frame sending with live traffic and history."""

from __future__ import annotations

import json
import time as _time

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Button, DataTable, Static, TextArea
from textual.containers import Horizontal, Vertical

from ...forge.models import Playbook, PlaybookFrame, PlaybookRun, TrafficEntry
from ..modals.playbook_modal import PlaybookModal, PlaybookResult
from ..modals.frame_edit import FrameEditModal
from ..utils.frame_codec import hex_template_to_str, str_to_hex_template


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
      │ [▶ Run Playbook]  [■ Stop]  [Clear Traffic]   h=3       │
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
    ForgeTab #btn-frame-up,
    ForgeTab #btn-frame-down {
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
        width: 5;
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
        self._running:            bool = False

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
                    yield Static("  Frames", classes="pane-header")
                    yield DataTable(id="frames-table", cursor_type="row")
                    with Horizontal(classes="frame-controls"):
                        yield Button("↑",  id="btn-frame-up",   flat=True)
                        yield Button("↓",  id="btn-frame-down", flat=True)
                        yield Button("+ Add",    id="btn-frame-add",    variant="success", flat=True)
                        yield Button("✖ Remove", id="btn-frame-remove", variant="error",   flat=True)
                        yield Button("✎ Edit",   id="btn-frame-edit",   variant="primary", flat=True)
                with Vertical(id="frame-editor-pane"):
                    with Horizontal(classes="pane-header"):
                        yield Static(
                            "  Frame Editor  ({{VAR}} · {{VAR:uint32be_add(1)}} · {{VAR:xor(ff)}})",
                            markup=False,
                        )
                        yield Button("HEX", id="btn-frame-mode", compact=True)
                    yield TextArea("", id="frame-editor", theme="monokai")

            with Vertical(id="right-col"):
                with Vertical(id="traffic-pane"):
                    yield Static("  Playbook Traffic", classes="pane-header")
                    yield DataTable(id="traffic-table", cursor_type="row")
                with Vertical(id="frame-view-pane"):
                    yield Static("  Frame View (hex)", classes="pane-header")
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
        tt.add_column("#",     key="num")
        tt.add_column("Dir",   key="dir")
        tt.add_column("Label", key="label")
        tt.add_column("Len",   key="len")
        tt.add_column("Time",  key="time")

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
        if self._current_idx < 0:
            return
        pb = self._playbooks[self._current_idx]
        for i, frame in enumerate(pb.frames):
            dt.add_row(
                str(i + 1),
                self._dir_symbol(frame.direction),
                frame.label or f"Frame {i+1}",
                str(frame.byte_length()),
                frame.preview(),
                key=frame.id,
            )

    def _update_frame_list_row(self, frame_idx: int) -> None:
        if self._current_idx < 0:
            return
        pb = self._playbooks[self._current_idx]
        if frame_idx < 0 or frame_idx >= len(pb.frames):
            return
        frame = pb.frames[frame_idx]
        try:
            dt = self.query_one("#frames-table", DataTable)
            dt.update_cell(frame.id, "dir",     self._dir_symbol(frame.direction),                  update_width=False)
            dt.update_cell(frame.id, "label",   frame.label or f"Frame {frame_idx+1}",              update_width=False)
            dt.update_cell(frame.id, "len",     str(frame.byte_length()),                           update_width=False)
            dt.update_cell(frame.id, "preview", frame.preview(),                                    update_width=False)
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
                self.notify(f"STR parse error: {exc}", severity="error")
                return
        else:
            frame.raw_hex = raw_text
        self._update_frame_list_row(self._selected_frame_idx)

    def _toggle_frame_editor_mode(self) -> None:
        editor = self.query_one("#frame-editor", TextArea)
        current_text = editor.text
        if self._frame_editor_mode == "hex":
            try:
                new_text = hex_template_to_str(current_text)
            except ValueError as exc:
                self.notify(f"Cannot switch to STR: {exc}", severity="error")
                return
            self._frame_editor_mode = "str"
            self.query_one("#btn-frame-mode", Button).label = "STR"
        else:
            try:
                new_text = str_to_hex_template(current_text)
            except ValueError as exc:
                self.notify(f"Cannot switch to HEX: {exc}", severity="error")
                return
            self._frame_editor_mode = "hex"
            self.query_one("#btn-frame-mode", Button).label = "HEX"
        editor.load_text(new_text)

    # ------------------------------------------------------------------
    # Traffic table
    # ------------------------------------------------------------------

    def _clear_traffic(self) -> None:
        self.query_one("#traffic-table", DataTable).clear()

    def _clear_frame_view(self) -> None:
        self.query_one("#frame-view", TextArea).load_text("")

    def _append_traffic_row(self, entry: TrafficEntry) -> None:
        tt = self.query_one("#traffic-table", DataTable)
        direction = "→" if entry.direction == "sent" else "←"
        t = _time.strftime("%H:%M:%S", _time.localtime(entry.timestamp))
        # Count existing rows to get sequential number
        num = len(tt.rows) + 1
        tt.add_row(
            str(num),
            direction,
            entry.frame_label,
            str(len(entry.raw_bytes)),
            t,
            key=entry.id,
        )

    def _populate_traffic_from_run(self, run: PlaybookRun) -> None:
        self._clear_traffic()
        self._clear_frame_view()
        tt = self.query_one("#traffic-table", DataTable)
        for i, entry in enumerate(run.traffic):
            direction = "→" if entry.direction == "sent" else "←"
            t = _time.strftime("%H:%M:%S", _time.localtime(entry.timestamp))
            tt.add_row(
                str(i + 1),
                direction,
                entry.frame_label,
                str(len(entry.raw_bytes)),
                t,
                key=entry.id,
            )

    def _show_traffic_entry(self, entry_id: str) -> None:
        """Display a traffic entry's bytes in the frame view."""
        if self._current_idx < 0:
            return
        pb = self._playbooks[self._current_idx]
        # Search in active traffic (history mode) or last run
        entry = None
        # Check all runs
        for run in pb.runs:
            for e in run.traffic:
                if e.id == entry_id:
                    entry = e
                    break
            if entry:
                break
        if entry is None:
            return
        pairs = " ".join(entry.raw_bytes.hex()[i:i+2] for i in range(0, len(entry.raw_bytes.hex()), 2))
        self.query_one("#frame-view", TextArea).load_text(pairs)

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
            self.notify("Create a playbook first.", severity="warning")
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
            self.notify("Select a frame to remove.", severity="warning")
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
            self.notify("Select a frame to edit.", severity="warning")
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
    # Playbook delete
    # ------------------------------------------------------------------

    def _delete_playbook(self) -> None:
        if self._current_idx < 0:
            self.notify("No playbook selected.", severity="warning")
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
            self.notify("No playbook selected.", severity="warning")
            return

        try:
            all_sessions = self.app.api.list_sessions()
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
            self.notify("No playbook selected to export.", severity="warning")
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
                self.notify(f"Playbook exported to {path}")
            except Exception as exc:
                self.notify(f"Export failed: {exc}", severity="error")

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
                self.notify(f"Import failed (read/parse): {exc}", severity="error")
                return

            label       = data.get("label", "Imported Playbook")
            frames_data = data.get("frames", [])
            if not isinstance(frames_data, list):
                self.notify("Import failed: 'frames' must be a list.", severity="error")
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
            self.notify(f"Imported '{label}' with {len(pb.frames)} frame(s).")

        self.app.push_screen(FilePickerModal(None), _on_pick)

    # ------------------------------------------------------------------
    # Run logic
    # ------------------------------------------------------------------

    def _do_run(self) -> None:
        if self._current_idx < 0:
            self.notify("Create a playbook first.", severity="warning")
            return
        self._save_frame_editor()
        pb = self._playbooks[self._current_idx]
        if not pb.frames:
            self.notify("No frames in the playbook.", severity="warning")
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
            self.notify(
                f"Playbook complete — {len(run.traffic)} traffic entries.",
                severity="information",
            )
        except Exception as exc:
            self.notify(f"Playbook error: {exc}", severity="error")
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

        elif bid == "btn-frame-mode":
            event.stop()
            self._toggle_frame_editor_mode()

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
                return
            pb = self._playbooks[self._current_idx]
            frame_id = str(event.row_key.value)
            for i, frame in enumerate(pb.frames):
                if frame.id == frame_id:
                    if i != self._selected_frame_idx:
                        self._save_frame_editor()
                        self._selected_frame_idx = i
                        self._load_frame_into_editor(frame)
                        self._clear_traffic()
                        self._clear_frame_view()
                    break

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
        hex_str = " ".join(raw_bytes.hex()[i:i+2] for i in range(0, len(raw_bytes.hex()), 2))
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
            hex_str = " ".join(raw_bytes.hex()[i:i+2] for i in range(0, len(raw_bytes.hex()), 2))
            pb.frames.append(PlaybookFrame.create(
                label=frame_label,
                raw_hex=hex_str,
                direction=direction,
            ))
        self.add_playbook(pb)
