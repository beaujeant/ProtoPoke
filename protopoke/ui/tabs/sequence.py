"""SequenceTab — session-based multi-packet replay with variable substitution."""

from __future__ import annotations

import json
import time as _time

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input, Label, Static, Switch, TextArea
from textual.containers import Horizontal, Vertical

from ...sequence.models import HistoryEntry, SequenceSession, SequenceStep
from ..utils.frame_codec import hex_template_to_str, str_to_hex_template


class SequenceTab(Widget):
    """
    Tab 6 — Sequence: send ordered frame chains with {{VAR}} variable
    substitution and an optional Python script for response-driven extraction.

    Layout (all panes 100% width, stacked vertically):

      ┌─────────────────────────────────────────────────────────┐
      │ Sequences pane (DataTable list)           h=20%         │
      │  Name        Steps                                      │
      │  Sequence 1  3                                          │
      │  Sequence 2  5                                          │
      ├─────────────────────────────────────────────────────────┤
      │ [+ New]  [Import]  [Export]               h=3           │
      ├─────────────────────────────────────────────────────────┤
      │ FRAME LIST  (~20%)                                      │
      │  #   Label      Len   Preview                           │
      ├─────────────────────────────────────────────────────────┤
      │ [↑ Up] [↓ Down] [+ Add] [- Remove]         h=3         │
      ├─────────────────────────────────────────────────────────┤
      │ STEP EDITOR  (~20%)                                     │
      │  Label: [___________________]          [HEX] / [STR]   │
      │  ┌─────────────────────────────────────────────────┐   │
      │  │ hex content with {{VAR}} placeholders           │   │
      │  └─────────────────────────────────────────────────┘   │
      ├─────────────────────────────────────────────────────────┤
      │ SEND / RECV HISTORY  (1fr)                              │
      ├─────────────────────────────────────────────────────────┤
      │ [▶ Run] [■ Stop]  Session: [____]  Host: [___]          │
      │ Port: [___]  [TLS ⬜]  Window (s): [1.0]  [Clear Hist] │
      └─────────────────────────────────────────────────────────┘
    """

    DEFAULT_CSS = """
    SequenceTab {
        layout: vertical;
    }
    SequenceTab .seq-list-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
        text-style: bold;
    }
    SequenceTab #seq-list-pane {
        height: 20%;
        border-bottom: solid $primary-darken-2;
    }
    SequenceTab #seq-list-pane DataTable {
        height: 1fr;
    }
    SequenceTab .seq-controls {
        height: 3;
        align: left middle;
        padding: 0 1;
        background: $surface-darken-1;
    }
    SequenceTab .seq-controls Button {
        margin-right: 1;
    }
    SequenceTab .pane-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
        text-style: bold;
    }
    SequenceTab #step-list-pane {
        height: 20%;
        border-bottom: solid $primary-darken-2;
    }
    SequenceTab #step-list-pane DataTable {
        height: 1fr;
    }
    SequenceTab .step-controls {
        height: 3;
        align: left middle;
        padding: 0 1;
        background: $surface-darken-1;
    }
    SequenceTab .step-controls Button {
        margin-right: 1;
    }
    SequenceTab #step-editor-pane {
        height: 22%;
        border-bottom: solid $primary-darken-2;
    }
    SequenceTab #step-label-bar {
        height: 3;
        align: left middle;
        padding: 0 1;
        background: $surface-darken-2;
    }
    SequenceTab #step-label-bar Label {
        margin-right: 1;
        width: 7;
    }
    SequenceTab #step-label-bar Input {
        width: 1fr;
    }
    SequenceTab #btn-step-mode {
        width: 5;
        margin-left: 1;
    }
    SequenceTab #step-hex-editor {
        height: 1fr;
    }
    SequenceTab #history-pane {
        height: 1fr;
    }
    SequenceTab #history-pane DataTable {
        height: 1fr;
    }
    SequenceTab .run-bar {
        height: 5;
        padding: 0 1;
        background: $surface-darken-1;
        layout: vertical;
    }
    SequenceTab .run-bar-row {
        height: 2;
        align: left middle;
    }
    SequenceTab .run-bar-row Button {
        margin-right: 1;
    }
    SequenceTab .run-bar-row Label {
        margin-right: 1;
    }
    SequenceTab .run-bar-row Input {
        margin-right: 1;
    }
    SequenceTab .run-bar-row #seq-host {
        width: 20;
    }
    SequenceTab .run-bar-row #seq-port {
        width: 6;
    }
    SequenceTab .run-bar-row #seq-session-id {
        width: 22;
    }
    SequenceTab .run-bar-row #seq-window {
        width: 6;
    }
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._sequences: list[SequenceSession] = []
        self._current_idx: int = -1
        self._selected_step_idx: int = -1
        self._running: bool = False
        # "hex" or "str" — controls how the step editor displays / parses content
        self._step_editor_mode: str = "hex"

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        # Sequence list pane
        with Vertical(id="seq-list-pane"):
            yield Static("  Sequences", classes="seq-list-header")
            yield DataTable(id="seq-table", cursor_type="row")

        # Sequence controls
        with Horizontal(classes="seq-controls"):
            yield Button("+ New",    id="btn-new-seq",    variant="success", compact=True)
            yield Button("Import",   id="btn-import-seq", compact=True)
            yield Button("Export",   id="btn-export-seq", compact=True)

        # Frame list
        with Vertical(id="step-list-pane"):
            yield Static("  Frame List", classes="pane-header")
            yield DataTable(id="step-table", cursor_type="row")

        # Step controls
        with Horizontal(classes="step-controls"):
            yield Button("↑ Up",     id="btn-step-up",     compact=True)
            yield Button("↓ Down",   id="btn-step-down",   compact=True)
            yield Button("+ Add",    id="btn-step-add",    variant="success", compact=True)
            yield Button("- Remove", id="btn-step-remove", variant="error",   compact=True)

        # Step editor
        with Vertical(id="step-editor-pane"):
            yield Static(
                "  Step Editor  ({{VAR}} · {{VAR:uint32be_add(1)}} · {{VAR:xor(ff)}} · {{VAR:script(expr)}})",
                classes="pane-header",
                markup=False,
            )
            with Horizontal(id="step-label-bar"):
                yield Label("Label:")
                yield Input("", id="step-label-input", placeholder="step name")
                yield Button("HEX", id="btn-step-mode", compact=True)
            yield TextArea("", id="step-hex-editor", theme="monokai")

        # History
        with Vertical(id="history-pane"):
            with Horizontal(classes="pane-header"):
                yield Static("  Send / Recv History")
                yield Button("Clear", id="btn-clear-hist", compact=True)
            yield DataTable(id="history-table", cursor_type="row")

        # Run bar (two rows)
        with Vertical(classes="run-bar"):
            with Horizontal(classes="run-bar-row"):
                yield Button("▶ Run Sequence", id="btn-run",  variant="success", compact=True)
                yield Button("■ Stop",         id="btn-stop", variant="error",   compact=True)
                yield Label("Session ID (blank=new):")
                yield Input("", id="seq-session-id", placeholder="leave blank for new connection")
            with Horizontal(classes="run-bar-row"):
                yield Label("Host:")
                yield Input("", id="seq-host", placeholder="127.0.0.1")
                yield Label("Port:")
                yield Input("", id="seq-port", placeholder="9090", restrict=r"\d*")
                yield Label("TLS:")
                yield Switch(False, id="seq-tls")
                yield Label(" Window (s):")
                yield Input("1.0", id="seq-window")

    def on_mount(self) -> None:
        # Sequence list table
        st = self.query_one("#seq-table", DataTable)
        st.add_column("Name",  key="name")
        st.add_column("Steps", key="steps")

        dt = self.query_one("#step-table", DataTable)
        dt.add_column("#",       key="num")
        dt.add_column("Dir",     key="dir")
        dt.add_column("Label",   key="label")
        dt.add_column("Len",     key="len")
        dt.add_column("Preview", key="preview")

        ht = self.query_one("#history-table", DataTable)
        ht.add_column("#",       key="num")
        ht.add_column("Dir",     key="dir")
        ht.add_column("Len",     key="len")
        ht.add_column("Preview", key="preview")
        ht.add_column("Time",    key="time")

    # ------------------------------------------------------------------
    # Sequence list management
    # ------------------------------------------------------------------

    def _refresh_seq_list(self) -> None:
        """Repopulate the sequence DataTable from self._sequences."""
        st = self.query_one("#seq-table", DataTable)
        st.clear()
        for seq in self._sequences:
            st.add_row(seq.label, str(len(seq.steps)), key=seq.id)

    def add_sequence(self, seq: SequenceSession) -> None:
        """Add a new sequence and switch to it."""
        self._sequences.append(seq)
        idx = len(self._sequences) - 1
        st = self.query_one("#seq-table", DataTable)
        st.add_row(seq.label, str(len(seq.steps)), key=seq.id)
        # Auto-select the newly added sequence
        self._switch_to(idx)
        try:
            st.move_cursor(row=idx)
        except Exception:
            pass

    def _switch_to(self, idx: int) -> None:
        if idx < 0 or idx >= len(self._sequences):
            return
        # Save any edits to the currently selected step before switching
        self._save_step_editor()

        self._current_idx = idx
        self._selected_step_idx = -1
        seq = self._sequences[idx]

        # Update run bar
        self.query_one("#seq-host",       Input).value = seq.host
        self.query_one("#seq-port",       Input).value = str(seq.port) if seq.port else ""
        self.query_one("#seq-tls",        Switch).value = seq.tls
        self.query_one("#seq-session-id", Input).value = seq.source_session_id or ""
        self.query_one("#seq-window",     Input).value = str(seq.response_window)

        self._refresh_step_list()
        self._refresh_history()
        self._clear_step_editor()

    def load_sequences(self, sequences: list[SequenceSession]) -> None:
        """Reload all sequences (e.g. after project open)."""
        self._sequences = []
        self._current_idx = -1
        self._selected_step_idx = -1
        st = self.query_one("#seq-table", DataTable)
        st.clear()
        for seq in sequences:
            self._sequences.append(seq)
            st.add_row(seq.label, str(len(seq.steps)), key=seq.id)
        # Auto-select the first sequence if any
        if self._sequences:
            self._switch_to(0)
            try:
                st.move_cursor(row=0)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Step list
    # ------------------------------------------------------------------

    @staticmethod
    def _direction_symbol(direction: str) -> str:
        """Return a short arrow symbol for a step direction."""
        return "→" if direction == "client_to_server" else "←"

    def _refresh_step_list(self) -> None:
        dt = self.query_one("#step-table", DataTable)
        dt.clear()
        if self._current_idx < 0:
            return
        seq = self._sequences[self._current_idx]
        for i, step in enumerate(seq.steps):
            dt.add_row(
                str(i + 1),
                self._direction_symbol(step.direction),
                step.label or f"Step {i+1}",
                str(step.byte_length()),
                step.preview(),
                key=step.id,
            )

    def _load_step_into_editor(self, step: SequenceStep) -> None:
        self.query_one("#step-label-input", Input).value = step.label
        if self._step_editor_mode == "str":
            content = hex_template_to_str(step.raw_hex)
        else:
            content = step.raw_hex
        self.query_one("#step-hex-editor", TextArea).load_text(content)

    def _clear_step_editor(self) -> None:
        self.query_one("#step-label-input", Input).value = ""
        self.query_one("#step-hex-editor",  TextArea).load_text("")

    def _save_step_editor(self) -> None:
        """Flush the editor contents back to the currently selected step."""
        if self._current_idx < 0 or self._selected_step_idx < 0:
            return
        seq = self._sequences[self._current_idx]
        if self._selected_step_idx >= len(seq.steps):
            return
        step = seq.steps[self._selected_step_idx]
        step.label = self.query_one("#step-label-input", Input).value
        raw_text   = self.query_one("#step-hex-editor",  TextArea).text
        if self._step_editor_mode == "str":
            try:
                step.raw_hex = str_to_hex_template(raw_text)
            except ValueError as exc:
                self.notify(f"STR parse error: {exc}", severity="error")
                return
        else:
            step.raw_hex = raw_text
        # Update the row in the table
        try:
            dt = self.query_one("#step-table", DataTable)
            dt.update_cell(step.id, "dir",     self._direction_symbol(step.direction),            update_width=False)
            dt.update_cell(step.id, "label",   step.label or f"Step {self._selected_step_idx+1}", update_width=False)
            dt.update_cell(step.id, "len",     str(step.byte_length()),                           update_width=False)
            dt.update_cell(step.id, "preview", step.preview(),                                    update_width=False)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def _refresh_history(self) -> None:
        ht = self.query_one("#history-table", DataTable)
        ht.clear()
        if self._current_idx < 0:
            return
        seq = self._sequences[self._current_idx]
        for i, entry in enumerate(seq.history, 1):
            self._add_history_row(ht, i, entry)

    def _add_history_row(self, ht: DataTable, num: int, entry: HistoryEntry) -> None:
        direction = "→" if entry.direction == "sent" else "←"
        preview = entry.raw_bytes[:12].hex()
        if len(entry.raw_bytes) > 12:
            preview += "…"
        t = _time.strftime("%H:%M:%S", _time.localtime(entry.timestamp))
        ht.add_row(
            str(num),
            direction,
            str(len(entry.raw_bytes)),
            preview,
            t,
            key=entry.id,
        )

    def append_history_entry(self, entry: HistoryEntry) -> None:
        """Append a single entry to the history table (called live during a run)."""
        if self._current_idx < 0:
            return
        seq = self._sequences[self._current_idx]
        ht = self.query_one("#history-table", DataTable)
        self._add_history_row(ht, len(seq.history), entry)

    # ------------------------------------------------------------------
    # Run bar helpers
    # ------------------------------------------------------------------

    def _get_response_window(self) -> float:
        try:
            return max(0.1, float(self.query_one("#seq-window", Input).value))
        except (ValueError, Exception):
            return 1.0

    def _sync_run_bar_to_seq(self) -> None:
        """Write run bar values into the current sequence."""
        if self._current_idx < 0:
            return
        seq = self._sequences[self._current_idx]
        seq.host              = self.query_one("#seq-host",       Input).value.strip()
        seq.source_session_id = self.query_one("#seq-session-id", Input).value.strip() or None
        seq.tls               = self.query_one("#seq-tls",        Switch).value
        seq.response_window   = self._get_response_window()
        try:
            seq.port = int(self.query_one("#seq-port", Input).value)
        except ValueError:
            seq.port = 0

    # ------------------------------------------------------------------
    # Import / Export sequences
    # ------------------------------------------------------------------

    def _export_sequence(self) -> None:
        """Export the current sequence to a JSON file via a path input modal."""
        if self._current_idx < 0:
            self.notify("No sequence selected to export.", severity="warning")
            return
        self._save_step_editor()
        seq = self._sequences[self._current_idx]

        export_data = {
            "label": seq.label,
            "steps": [
                {
                    "label":     step.label,
                    "raw_hex":   step.raw_hex,
                    "direction": step.direction,
                }
                for step in seq.steps
            ],
        }

        from ..modals.project import SaveAsModal as _SaveModal

        class _ExportModal(_SaveModal):
            def compose(self):
                from textual.app import ComposeResult
                from textual.widgets import Button, Input, Label, Static
                from textual.containers import Horizontal, Vertical
                with Vertical():
                    yield Label("Export Sequence", classes="modal-title")
                    yield Label("Destination path (.json):")
                    yield Input(
                        value=self._default_path,
                        placeholder="~/sequence_export.json",
                        id="save-path",
                    )
                    yield Static(
                        "The sequence steps and direction will be saved (not session info).",
                        classes="hint",
                    )
                    with Horizontal(classes="buttons"):
                        yield Button("Cancel", variant="default", id="btn-cancel")
                        yield Button("Export", variant="primary", id="btn-save")

        def _on_path(path: str | None) -> None:
            if not path:
                return
            if not path.endswith(".json"):
                path = path + ".json"
            try:
                import pathlib
                pathlib.Path(path).write_text(
                    json.dumps(export_data, indent=2), encoding="utf-8"
                )
                self.notify(f"Sequence exported to {path}")
            except Exception as exc:
                self.notify(f"Export failed: {exc}", severity="error")

        self.app.push_screen(_ExportModal(""), _on_path)

    def _import_sequence(self) -> None:
        """Import a sequence from a JSON file — creates a new sequence tab."""
        from ..modals.file_picker import FilePickerModal

        def _on_pick(path: str | None) -> None:
            if not path:
                return
            try:
                import pathlib
                raw = pathlib.Path(path).read_text(encoding="utf-8")
                data = json.loads(raw)
            except Exception as exc:
                self.notify(f"Import failed (read/parse): {exc}", severity="error")
                return

            label = data.get("label", "Imported Sequence")
            steps_data = data.get("steps", [])
            if not isinstance(steps_data, list):
                self.notify("Import failed: 'steps' must be a list.", severity="error")
                return

            seq = SequenceSession.create(label=label)
            for sd in steps_data:
                step = SequenceStep.create(
                    label=sd.get("label", ""),
                    raw_hex=sd.get("raw_hex", ""),
                    direction=sd.get("direction", "client_to_server"),
                )
                seq.steps.append(step)

            # Note: session fields (host, port, tls, source_session_id) are NOT
            # imported — the user needs to configure them for the new context.
            self.add_sequence(seq)
            if hasattr(self.app, "mark_dirty"):
                self.app.mark_dirty()
            self.notify(f"Imported '{label}' with {len(seq.steps)} step(s).")

        self.app.push_screen(FilePickerModal(None), _on_pick)

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""

        if bid == "btn-new-seq":
            event.stop()
            self._do_new_sequence()

        elif bid == "btn-import-seq":
            event.stop()
            self._import_sequence()

        elif bid == "btn-export-seq":
            event.stop()
            self._export_sequence()

        elif bid == "btn-step-mode":
            event.stop()
            self._toggle_step_editor_mode()

        elif bid == "btn-step-up":
            event.stop()
            self._move_step(-1)

        elif bid == "btn-step-down":
            event.stop()
            self._move_step(1)

        elif bid == "btn-step-add":
            event.stop()
            self._add_blank_step()

        elif bid == "btn-step-remove":
            event.stop()
            self._remove_step()

        elif bid == "btn-run":
            event.stop()
            self._do_run()

        elif bid == "btn-stop":
            event.stop()
            self._running = False

        elif bid == "btn-clear-hist":
            event.stop()
            if 0 <= self._current_idx < len(self._sequences):
                self._sequences[self._current_idx].history.clear()
                self.query_one("#history-table", DataTable).clear()

    def _toggle_step_editor_mode(self) -> None:
        """Switch the step editor between HEX and STR (python-like) display."""
        editor = self.query_one("#step-hex-editor", TextArea)
        current_text = editor.text

        if self._step_editor_mode == "hex":
            # Convert current HEX content → STR and switch mode
            try:
                new_text = hex_template_to_str(current_text)
            except ValueError as exc:
                self.notify(f"Cannot switch to STR: {exc}", severity="error")
                return
            self._step_editor_mode = "str"
            self.query_one("#btn-step-mode", Button).label = "STR"
        else:
            # Convert current STR content → HEX and switch mode
            try:
                new_text = str_to_hex_template(current_text)
            except ValueError as exc:
                self.notify(f"Cannot switch to HEX: {exc}", severity="error")
                return
            self._step_editor_mode = "hex"
            self.query_one("#btn-step-mode", Button).label = "HEX"

        editor.load_text(new_text)

    def _do_new_sequence(self) -> None:
        from ...sequence.models import SequenceSession
        seq = SequenceSession.create(label=f"Sequence {len(self._sequences)+1}")
        self.add_sequence(seq)
        if hasattr(self.app, "mark_dirty"):
            self.app.mark_dirty()

    def _move_step(self, delta: int) -> None:
        """Move the selected step up (delta=-1) or down (delta=+1)."""
        if self._current_idx < 0 or self._selected_step_idx < 0:
            return
        self._save_step_editor()
        seq = self._sequences[self._current_idx]
        i = self._selected_step_idx
        j = i + delta
        if j < 0 or j >= len(seq.steps):
            return
        seq.steps[i], seq.steps[j] = seq.steps[j], seq.steps[i]
        self._selected_step_idx = j
        self._refresh_step_list()
        # Re-select the moved row
        dt = self.query_one("#step-table", DataTable)
        try:
            dt.move_cursor(row=j)
        except Exception:
            pass

    def _add_blank_step(self) -> None:
        if self._current_idx < 0:
            self.notify("Create a sequence first.", severity="warning")
            return
        self._save_step_editor()
        seq = self._sequences[self._current_idx]
        step = SequenceStep.create(label=f"Step {len(seq.steps)+1}")
        insert_at = self._selected_step_idx + 1 if self._selected_step_idx >= 0 else len(seq.steps)
        seq.steps.insert(insert_at, step)
        self._selected_step_idx = insert_at
        self._refresh_step_list()
        self._load_step_into_editor(step)
        # Move cursor to new row
        try:
            self.query_one("#step-table", DataTable).move_cursor(row=insert_at)
        except Exception:
            pass
        # Update sequence list step count
        self._update_seq_list_row()
        if hasattr(self.app, "mark_dirty"):
            self.app.mark_dirty()

    def _remove_step(self) -> None:
        if self._current_idx < 0 or self._selected_step_idx < 0:
            self.notify("Select a step to remove.", severity="warning")
            return
        seq = self._sequences[self._current_idx]
        seq.steps.pop(self._selected_step_idx)
        new_idx = min(self._selected_step_idx, len(seq.steps) - 1)
        self._selected_step_idx = new_idx
        self._refresh_step_list()
        if new_idx >= 0:
            self._load_step_into_editor(seq.steps[new_idx])
            try:
                self.query_one("#step-table", DataTable).move_cursor(row=new_idx)
            except Exception:
                pass
        else:
            self._clear_step_editor()
        # Update sequence list step count
        self._update_seq_list_row()
        if hasattr(self.app, "mark_dirty"):
            self.app.mark_dirty()

    def _update_seq_list_row(self) -> None:
        """Refresh the step count in the sequence list for the current sequence."""
        if self._current_idx < 0 or self._current_idx >= len(self._sequences):
            return
        seq = self._sequences[self._current_idx]
        try:
            st = self.query_one("#seq-table", DataTable)
            st.update_cell(seq.id, "steps", str(len(seq.steps)), update_width=False)
        except Exception:
            pass

    def _do_run(self) -> None:
        if self._current_idx < 0:
            self.notify("Create a sequence first.", severity="warning")
            return
        self._save_step_editor()
        self._sync_run_bar_to_seq()
        seq = self._sequences[self._current_idx]
        if not seq.steps:
            self.notify("No steps in the sequence.", severity="warning")
            return
        self._running = True
        self.run_worker(self._async_run(seq), exclusive=True)

    async def _async_run(self, seq: SequenceSession) -> None:
        """Background worker: run the sequence and update the UI live."""
        from ...sequence.models import HistoryEntry as HE

        def on_entry(entry: HE) -> None:
            if self._running:
                self.append_history_entry(entry)

        try:
            await self.app.api.run_sequence(seq=seq, on_entry=on_entry)
            if self._running:
                self.notify(
                    f"Sequence complete — {len(seq.history)} packets in history.",
                    severity="information",
                )
        except Exception as exc:
            self.notify(f"Sequence error: {exc}", severity="error")
        finally:
            self._running = False

    # ------------------------------------------------------------------
    # DataTable row selection
    # ------------------------------------------------------------------

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Arrow-key navigation auto-selects the highlighted row."""
        if event.data_table.id == "seq-table":
            if event.row_key is None:
                return
            seq_id = str(event.row_key.value)
            for i, seq in enumerate(self._sequences):
                if seq.id == seq_id:
                    if i != self._current_idx:
                        self._switch_to(i)
                    break

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "seq-table":
            seq_id = str(event.row_key.value)
            for i, seq in enumerate(self._sequences):
                if seq.id == seq_id:
                    self._switch_to(i)
                    break

        elif event.data_table.id == "step-table":
            if self._current_idx < 0:
                return
            # Save before switching
            self._save_step_editor()
            seq = self._sequences[self._current_idx]
            step_id = str(event.row_key.value)
            for i, step in enumerate(seq.steps):
                if step.id == step_id:
                    self._selected_step_idx = i
                    self._load_step_into_editor(step)
                    break

        elif event.data_table.id == "history-table":
            if self._current_idx < 0:
                return
            entry_id = str(event.row_key.value)
            seq = self._sequences[self._current_idx]
            for entry in seq.history:
                if entry.id == entry_id:
                    # Show the raw bytes in the editor (respects current mode)
                    hex_pairs = " ".join(
                        entry.raw_bytes.hex()[i : i + 2]
                        for i in range(0, len(entry.raw_bytes.hex()), 2)
                    )
                    if self._step_editor_mode == "str":
                        from ..utils.frame_codec import hex_template_to_str as _h2s
                        display = _h2s(hex_pairs)
                    else:
                        display = hex_pairs
                    self.query_one("#step-hex-editor", TextArea).load_text(display)
                    self.query_one("#step-label-input", Input).value = (
                        f"[{entry.direction}] {entry.step_label}"
                    )
                    break

    # ------------------------------------------------------------------
    # Public: add a frame from the Traffic tab
    # ------------------------------------------------------------------

    def add_step_from_bytes(
        self,
        raw_bytes: bytes,
        label: str,
        host: str = "",
        port: int = 0,
        tls: bool = False,
        source_session_id: str | None = None,
        direction: str = "client_to_server",
    ) -> None:
        """
        Add a new step from raw bytes (called when importing from the Traffic tab).

        If no sequence exists, a new one is created first, inheriting the
        connection parameters from the imported frame's session.

        Args:
            direction: ``"client_to_server"`` or ``"server_to_client"``.  A
                       sequence should only contain steps of one direction; this
                       is enforced at the Traffic tab import level (only frames
                       matching the first selected frame's direction are sent).
        """
        if self._current_idx < 0:
            from ...sequence.models import SequenceSession
            seq = SequenceSession.create(
                label="Imported Sequence",
                host=host,
                port=port,
                tls=tls,
                source_session_id=source_session_id,
            )
            self.add_sequence(seq)

        self._save_step_editor()
        seq = self._sequences[self._current_idx]
        hex_str = " ".join(
            raw_bytes.hex()[i : i + 2] for i in range(0, len(raw_bytes.hex()), 2)
        )
        step = SequenceStep.create(label=label, raw_hex=hex_str, direction=direction)
        seq.steps.append(step)
        self._selected_step_idx = len(seq.steps) - 1
        self._refresh_step_list()
        self._load_step_into_editor(step)
        try:
            self.query_one("#step-table", DataTable).move_cursor(
                row=len(seq.steps) - 1
            )
        except Exception:
            pass
        self._update_seq_list_row()
