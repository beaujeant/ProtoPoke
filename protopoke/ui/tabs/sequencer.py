"""SequencerTab — session-based multi-packet replay with variable substitution."""

from __future__ import annotations

import time as _time

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input, Label, Static, Switch, TextArea
from textual.containers import Horizontal, Vertical

from ...sequencer.models import HistoryEntry, SequencerSession, SequenceStep
from ..utils.frame_codec import hex_template_to_str, str_to_hex_template


class SequencerTab(Widget):
    """
    Tab 6 — Sequencer: send ordered packet chains with {{VAR}} variable
    substitution and an optional Python script for response-driven extraction.

    Layout (all panes 100% width, stacked vertically):

      ┌─────────────────────────────────────────────────────────┐
      │ Sequences: [Seq 1] [Seq 2] [+ New]     tab strip  h=3  │
      ├─────────────────────────────────────────────────────────┤
      │ PACKET LIST  (~25%)                                     │
      │  #   Label      Len   Preview                           │
      │  1   Handshake  12    01 02 03 04 05 …                  │
      │  2   Login      40    01 0a {{SESS_ID}} …               │
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
      │  #   Dir  Len   Preview                  Time           │
      │  1   →    40    01 0a de ad be ef …     14:32:01        │
      │  2   ←    12    61 62 00 01 …           14:32:01        │
      ├─────────────────────────────────────────────────────────┤
      │ [▶ Run] [■ Stop]  Session: [____]  Host: [___]          │
      │ Port: [___]  [TLS ⬜]  Window (s): [1.0]  [Clear Hist] │
      └─────────────────────────────────────────────────────────┘
    """

    DEFAULT_CSS = """
    SequencerTab {
        layout: vertical;
    }
    SequencerTab .tab-strip {
        height: 3;
        align: left middle;
        background: $surface-darken-1;
        padding: 0 1;
    }
    SequencerTab .tab-strip Button {
        margin-right: 1;
    }
    SequencerTab .pane-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
        text-style: bold;
    }
    SequencerTab #step-list-pane {
        height: 25%;
        border-bottom: solid $primary-darken-2;
    }
    SequencerTab #step-list-pane DataTable {
        height: 1fr;
    }
    SequencerTab .step-controls {
        height: 3;
        align: left middle;
        padding: 0 1;
        background: $surface-darken-1;
    }
    SequencerTab .step-controls Button {
        margin-right: 1;
    }
    SequencerTab #step-editor-pane {
        height: 22%;
        border-bottom: solid $primary-darken-2;
    }
    SequencerTab #step-label-bar {
        height: 3;
        align: left middle;
        padding: 0 1;
        background: $surface-darken-2;
    }
    SequencerTab #step-label-bar Label {
        margin-right: 1;
        width: 7;
    }
    SequencerTab #step-label-bar Input {
        width: 1fr;
    }
    SequencerTab #btn-step-mode {
        width: 5;
        margin-left: 1;
    }
    SequencerTab #step-hex-editor {
        height: 1fr;
    }
    SequencerTab #history-pane {
        height: 1fr;
    }
    SequencerTab #history-pane DataTable {
        height: 1fr;
    }
    SequencerTab .run-bar {
        height: 5;
        padding: 0 1;
        background: $surface-darken-1;
        layout: vertical;
    }
    SequencerTab .run-bar-row {
        height: 2;
        align: left middle;
    }
    SequencerTab .run-bar-row Button {
        margin-right: 1;
    }
    SequencerTab .run-bar-row Label {
        margin-right: 1;
    }
    SequencerTab .run-bar-row Input {
        margin-right: 1;
    }
    SequencerTab .run-bar-row #seq-host {
        width: 20;
    }
    SequencerTab .run-bar-row #seq-port {
        width: 6;
    }
    SequencerTab .run-bar-row #seq-session-id {
        width: 22;
    }
    SequencerTab .run-bar-row #seq-window {
        width: 6;
    }
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._sequences: list[SequencerSession] = []
        self._current_idx: int = -1
        self._selected_step_idx: int = -1
        self._running: bool = False
        # "hex" or "str" — controls how the step editor displays / parses content
        self._step_editor_mode: str = "hex"

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        # Tab strip
        with Horizontal(classes="tab-strip"):
            yield Label("Sequences:")
            yield Button("[+ New]", id="btn-new-seq", variant="success", compact=True)

        # Packet list
        with Vertical(id="step-list-pane"):
            yield Static("  Packet List", classes="pane-header")
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
    # Sequence (tab) management
    # ------------------------------------------------------------------

    def add_sequence(self, seq: SequencerSession) -> None:
        """Add a new sequence and switch to it."""
        self._sequences.append(seq)
        idx = len(self._sequences) - 1
        btn = Button(seq.label, id=f"seq-tab-{idx}", compact=True)
        self.query_one(".tab-strip", Horizontal).mount(btn, before="#btn-new-seq")
        self._switch_to(idx)

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

    def load_sequences(self, sequences: list[SequencerSession]) -> None:
        """Reload all sequences (e.g. after project open)."""
        for btn in self.query(".tab-strip Button"):
            if btn.id and btn.id.startswith("seq-tab-"):
                btn.remove()
        self._sequences = []
        self._current_idx = -1
        self._selected_step_idx = -1
        for seq in sequences:
            self.add_sequence(seq)

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
    # Button handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""

        if bid == "btn-new-seq":
            event.stop()
            self._do_new_sequence()

        elif bid == "btn-step-mode":
            event.stop()
            self._toggle_step_editor_mode()

        elif bid.startswith("seq-tab-"):
            event.stop()
            idx = int(bid.removeprefix("seq-tab-"))
            self._save_step_editor()
            self._switch_to(idx)

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
        from ...sequencer.models import SequencerSession
        seq = SequencerSession.create(label=f"Sequence {len(self._sequences)+1}")
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
        if hasattr(self.app, "mark_dirty"):
            self.app.mark_dirty()

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

    async def _async_run(self, seq: SequencerSession) -> None:
        """Background worker: run the sequence and update the UI live."""
        from ...sequencer.models import HistoryEntry as HE

        def on_entry(entry: HE) -> None:
            if self._running:
                self.call_from_thread(self.append_history_entry, entry)

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

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "step-table":
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
    # Public: add a frame from the Logs tab
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
        Add a new step from raw bytes (called when importing from the Logs tab).

        If no sequence exists, a new one is created first, inheriting the
        connection parameters from the imported frame's session.

        Args:
            direction: ``"client_to_server"`` or ``"server_to_client"``.  A
                       sequence should only contain steps of one direction; this
                       is enforced at the Logs tab import level (only frames
                       matching the first selected frame's direction are sent).
        """
        if self._current_idx < 0:
            from ...sequencer.models import SequencerSession
            seq = SequencerSession.create(
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
