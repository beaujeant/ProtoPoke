"""
NotesTab — view and edit the knowledge base (findings + notes).

Layout:

  ┌──────────────────────────────────────────────────────────────────────┐
  │ [+ New]  [Edit]  [Delete]   filter: <input>        [Findings | Notes] │  toolbar
  ├──────────────────────────────────────────────────────────────────────┤
  │ table of findings or notes (selectable row)                          │
  ├──────────────────────────────────────────────────────────────────────┤
  │ details / preview pane for the selected entry                        │
  └──────────────────────────────────────────────────────────────────────┘

The Findings sub-view shows status / confidence / scope / title columns
and a markdown preview pane.  The Notes sub-view shows title / author /
updated columns and a markdown body pane.

Mutations from the UI mark the entry ``locked=True`` so the MCP layer
will refuse subsequent AI edits — the operator's word is final.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input, Label, Static

from ..modals.confirm import ConfirmModal
from ..modals.finding_edit import FindingEditModal
from ..modals.note_edit import NoteEditModal
from ..widgets.segmented_control import SegmentedControl

if TYPE_CHECKING:
    from ...api import ProtoPokeAPI
    from ...knowledge import Finding, Note

logger = logging.getLogger(__name__)


_VIEW_FINDINGS = "findings"
_VIEW_NOTES    = "notes"


class NotesTab(Widget):
    """Tab — knowledge base viewer / editor."""

    DEFAULT_CSS = """
    NotesTab {
        layout: vertical;
    }
    NotesTab .toolbar {
        height: 3;
        background: $primary-darken-2;
        align: left middle;
        padding: 0 1;
    }
    NotesTab .toolbar SegmentedControl {
        height: 100%;
    }
    NotesTab .toolbar SegmentedControl Button.segment {
        height: 100%;
        content-align: center middle;
    }
    NotesTab .toolbar-spacer {
        width: 1fr;
    }
    NotesTab .toolbar Input {
        width: 30;
        margin-right: 1;
    }
    NotesTab .toolbar > Button {
        margin-right: 1;
        padding: 0 0;
    }
    NotesTab DataTable {
        height: 2fr;
    }
    NotesTab #detail-pane {
        height: 1fr;
        border-top: solid $primary-darken-2;
        padding: 0 1;
    }
    NotesTab .pane-header {
        background: $surface-darken-1;
        color: $text;
        padding: 0 1;
        height: 1;
        text-style: bold;
    }
    NotesTab #detail-body {
        height: 1fr;
        background: $surface;
        padding: 0 1;
    }
    """

    def __init__(self, api: "ProtoPokeAPI", *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._api = api
        self._view: str = _VIEW_FINDINGS
        self._row_to_id: dict[int, str] = {}
        self._selected_id: Optional[str] = None
        self._filter_text: str = ""

    # ------------------------------------------------------------------
    # API rebind (called by the app after a project reload)
    # ------------------------------------------------------------------

    def rebind_api(self, api: "ProtoPokeAPI") -> None:
        self._api = api
        self._selected_id = None
        self.refresh_table()

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Horizontal(classes="toolbar"):
            yield Button("+ New",    id="btn-new",    variant="success", flat=True)
            yield Button("✎ Edit",   id="btn-edit",   variant="primary", flat=True)
            yield Button("✖ Delete", id="btn-delete", variant="error",   flat=True)
            yield Input(placeholder="filter…", id="filter-input")
            yield Static("", classes="toolbar-spacer")
            yield SegmentedControl(
                [("Findings", _VIEW_FINDINGS), ("Notes", _VIEW_NOTES)],
                value=_VIEW_FINDINGS,
                id="view-switch",
                compact=False,
            )
        yield DataTable(id="kb-table", cursor_type="row")
        with Vertical(id="detail-pane"):
            yield Static("Details", classes="pane-header")
            yield Static("(select an entry)", id="detail-body", markup=False)

    def on_mount(self) -> None:
        self._build_columns()
        self.refresh_table()

    # ------------------------------------------------------------------
    # Toolbar events
    # ------------------------------------------------------------------

    def on_segmented_control_changed(self, event: SegmentedControl.Changed) -> None:
        if event.control.id != "view-switch":
            return
        self._view = str(event.value)
        self._selected_id = None
        self._build_columns()
        self.refresh_table()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "filter-input":
            return
        self._filter_text = event.value
        self.refresh_table()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-new":
            self._open_new_modal()
        elif bid == "btn-edit":
            self._open_edit_modal()
        elif bid == "btn-delete":
            self._confirm_delete()

    # ------------------------------------------------------------------
    # Table
    # ------------------------------------------------------------------

    def _build_columns(self) -> None:
        dt = self.query_one("#kb-table", DataTable)
        dt.clear(columns=True)
        if self._view == _VIEW_FINDINGS:
            dt.add_column("Status",     key="status",     width=12)
            dt.add_column("Conf",       key="confidence", width=6)
            dt.add_column("Scope",      key="scope",      width=28)
            dt.add_column("Title",      key="title",      width=40)
            dt.add_column("Author",     key="author",     width=8)
            dt.add_column("Locked",     key="locked",     width=6)
        else:
            dt.add_column("Title",   key="title",   width=40)
            dt.add_column("Tags",    key="tags",    width=20)
            dt.add_column("Author",  key="author",  width=8)
            dt.add_column("Locked",  key="locked",  width=6)
            dt.add_column("Updated", key="updated", width=20)

    def refresh_table(self) -> None:
        dt = self.query_one("#kb-table", DataTable)
        dt.clear()
        self._row_to_id.clear()
        query = self._filter_text.strip() or None

        if self._view == _VIEW_FINDINGS:
            findings = self._api.knowledge.list_findings(query=query)
            for f in findings:
                scope = self._format_finding_scope(f)
                row = dt.add_row(
                    f.status, f.confidence, scope, f.title,
                    f.author, "✓" if f.locked else "",
                )
                self._row_to_id[len(self._row_to_id)] = f.id
        else:
            notes = self._api.knowledge.list_notes(query=query)
            for n in notes:
                updated = time.strftime("%Y-%m-%d %H:%M",
                                        time.localtime(n.updated_at))
                row = dt.add_row(
                    n.title, ", ".join(n.tags), n.author,
                    "✓" if n.locked else "", updated,
                )
                self._row_to_id[len(self._row_to_id)] = n.id

        # Try to keep the previously-selected entry highlighted if it survived.
        if self._selected_id:
            for row_idx, eid in self._row_to_id.items():
                if eid == self._selected_id:
                    dt.move_cursor(row=row_idx)
                    self._render_details(eid)
                    return
        self._selected_id = None
        self._render_details(None)

    def on_data_table_row_highlighted(
        self, event: DataTable.RowHighlighted,
    ) -> None:
        idx = event.cursor_row
        eid = self._row_to_id.get(idx)
        self._selected_id = eid
        self._render_details(eid)

    # ------------------------------------------------------------------
    # Details pane
    # ------------------------------------------------------------------

    def _render_details(self, entry_id: Optional[str]) -> None:
        body = self.query_one("#detail-body", Static)
        if entry_id is None:
            body.update("(select an entry)")
            return
        if self._view == _VIEW_FINDINGS:
            f = self._api.knowledge.get_finding(entry_id)
            if f is None:
                body.update("(not found)")
                return
            fwd_name = self._api.resolve_forwarder_name(f.forwarder_id) or "—"
            updated = time.strftime("%Y-%m-%d %H:%M",
                                    time.localtime(f.updated_at))
            text = (
                f"Title:       {f.title}\n"
                f"Status:      {f.status}   Confidence: {f.confidence}\n"
                f"Author:      {f.author}   Locked: {f.locked}   Updated: {updated}\n"
                f"Protocol:    {f.protocol_name or '—'}\n"
                f"Message:     {f.message_name or '—'}   Field: {f.field_name or '—'}\n"
                f"Bytes:       {f.byte_offset if f.byte_offset is not None else '—'}"
                f"  len={f.byte_length if f.byte_length is not None else '—'}\n"
                f"Direction:   {f.direction.value if f.direction else '—'}\n"
                f"Forwarder:   {fwd_name}\n"
                f"Tags:        {', '.join(f.tags) or '—'}\n"
                f"Evidence:    {', '.join(f.evidence_frame_ids) or '—'}\n"
                f"Counter:     {', '.join(f.counter_evidence_frame_ids) or '—'}\n"
                f"\n"
                f"{f.description or '(no description)'}"
            )
            body.update(text)
        else:
            n = self._api.knowledge.get_note(entry_id)
            if n is None:
                body.update("(not found)")
                return
            updated = time.strftime("%Y-%m-%d %H:%M",
                                    time.localtime(n.updated_at))
            text = (
                f"Title:    {n.title}\n"
                f"Author:   {n.author}   Locked: {n.locked}   Updated: {updated}\n"
                f"Tags:     {', '.join(n.tags) or '—'}\n"
                f"\n"
                f"{n.body_md or '(empty)'}"
            )
            body.update(text)

    def _format_finding_scope(self, f: "Finding") -> str:
        parts: list[str] = []
        if f.protocol_name:
            parts.append(f.protocol_name)
        if f.message_name:
            parts.append(f.message_name)
        if f.field_name:
            parts.append(f.field_name)
        elif f.byte_offset is not None:
            span = f"@{f.byte_offset}"
            if f.byte_length is not None:
                span += f"+{f.byte_length}"
            parts.append(span)
        return "/".join(parts) if parts else "—"

    # ------------------------------------------------------------------
    # Modal callbacks
    # ------------------------------------------------------------------

    def _open_new_modal(self) -> None:
        if self._view == _VIEW_FINDINGS:
            self.app.push_screen(
                FindingEditModal(forwarders=self._api.forwarders),
                self._on_finding_saved,
            )
        else:
            self.app.push_screen(NoteEditModal(), self._on_note_saved)

    def _open_edit_modal(self) -> None:
        if self._selected_id is None:
            return
        if self._view == _VIEW_FINDINGS:
            f = self._api.knowledge.get_finding(self._selected_id)
            if f is None:
                return
            self.app.push_screen(
                FindingEditModal(existing=f, forwarders=self._api.forwarders),
                self._on_finding_saved,
            )
        else:
            n = self._api.knowledge.get_note(self._selected_id)
            if n is None:
                return
            self.app.push_screen(
                NoteEditModal(existing=n), self._on_note_saved,
            )

    def _on_finding_saved(self, finding: Optional["Finding"]) -> None:
        if finding is None:
            return
        if self._api.knowledge.get_finding(finding.id) is None:
            self._api.knowledge.add_finding(finding)
        else:
            # The modal mutates the existing object in place; just bump
            # ``updated_at`` so the UI ordering reflects the change.
            finding.updated_at = time.time()
        self._mark_dirty()
        self._selected_id = finding.id
        self.refresh_table()

    def _on_note_saved(self, note: Optional["Note"]) -> None:
        if note is None:
            return
        if self._api.knowledge.get_note(note.id) is None:
            self._api.knowledge.add_note(note)
        else:
            note.updated_at = time.time()
        self._mark_dirty()
        self._selected_id = note.id
        self.refresh_table()

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def _confirm_delete(self) -> None:
        if self._selected_id is None:
            return
        label = "finding" if self._view == _VIEW_FINDINGS else "note"
        self.app.push_screen(
            ConfirmModal(
                title=f"Delete {label}",
                body=f"Permanently delete this {label}?",
                confirm_label="Delete",
                confirm_variant="error",
            ),
            self._on_delete_confirmed,
        )

    def _on_delete_confirmed(self, confirmed: bool) -> None:
        if not confirmed or self._selected_id is None:
            return
        if self._view == _VIEW_FINDINGS:
            self._api.knowledge.remove_finding(self._selected_id)
        else:
            self._api.knowledge.remove_note(self._selected_id)
        self._selected_id = None
        self._mark_dirty()
        self.refresh_table()

    # ------------------------------------------------------------------
    # Dirty flag (signals the app to mark the project dirty)
    # ------------------------------------------------------------------

    def _mark_dirty(self) -> None:
        try:
            self.app.mark_dirty()  # type: ignore[attr-defined]
        except Exception:
            pass
