"""FrameFilterModal — manage the list of frame display filters."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Label
from textual.containers import Horizontal, Vertical

from ...filters.frame_filter import FrameDisplayFilter
from ..widgets.rule_table import RuleTable
from .add_frame_filter import AddFrameFilterModal


class FrameFilterModal(ModalScreen[list[FrameDisplayFilter]]):
    """
    Modal for managing the frame display filter list.

    Shows all current filters in a :class:`RuleTable` with Add / Remove /
    Toggle / Edit actions.  Dismisses with the updated filter list when the
    user closes the modal.
    """

    DEFAULT_CSS = """
    FrameFilterModal > Vertical {
        width: 90;
        height: 60vh;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    FrameFilterModal RuleTable {
        height: 1fr;
    }
    FrameFilterModal RuleTable DataTable {
        height: 1fr;
    }
    FrameFilterModal .buttons {
        height: 3;
        margin-top: 1;
        align: right middle;
    }
    FrameFilterModal Button {
        margin-left: 1;
        padding: 0 0;
    }
    """

    _COLUMNS: list[tuple[str, str]] = [
        ("enabled", "En"),
        ("mode",    "Mode"),
        ("label",   "Label"),
        ("pattern", "Pattern"),
    ]

    def __init__(self, filters: list[FrameDisplayFilter]) -> None:
        super().__init__()
        self._filters: list[FrameDisplayFilter] = list(filters)

    @staticmethod
    def _row_factory(f: FrameDisplayFilter) -> tuple[str, str, str, str]:
        return (
            "✓" if f.enabled else "✗",
            f.mode.upper(),
            f.label,
            f.pattern_str or "(match all)",
        )

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Frame Filters", classes="modal-title")
            yield RuleTable(
                columns=self._COLUMNS,
                row_factory=self._row_factory,
                on_add=self._on_add,
                on_remove=self._on_remove,
                on_toggle=self._on_toggle,
                on_edit=self._on_edit,
                id="filter-rule-table",
            )
            with Horizontal(classes="buttons"):
                yield Button("Close", variant="primary", id="btn-close")

    def on_mount(self) -> None:
        self.query_one("#filter-rule-table", RuleTable).refresh_rules(self._filters)

    def _refresh(self) -> None:
        self.query_one("#filter-rule-table", RuleTable).refresh_rules(self._filters)

    async def _on_add(self) -> None:
        def _done(result: FrameDisplayFilter | None) -> None:
            if result is not None:
                self._filters.append(result)
                self._refresh()
        self.app.push_screen(AddFrameFilterModal(), _done)

    def _on_remove(self, rule_id: str) -> None:
        self._filters = [f for f in self._filters if f.id != rule_id]
        self._refresh()

    def _on_toggle(self, rule_id: str) -> None:
        for f in self._filters:
            if f.id == rule_id:
                f.enabled = not f.enabled
                break
        self._refresh()

    async def _on_edit(self, rule: FrameDisplayFilter) -> None:
        def _done(result: FrameDisplayFilter | None) -> None:
            if result is not None:
                self._refresh()
        self.app.push_screen(AddFrameFilterModal(existing=rule), _done)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close":
            self.dismiss(list(self._filters))
