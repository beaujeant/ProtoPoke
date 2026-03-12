"""RuleTable widget — an editable ordered list of rules (replace or intercept)."""

from __future__ import annotations

from typing import Callable, Generic, TypeVar

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, Button
from textual.containers import Horizontal, Vertical

R = TypeVar("R")


class RuleTable(Widget, Generic[R]):
    """
    A DataTable plus Add/Remove/Move buttons for a list of rules.

    The caller provides:
      - ``columns``: list of (key, label) pairs for the table.
      - ``row_factory``: callable that converts a rule object to a tuple of
        display strings matching the columns.
      - ``on_add``: async callable invoked when the user presses [+].
      - ``on_remove``: called with the selected rule's ID when [-] is pressed.
      - ``on_move_up`` / ``on_move_down``: called with rule ID.

    The widget does *not* own the underlying rule list — it is a pure display
    layer.  Call ``refresh_rules(rules)`` to repopulate after any mutation.
    """

    DEFAULT_CSS = """
    RuleTable {
        height: auto;
    }
    RuleTable DataTable {
        height: 1fr;
        min-height: 4;
    }
    RuleTable .rule-buttons {
        height: 3;
        margin: 1 0;
    }
    RuleTable Button {
        min-width: 6;
        margin-right: 1;
        padding: 0 1;
    }
    """

    def __init__(
        self,
        columns: list[tuple[str, str]],
        row_factory: Callable,
        on_add: Callable,
        on_remove: Callable,
        on_move_up: Callable | None = None,
        on_move_down: Callable | None = None,
        *,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self._columns = columns
        self._row_factory = row_factory
        self._on_add = on_add
        self._on_remove = on_remove
        self._on_move_up = on_move_up
        self._on_move_down = on_move_down
        self._rules: list[R] = []

    def compose(self) -> ComposeResult:
        with Vertical():
            yield DataTable(id="rule-dt", cursor_type="row")
            with Horizontal(classes="rule-buttons"):
                yield Button("[+] Add", variant="success", id="btn-add")
                yield Button("[-] Remove", variant="error", id="btn-remove")
                if self._on_move_up:
                    yield Button("[↑] Up", id="btn-up")
                if self._on_move_down:
                    yield Button("[↓] Down", id="btn-down")

    def on_mount(self) -> None:
        dt = self.query_one("#rule-dt", DataTable)
        for key, label in self._columns:
            dt.add_column(label, key=key)

    def refresh_rules(self, rules: list[R]) -> None:
        """Repopulate the table from *rules*."""
        self._rules = list(rules)
        dt = self.query_one("#rule-dt", DataTable)
        dt.clear()
        for rule in self._rules:
            dt.add_row(*self._row_factory(rule))

    def _selected_rule_id(self) -> str | None:
        dt = self.query_one("#rule-dt", DataTable)
        if dt.cursor_row < 0 or dt.cursor_row >= len(self._rules):
            return None
        return getattr(self._rules[dt.cursor_row], "id", None)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "btn-add":
            await self._on_add()
        elif event.button.id == "btn-remove":
            rid = self._selected_rule_id()
            if rid:
                self._on_remove(rid)
        elif event.button.id == "btn-up" and self._on_move_up:
            rid = self._selected_rule_id()
            if rid:
                self._on_move_up(rid)
        elif event.button.id == "btn-down" and self._on_move_down:
            rid = self._selected_rule_id()
            if rid:
                self._on_move_down(rid)
