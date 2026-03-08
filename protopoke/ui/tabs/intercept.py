"""InterceptTab — Burp-style frame interception queue + auto-forward rules."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, TextArea, Button, Label, Static, Switch
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.message import Message

from ...models import InterceptedUnit, Direction
from ...rules.rule import InterceptRule, RuleAction
from ..widgets.rule_table import RuleTable


class InterceptTab(Widget):
    """
    Tab 3 — Interception queue and auto-forward rules.

    Layout:
      ┌──────────────────────────────────────────┐
      │ Controls: Enable/Disable, direction filter│  top bar
      ├──────────────────────────────────────────┤
      │ Queue (DataTable of pending units)        │  ~40%
      ├──────────────────────────────────────────┤
      │ [Forward] [Drop] [Modify+Forward]         │  action bar
      ├──────────────────────────────────────────┤
      │ Hex editor (TextArea — editable)          │  ~30%
      ├──────────────────────────────────────────┤
      │ Auto-forward rules (RuleTable)            │  ~30%
      └──────────────────────────────────────────┘
    """

    DEFAULT_CSS = """
    InterceptTab {
        layout: vertical;
    }
    InterceptTab .top-bar {
        height: 3;
        background: $surface-darken-1;
        align: left middle;
        padding: 0 1;
    }
    InterceptTab .top-bar Label {
        margin-right: 1;
    }
    InterceptTab .top-bar Switch {
        margin-right: 2;
    }
    InterceptTab #queue-pane {
        height: 35%;
        border-bottom: solid $primary-darken-2;
    }
    InterceptTab .pane-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
        text-style: bold;
    }
    InterceptTab DataTable {
        height: 1fr;
    }
    InterceptTab .action-bar {
        height: 3;
        align: left middle;
        padding: 0 1;
        background: $surface-darken-1;
    }
    InterceptTab .action-bar Button {
        margin-right: 1;
    }
    InterceptTab #hex-editor-pane {
        height: 25%;
        border-bottom: solid $primary-darken-2;
    }
    InterceptTab TextArea {
        height: 1fr;
    }
    InterceptTab #rules-pane {
        height: 1fr;
    }
    InterceptTab RuleTable {
        height: 1fr;
    }
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._units: dict[str, InterceptedUnit] = {}  # unit_id → unit
        self._selected_unit_id: str | None = None

    def compose(self) -> ComposeResult:
        # Top control bar
        with Horizontal(classes="top-bar"):
            yield Label("Intercept:")
            yield Switch(id="intercept-toggle", value=False)
            yield Label("Direction:")
            yield Button("Both", id="dir-both", variant="default")
            yield Button("→ C→S", id="dir-c2s", variant="default")
            yield Button("← S→C", id="dir-s2c", variant="default")
            yield Label("", id="pending-label")

        # Queue pane
        with Vertical(id="queue-pane"):
            yield Static("  Intercept Queue", classes="pane-header")
            yield DataTable(id="queue-table", cursor_type="row")

        # Action bar
        with Horizontal(classes="action-bar"):
            yield Button("▶ Forward", variant="success", id="btn-forward")
            yield Button("✖ Drop", variant="error", id="btn-drop")
            yield Button("✎ Modify+Forward", variant="warning", id="btn-modify")
            yield Button("▶▶ Forward All", id="btn-forward-all")

        # Hex editor
        with Vertical(id="hex-editor-pane"):
            yield Static("  Edit Frame (hex — modify before forwarding)", classes="pane-header")
            yield TextArea(
                id="hex-editor",
                language=None,
                theme="monokai",
            )

        # Auto-forward rules
        with Vertical(id="rules-pane"):
            yield Static("  Auto-Forward Rules  (first match wins; no rules → intercept all)", classes="pane-header")
            yield RuleTable(
                columns=[
                    ("enabled", "On"),
                    ("label", "Label"),
                    ("action", "Action"),
                    ("pattern", "Pattern"),
                    ("direction", "Direction"),
                ],
                row_factory=self._rule_row,
                on_add=self._add_rule,
                on_remove=self._remove_rule,
                on_move_up=self._move_rule_up,
                on_move_down=self._move_rule_down,
                id="intercept-rules",
            )

    def on_mount(self) -> None:
        dt = self.query_one("#queue-table", DataTable)
        dt.add_column("Unit ID", key="id")
        dt.add_column("Session", key="session")
        dt.add_column("Dir", key="dir")
        dt.add_column("Len", key="len")
        dt.add_column("Preview", key="preview")

    # ------------------------------------------------------------------
    # Queue management
    # ------------------------------------------------------------------

    def add_unit(self, unit: InterceptedUnit) -> None:
        """Add a newly intercepted unit to the queue."""
        self._units[unit.id] = unit
        dt = self.query_one("#queue-table", DataTable)
        direction = "→" if unit.frame.direction is Direction.CLIENT_TO_SERVER else "←"
        preview = unit.effective_bytes()[:24].hex()
        if len(unit.effective_bytes()) > 24:
            preview += "…"
        dt.add_row(
            unit.id[:8],
            unit.frame.session_id[:8],
            direction,
            str(len(unit.effective_bytes())),
            preview,
            key=unit.id,
        )
        self._refresh_pending_label()

    def remove_unit(self, unit_id: str) -> None:
        """Remove a unit from the display queue."""
        self._units.pop(unit_id, None)
        dt = self.query_one("#queue-table", DataTable)
        try:
            dt.remove_row(unit_id)
        except Exception:
            pass
        if self._selected_unit_id == unit_id:
            self._selected_unit_id = None
            self.query_one("#hex-editor", TextArea).text = ""
        self._refresh_pending_label()

    def _refresh_pending_label(self) -> None:
        count = len(self._units)
        label = self.query_one("#pending-label", Label)
        label.update(f"  {count} pending")

    # ------------------------------------------------------------------
    # Rules display
    # ------------------------------------------------------------------

    @staticmethod
    def _rule_row(rule: InterceptRule) -> tuple:
        enabled = "✓" if rule.enabled else "✗"
        action  = rule.action.value
        direction = rule.direction.value if rule.direction else "both"
        return (enabled, rule.label, action, rule.pattern_str or "(any)", direction)

    def refresh_rules(self, rules: list[InterceptRule]) -> None:
        self.query_one("#intercept-rules", RuleTable).refresh_rules(rules)

    async def _add_rule(self) -> None:
        """Open a simple inline prompt to add a new intercept rule."""
        self.notify("Use the rule editor (coming soon). For now, add rules via the API.", severity="information")

    def _remove_rule(self, rule_id: str) -> None:
        self.app.api.remove_intercept_rule(rule_id)
        self.refresh_rules(self.app.api.list_intercept_rules())

    def _move_rule_up(self, rule_id: str) -> None:
        self.app.api.intercept_filter.move_rule(rule_id, -1)
        self.refresh_rules(self.app.api.list_intercept_rules())

    def _move_rule_down(self, rule_id: str) -> None:
        self.app.api.intercept_filter.move_rule(rule_id, 1)
        self.refresh_rules(self.app.api.list_intercept_rules())

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id == "intercept-toggle":
            self.app.api.intercept_enabled = event.value
            state = "enabled" if event.value else "disabled"
            self.notify(f"Interception {state}.")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "queue-table":
            return
        unit_id = str(event.row_key.value)
        unit = self._units.get(unit_id)
        if unit:
            self._selected_unit_id = unit_id
            # Populate the hex editor with the effective bytes
            hex_text = unit.effective_bytes().hex()
            # Format as spaced pairs for readability
            pairs = [hex_text[i:i+2] for i in range(0, len(hex_text), 2)]
            self.query_one("#hex-editor", TextArea).load_text(" ".join(pairs))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id

        if bid == "dir-both":
            self.app.api.intercept_direction_filter = None
        elif bid == "dir-c2s":
            self.app.api.intercept_direction_filter = Direction.CLIENT_TO_SERVER
        elif bid == "dir-s2c":
            self.app.api.intercept_direction_filter = Direction.SERVER_TO_CLIENT

        elif bid == "btn-forward":
            self._do_forward()
        elif bid == "btn-drop":
            self._do_drop()
        elif bid == "btn-modify":
            self._do_modify_and_forward()
        elif bid == "btn-forward-all":
            count = self.app.api.forward_all()
            # Clear all units from display
            for uid in list(self._units):
                self.remove_unit(uid)
            self.notify(f"Forwarded {count} frames.")

    def _do_forward(self) -> None:
        uid = self._selected_unit_id
        if not uid:
            self.notify("Select a frame to forward.", severity="warning")
            return
        ok = self.app.api.forward(uid)
        if ok:
            self.remove_unit(uid)
        else:
            self.notify("Forward failed — unit may have already been processed.", severity="error")

    def _do_drop(self) -> None:
        uid = self._selected_unit_id
        if not uid:
            self.notify("Select a frame to drop.", severity="warning")
            return
        ok = self.app.api.drop(uid)
        if ok:
            self.remove_unit(uid)
        else:
            self.notify("Drop failed — unit may have already been processed.", severity="error")

    def _do_modify_and_forward(self) -> None:
        uid = self._selected_unit_id
        if not uid:
            self.notify("Select a frame to modify.", severity="warning")
            return
        hex_text = self.query_one("#hex-editor", TextArea).text
        # Strip whitespace / newlines
        hex_clean = hex_text.replace(" ", "").replace("\n", "").strip()
        try:
            new_data = bytes.fromhex(hex_clean)
        except ValueError as exc:
            self.notify(f"Invalid hex: {exc}", severity="error")
            return
        ok = self.app.api.modify_and_forward(uid, new_data)
        if ok:
            self.remove_unit(uid)
        else:
            self.notify("Modify failed — unit may have already been processed.", severity="error")
