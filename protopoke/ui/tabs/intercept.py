"""InterceptTab — Burp-style frame interception queue + rules."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, TextArea, Button, Label, Static, Switch
from textual.containers import Horizontal, Vertical
from textual.message import Message

from ...models import InterceptedUnit, Direction
from ...rules.rule import InterceptRule, ReplaceRule, RuleAction
from ..widgets.rule_table import RuleTable
from ..modals.add_rule import AddInterceptRuleModal, AddReplaceRuleModal


class InterceptTab(Widget):
    """
    Tab 3 — Interception queue, hex editor, and auto-forward / replace rules.

    Layout:
      ┌──────────────────────────────────────────────────┐
      │ Top bar: Enable toggle, direction filter, count  │
      ├──────────────────────────────────────────────────┤
      │ Queue (DataTable of pending intercepted units)   │  ~30%
      ├──────────────────────────────────────────────────┤
      │ [Forward] [Drop] [Modify+Forward] [Forward All]  │
      ├──────────────────────────────────────────────────┤
      │ Hex editor (editable TextArea)                   │  ~20%
      ├──────────────────────────────────────────────────┤
      │ Intercept Rules header + RuleTable               │  ~25%
      ├──────────────────────────────────────────────────┤
      │ Replace Rules header + RuleTable                 │  ~25%
      └──────────────────────────────────────────────────┘
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
        height: 30%;
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
        margin: 1 0;
        background: $surface-darken-1;
    }
    InterceptTab .action-bar Button {
        margin-right: 1;
    }
    InterceptTab #hex-editor-pane {
        height: 20%;
    }
    InterceptTab TextArea {
        height: 1fr;
    }
    InterceptTab #intercept-rules-pane {
        height: 1fr;
    }
    InterceptTab #replace-rules-pane {
        height: 1fr;
    }
    InterceptTab RuleTable {
        height: 1fr;
    }
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._units: dict[str, InterceptedUnit] = {}
        self._selected_unit_id: str | None = None

    def compose(self) -> ComposeResult:
        # Top control bar
        with Horizontal(classes="top-bar"):
            yield Label("Intercept:")
            yield Switch(id="intercept-toggle", value=False)
            yield Label("Direction:")
            yield Button("Both",  id="dir-both", variant="default", compact=True)
            yield Button("→ C→S", id="dir-c2s",  variant="default", compact=True)
            yield Button("← S→C", id="dir-s2c",  variant="default", compact=True)
            yield Label("", id="pending-label")

        # Queue
        with Vertical(id="queue-pane"):
            yield Static("  Intercept Queue", classes="pane-header")
            yield DataTable(id="queue-table", cursor_type="row")

        # Action bar
        with Horizontal(classes="action-bar"):
            yield Button("▶ Forward",        variant="success", id="btn-forward",    compact=True)
            yield Button("✖ Drop",           variant="error",   id="btn-drop",       compact=True)
            yield Button("✎ Modify+Forward", variant="warning", id="btn-modify",     compact=True)
            yield Button("▶▶ Forward All",                      id="btn-forward-all", compact=True)

        # Hex editor
        with Vertical(id="hex-editor-pane"):
            yield Static(
                "  Edit (hex pairs, space-separated) — modify before forwarding",
                classes="pane-header",
            )
            yield TextArea(id="hex-editor", language=None, theme="monokai")

        # Intercept rules
        with Vertical(id="intercept-rules-pane"):
            yield Static(
                "  Intercept Rules  [first match wins · no rules → intercept all]",
                classes="pane-header",
            )
            yield RuleTable(
                columns=[
                    ("enabled", "On"),
                    ("label",   "Label"),
                    ("action",  "Action"),
                    ("pattern", "Pattern"),
                    ("dir",     "Direction"),
                ],
                row_factory=self._intercept_rule_row,
                on_add=self._add_intercept_rule,
                on_remove=self._remove_intercept_rule,
                on_move_up=self._move_intercept_rule_up,
                on_move_down=self._move_intercept_rule_down,
                id="intercept-rules",
            )

        # Replace rules
        with Vertical(id="replace-rules-pane"):
            yield Static(
                "  Replace Rules  [applied in order before intercept/forward]",
                classes="pane-header",
            )
            yield RuleTable(
                columns=[
                    ("enabled",  "On"),
                    ("label",    "Label"),
                    ("pattern",  "Pattern"),
                    ("replace",  "→ Replacement"),
                    ("dir",      "Direction"),
                ],
                row_factory=self._replace_rule_row,
                on_add=self._add_replace_rule,
                on_remove=self._remove_replace_rule,
                on_move_up=self._move_replace_rule_up,
                on_move_down=self._move_replace_rule_down,
                id="replace-rules",
            )

    def on_mount(self) -> None:
        dt = self.query_one("#queue-table", DataTable)
        dt.add_column("Unit ID",  key="id")
        dt.add_column("Session",  key="session")
        dt.add_column("Dir",      key="dir")
        dt.add_column("Len",      key="len")
        dt.add_column("Preview",  key="preview")

    # ------------------------------------------------------------------
    # Queue management (called by the app)
    # ------------------------------------------------------------------

    def add_unit(self, unit: InterceptedUnit) -> None:
        self._units[unit.id] = unit
        dt = self.query_one("#queue-table", DataTable)
        direction = "→" if unit.frame.direction is Direction.CLIENT_TO_SERVER else "←"
        data = unit.effective_bytes()
        preview = data[:24].hex()
        if len(data) > 24:
            preview += "…"
        dt.add_row(
            unit.id[:8],
            unit.frame.session_id[:8],
            direction,
            str(len(data)),
            preview,
            key=unit.id,
        )
        self._refresh_pending_label()

    def remove_unit(self, unit_id: str) -> None:
        self._units.pop(unit_id, None)
        dt = self.query_one("#queue-table", DataTable)
        try:
            dt.remove_row(unit_id)
        except Exception:
            pass
        if self._selected_unit_id == unit_id:
            self._selected_unit_id = None
            self.query_one("#hex-editor", TextArea).load_text("")
        self._refresh_pending_label()

    def _refresh_pending_label(self) -> None:
        self.query_one("#pending-label", Label).update(
            f"  {len(self._units)} pending"
        )

    # ------------------------------------------------------------------
    # Intercept rule helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _intercept_rule_row(rule: InterceptRule) -> tuple:
        enabled   = "✓" if rule.enabled else "✗"
        action    = rule.action.value
        direction = rule.direction.value if rule.direction else "both"
        pattern   = rule.pattern_str or "(any)"
        return (enabled, rule.label, action, pattern, direction)

    def refresh_intercept_rules(self, rules: list[InterceptRule]) -> None:
        self.query_one("#intercept-rules", RuleTable).refresh_rules(rules)

    async def _add_intercept_rule(self) -> None:
        def on_result(rule: InterceptRule | None) -> None:
            if rule is None:
                return
            self.app.api.add_intercept_rule(rule)
            self.refresh_intercept_rules(self.app.api.list_intercept_rules())

        await self.app.push_screen_wait(AddInterceptRuleModal(), callback=on_result)

    def _remove_intercept_rule(self, rule_id: str) -> None:
        self.app.api.remove_intercept_rule(rule_id)
        self.refresh_intercept_rules(self.app.api.list_intercept_rules())

    def _move_intercept_rule_up(self, rule_id: str) -> None:
        rules = self.app.api.intercept_filter.rules
        idx = next((i for i, r in enumerate(rules) if r.id == rule_id), -1)
        if idx > 0:
            self.app.api.intercept_filter.move_rule(rule_id, idx - 1)
            self.refresh_intercept_rules(self.app.api.list_intercept_rules())

    def _move_intercept_rule_down(self, rule_id: str) -> None:
        rules = self.app.api.intercept_filter.rules
        idx = next((i for i, r in enumerate(rules) if r.id == rule_id), -1)
        if 0 <= idx < len(rules) - 1:
            self.app.api.intercept_filter.move_rule(rule_id, idx + 1)
            self.refresh_intercept_rules(self.app.api.list_intercept_rules())

    # ------------------------------------------------------------------
    # Replace rule helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _replace_rule_row(rule: ReplaceRule) -> tuple:
        enabled   = "✓" if rule.enabled else "✗"
        direction = rule.direction.value if rule.direction else "both"
        repl_hex  = rule.replacement.hex()
        if len(repl_hex) > 20:
            repl_hex = repl_hex[:20] + "…"
        pattern = rule.pattern_str or "(empty)"
        return (enabled, rule.label, pattern, repl_hex, direction)

    def refresh_replace_rules(self, rules: list[ReplaceRule]) -> None:
        self.query_one("#replace-rules", RuleTable).refresh_rules(rules)

    async def _add_replace_rule(self) -> None:
        def on_result(rule: ReplaceRule | None) -> None:
            if rule is None:
                return
            self.app.api.add_replace_rule(rule)
            self.refresh_replace_rules(self.app.api.list_replace_rules())

        await self.app.push_screen_wait(AddReplaceRuleModal(), callback=on_result)

    def _remove_replace_rule(self, rule_id: str) -> None:
        self.app.api.remove_replace_rule(rule_id)
        self.refresh_replace_rules(self.app.api.list_replace_rules())

    def _move_replace_rule_up(self, rule_id: str) -> None:
        rules = self.app.api.rules_engine.rules
        idx = next((i for i, r in enumerate(rules) if r.id == rule_id), -1)
        if idx > 0:
            self.app.api.rules_engine.move_rule(rule_id, idx - 1)
            self.refresh_replace_rules(self.app.api.list_replace_rules())

    def _move_replace_rule_down(self, rule_id: str) -> None:
        rules = self.app.api.rules_engine.rules
        idx = next((i for i, r in enumerate(rules) if r.id == rule_id), -1)
        if 0 <= idx < len(rules) - 1:
            self.app.api.rules_engine.move_rule(rule_id, idx + 1)
            self.refresh_replace_rules(self.app.api.list_replace_rules())

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
            data = unit.effective_bytes()
            pairs = [data.hex()[i:i+2] for i in range(0, len(data.hex()), 2)]
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
            for uid in list(self._units):
                self.remove_unit(uid)
            self.notify(f"Forwarded {count} frames.")

    def _do_forward(self) -> None:
        uid = self._selected_unit_id
        if not uid:
            self.notify("Select a frame to forward.", severity="warning")
            return
        if self.app.api.forward(uid):
            self.remove_unit(uid)
        else:
            self.notify("Forward failed — unit may have already been processed.", severity="error")

    def _do_drop(self) -> None:
        uid = self._selected_unit_id
        if not uid:
            self.notify("Select a frame to drop.", severity="warning")
            return
        if self.app.api.drop(uid):
            self.remove_unit(uid)
        else:
            self.notify("Drop failed — unit may have already been processed.", severity="error")

    def _do_modify_and_forward(self) -> None:
        uid = self._selected_unit_id
        if not uid:
            self.notify("Select a frame to modify.", severity="warning")
            return
        hex_text = self.query_one("#hex-editor", TextArea).text
        hex_clean = hex_text.replace(" ", "").replace("\n", "").strip()
        try:
            new_data = bytes.fromhex(hex_clean)
        except ValueError as exc:
            self.notify(f"Invalid hex: {exc}", severity="error")
            return
        if self.app.api.modify_and_forward(uid, new_data):
            self.remove_unit(uid)
        else:
            self.notify("Modify failed — unit may have already been processed.", severity="error")
