"""Add-rule modals: AddReplaceRuleModal and AddInterceptRuleModal."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Switch, Static
from textual.containers import Horizontal, Vertical

from ...rules.rule import (
    ReplaceRule,
    InterceptRule,
    RuleAction,
    compile_binary_pattern,
    PatternError,
)
from ...models import Direction


_DIRECTION_OPTIONS = [
    ("Both directions", ""),
    ("Client → Server", "client_to_server"),
    ("Server → Client", "server_to_client"),
]

_ACTION_OPTIONS = [
    ("Intercept (hold for review)", "intercept"),
    ("Forward (bypass queue)", "forward"),
]


# ---------------------------------------------------------------------------
# AddReplaceRuleModal
# ---------------------------------------------------------------------------

class AddReplaceRuleModal(ModalScreen[ReplaceRule | None]):
    """
    Modal form to create a new ReplaceRule.

    Dismisses with the new rule, or None if cancelled.
    """

    DEFAULT_CSS = """
    AddReplaceRuleModal > Vertical {
        width: 72;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    AddReplaceRuleModal Label {
        margin-top: 1;
    }
    AddReplaceRuleModal Input {
        margin-bottom: 0;
    }
    AddReplaceRuleModal .hint {
        color: $text-muted;
        margin-bottom: 0;
    }
    AddReplaceRuleModal .tls-row {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    AddReplaceRuleModal .buttons {
        height: 3;
        margin-top: 2;
        align: right middle;
    }
    AddReplaceRuleModal Button {
        margin-left: 1;
    }
    AddReplaceRuleModal #validation-msg {
        color: $error;
        height: 1;
    }
    """

    def __init__(self, existing: ReplaceRule | None = None) -> None:
        super().__init__()
        self._existing = existing

    def compose(self) -> ComposeResult:
        ex = self._existing
        with Vertical():
            yield Label("Replace Rule", classes="modal-title")

            yield Label("Label:")
            yield Input(value=ex.label if ex else "", placeholder="My replace rule", id="r-label")

            yield Label("Pattern (hex binary syntax):")
            yield Input(
                value=ex.pattern_str if ex else "",
                placeholder='e.g.  01 00 ??  or  FF [03-09]  or  (01|02) 00',
                id="r-pattern",
            )
            yield Static(
                "Tokens: AB=literal  ??=any byte  [AB-CD]=range  .{N}=N bytes  (AB|CD)=alt",
                classes="hint",
            )

            yield Label("Replacement (hex bytes, e.g. DEADBEEF):")
            yield Input(
                value=ex.replacement.hex() if ex else "",
                placeholder="00 or deadbeef or 0d0a",
                id="r-replacement",
            )

            yield Label("Direction:")
            direction_val = ex.direction.value if (ex and ex.direction) else ""
            yield Select(
                [(lbl, val) for lbl, val in _DIRECTION_OPTIONS],
                value=direction_val,
                id="r-direction",
            )

            with Horizontal(classes="tls-row"):
                yield Label("Enabled: ")
                yield Switch(value=ex.enabled if ex else True, id="r-enabled")

            yield Static("", id="validation-msg")

            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Save", variant="primary", id="btn-save")

    def on_mount(self) -> None:
        self.query_one("#r-label", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
            return
        self._try_save()

    def on_input_submitted(self, _: Input.Submitted) -> None:
        self._try_save()

    def _try_save(self) -> None:
        label = self.query_one("#r-label", Input).value.strip() or "Rule"
        pattern = self.query_one("#r-pattern", Input).value.strip()
        replacement_raw = self.query_one("#r-replacement", Input).value.replace(" ", "").strip()
        dir_val = str(self.query_one("#r-direction", Select).value)
        enabled = self.query_one("#r-enabled", Switch).value
        msg_widget = self.query_one("#validation-msg", Static)

        # Validate pattern
        if pattern:
            try:
                compile_binary_pattern(pattern)
            except PatternError as exc:
                msg_widget.update(f"Pattern error: {exc}")
                return

        # Validate replacement
        try:
            replacement = bytes.fromhex(replacement_raw) if replacement_raw else b""
        except ValueError:
            msg_widget.update("Replacement must be valid hex (spaces are stripped).")
            return

        direction: Direction | None = None
        if dir_val:
            try:
                direction = Direction(dir_val)
            except ValueError:
                pass

        msg_widget.update("")

        if self._existing:
            # Mutate and return the same object
            rule = self._existing
            rule.label = label
            rule.pattern_str = pattern
            rule.replacement = replacement
            rule.direction = direction
            rule.enabled = enabled
            # Recompile
            from ...rules.rule import compile_binary_pattern as _compile
            rule.compiled = _compile(pattern) if pattern else None
        else:
            rule = ReplaceRule.create(label, pattern, replacement, direction=direction, enabled=enabled)

        self.dismiss(rule)


# ---------------------------------------------------------------------------
# AddInterceptRuleModal
# ---------------------------------------------------------------------------

class AddInterceptRuleModal(ModalScreen[InterceptRule | None]):
    """
    Modal form to create or edit an InterceptRule.

    Dismisses with the new/updated rule, or None if cancelled.
    """

    DEFAULT_CSS = """
    AddInterceptRuleModal > Vertical {
        width: 72;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    AddInterceptRuleModal Label {
        margin-top: 1;
    }
    AddInterceptRuleModal Input {
        margin-bottom: 0;
    }
    AddInterceptRuleModal .hint {
        color: $text-muted;
    }
    AddInterceptRuleModal .tls-row {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    AddInterceptRuleModal .buttons {
        height: 3;
        margin-top: 2;
        align: right middle;
    }
    AddInterceptRuleModal Button {
        margin-left: 1;
    }
    AddInterceptRuleModal #validation-msg {
        color: $error;
        height: 1;
    }
    """

    def __init__(self, existing: InterceptRule | None = None) -> None:
        super().__init__()
        self._existing = existing

    def compose(self) -> ComposeResult:
        ex = self._existing
        with Vertical():
            yield Label("Intercept Rule", classes="modal-title")

            yield Label("Label:")
            yield Input(value=ex.label if ex else "", placeholder="My intercept rule", id="i-label")

            yield Label("Pattern (hex binary syntax, empty = match all):")
            yield Input(
                value=ex.pattern_str if ex else "",
                placeholder='e.g.  01 00 ??  or leave blank to match everything',
                id="i-pattern",
            )
            yield Static(
                "Tokens: AB=literal  ??=any byte  [AB-CD]=range  .{N}=N bytes  (AB|CD)=alt",
                classes="hint",
            )

            yield Label("Action when matched:")
            action_val = ex.action.value if ex else "intercept"
            yield Select(
                [(lbl, val) for lbl, val in _ACTION_OPTIONS],
                value=action_val,
                id="i-action",
            )

            yield Label("Direction:")
            direction_val = ex.direction.value if (ex and ex.direction) else ""
            yield Select(
                [(lbl, val) for lbl, val in _DIRECTION_OPTIONS],
                value=direction_val,
                id="i-direction",
            )

            with Horizontal(classes="tls-row"):
                yield Label("Enabled: ")
                yield Switch(value=ex.enabled if ex else True, id="i-enabled")

            yield Static("", id="validation-msg")

            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Save", variant="primary", id="btn-save")

    def on_mount(self) -> None:
        self.query_one("#i-label", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
            return
        self._try_save()

    def on_input_submitted(self, _: Input.Submitted) -> None:
        self._try_save()

    def _try_save(self) -> None:
        label = self.query_one("#i-label", Input).value.strip() or "Rule"
        pattern = self.query_one("#i-pattern", Input).value.strip()
        action_val = str(self.query_one("#i-action", Select).value)
        dir_val = str(self.query_one("#i-direction", Select).value)
        enabled = self.query_one("#i-enabled", Switch).value
        msg_widget = self.query_one("#validation-msg", Static)

        if pattern:
            try:
                compile_binary_pattern(pattern)
            except PatternError as exc:
                msg_widget.update(f"Pattern error: {exc}")
                return

        try:
            action = RuleAction(action_val)
        except ValueError:
            action = RuleAction.INTERCEPT

        direction: Direction | None = None
        if dir_val:
            try:
                direction = Direction(dir_val)
            except ValueError:
                pass

        msg_widget.update("")

        if self._existing:
            rule = self._existing
            rule.label = label
            rule.pattern_str = pattern
            rule.action = action
            rule.direction = direction
            rule.enabled = enabled
            from ...rules.rule import compile_binary_pattern as _compile
            rule.compiled = _compile(pattern) if pattern else None
        else:
            rule = InterceptRule.create(label, pattern, action, direction=direction, enabled=enabled)

        self.dismiss(rule)
