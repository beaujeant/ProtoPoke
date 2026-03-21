"""Add-rule modals: AddReplaceRuleModal and AddInterceptRuleModal."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Switch, Static, Checkbox
from textual.containers import Horizontal, Vertical

from ...rules.rule import (
    ReplaceRule,
    InterceptRule,
    RuleAction,
    compile_binary_pattern,
    compile_regex_pattern,
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

_RULE_TYPE_OPTIONS = [
    ("Binary pattern replacement", "binary"),
    ("Regex replacement", "regex"),
    ("Custom script", "script"),
]


# ---------------------------------------------------------------------------
# AddReplaceRuleModal
# ---------------------------------------------------------------------------

class AddReplaceRuleModal(ModalScreen[ReplaceRule | None]):
    """
    Modal form to create or edit a ReplaceRule.

    Supports three rule types (binary pattern, regex, custom script) with
    scope checkboxes controlling which pipeline stages apply the rule.

    Dismisses with the rule object, or None if cancelled.
    """

    DEFAULT_CSS = """
    AddReplaceRuleModal > Vertical {
        width: 80;
        height: auto;
        max-height: 90vh;
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
    AddReplaceRuleModal .switch-row {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    AddReplaceRuleModal .scope-row {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    AddReplaceRuleModal .scope-row Checkbox {
        margin-right: 2;
    }
    AddReplaceRuleModal .buttons {
        height: 3;
        margin-top: 2;
        align: right middle;
    }
    AddReplaceRuleModal Button {
        margin-left: 1;
        padding: 0 0;
    }
    AddReplaceRuleModal #validation-msg {
        color: $error;
        height: 1;
    }
    AddReplaceRuleModal .section-divider {
        color: $text-muted;
        margin-top: 1;
        height: 1;
    }
    """

    def __init__(self, existing: ReplaceRule | None = None) -> None:
        super().__init__()
        self._existing = existing

    def compose(self) -> ComposeResult:
        ex = self._existing
        rule_type = ex.rule_type if ex else "binary"

        with Vertical():
            yield Label("Replace Rule", classes="modal-title")

            # ---- Label ----
            yield Label("Label:")
            yield Input(value=ex.label if ex else "", placeholder="My replace rule", id="r-label")

            # ---- Rule type ----
            yield Label("Mechanism:")
            yield Select(
                [(lbl, val) for lbl, val in _RULE_TYPE_OPTIONS],
                value=rule_type,
                id="r-type",
            )

            # ---- Binary fields ----
            with Vertical(id="binary-fields"):
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

            # ---- Regex fields ----
            with Vertical(id="regex-fields"):
                yield Label("Regex pattern (Python bytes regex, e.g. \\x01\\x00.{2}):")
                yield Input(
                    value=ex.regex_pattern if ex else "",
                    placeholder=r"e.g.  \x01\x00.{2}  or  (\xff[\x00-\x09])",
                    id="r-regex-pattern",
                )
                yield Static(
                    "Uses Python bytes regex syntax with \\xNN escapes (re.DOTALL enabled)",
                    classes="hint",
                )
                yield Label("Replacement (\\xNN bytes and \\g<N> backreferences):")
                yield Input(
                    value=ex.regex_replacement if ex else "",
                    placeholder=r"e.g.  \g<1>\x00\xff  or  \x00",
                    id="r-regex-replacement",
                )

            # ---- Script fields ----
            with Vertical(id="script-fields"):
                yield Label("Script path (must export apply(data: bytes) -> bytes):")
                with Horizontal(classes="switch-row"):
                    yield Input(
                        value=ex.script_path if ex else "",
                        placeholder="/path/to/replace_script.py",
                        id="r-script-path",
                    )
                    yield Button("Browse", id="btn-browse-script", compact=True)

            # ---- Direction (common) ----
            yield Static("─" * 60, classes="section-divider")
            yield Label("Direction:")
            direction_val = ex.direction.value if (ex and ex.direction) else ""
            yield Select(
                [(lbl, val) for lbl, val in _DIRECTION_OPTIONS],
                value=direction_val,
                id="r-direction",
            )

            # ---- Enabled toggle ----
            with Horizontal(classes="switch-row"):
                yield Label("Enabled: ")
                yield Switch(value=ex.enabled if ex else True, id="r-enabled")

            # ---- Scope checkboxes ----
            yield Label("Apply in:")
            with Horizontal(classes="scope-row"):
                yield Checkbox(
                    "Intercept (relay)",
                    value=ex.apply_to_intercept if ex else True,
                    id="r-scope-intercept",
                )
                yield Checkbox(
                    "Forge",
                    value=ex.apply_to_forge if ex else True,
                    id="r-scope-forge",
                )
                yield Checkbox(
                    "Sequence",
                    value=ex.apply_to_sequence if ex else True,
                    id="r-scope-sequence",
                )

            yield Static("", id="validation-msg")

            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Save", variant="primary", id="btn-save")

    def on_mount(self) -> None:
        self.query_one("#r-label", Input).focus()
        # Show/hide sections based on current rule type
        rule_type = self._existing.rule_type if self._existing else "binary"
        self._show_type_fields(rule_type)

    def _show_type_fields(self, rule_type: str) -> None:
        """Show/hide field sections based on the selected rule type."""
        self.query_one("#binary-fields").display = (rule_type == "binary")
        self.query_one("#regex-fields").display  = (rule_type == "regex")
        self.query_one("#script-fields").display = (rule_type == "script")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "r-type" and event.value is not Select.BLANK:
            self._show_type_fields(str(event.value))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
            return
        if event.button.id == "btn-browse-script":
            event.stop()
            current = self.query_one("#r-script-path", Input).value.strip() or None
            def _on_pick(path: str | None) -> None:
                if path is not None:
                    self.query_one("#r-script-path", Input).value = path
            self.app.push_screen(
                __import__(
                    "protopoke.ui.modals.file_picker",
                    fromlist=["FilePickerModal"],
                ).FilePickerModal(current),
                _on_pick,
            )
            return
        self._try_save()

    def on_input_submitted(self, _: Input.Submitted) -> None:
        self._try_save()

    def _try_save(self) -> None:
        msg_widget = self.query_one("#validation-msg", Static)

        label    = self.query_one("#r-label", Input).value.strip() or "Rule"
        dir_select_val = self.query_one("#r-direction", Select).value
        enabled  = self.query_one("#r-enabled", Switch).value
        rule_type_val = str(self.query_one("#r-type", Select).value)

        scope_intercept = self.query_one("#r-scope-intercept", Checkbox).value
        scope_forge  = self.query_one("#r-scope-forge",  Checkbox).value
        scope_sequence = self.query_one("#r-scope-sequence", Checkbox).value

        direction: Direction | None = None
        if dir_select_val is not Select.BLANK:
            try:
                direction = Direction(str(dir_select_val))
            except ValueError:
                pass

        # ---- Type-specific validation ----
        if rule_type_val == "binary":
            pattern = self.query_one("#r-pattern", Input).value.strip()
            replacement_raw = self.query_one("#r-replacement", Input).value.replace(" ", "").strip()

            if pattern:
                try:
                    compile_binary_pattern(pattern)
                except PatternError as exc:
                    msg_widget.update(f"Pattern error: {exc}")
                    return

            try:
                replacement = bytes.fromhex(replacement_raw) if replacement_raw else b""
            except ValueError:
                msg_widget.update("Replacement must be valid hex (spaces are stripped).")
                return

            msg_widget.update("")
            if self._existing:
                rule = self._existing
                rule.label      = label
                rule.rule_type  = "binary"
                rule.pattern_str = pattern
                rule.replacement = replacement
                rule.direction  = direction
                rule.enabled    = enabled
                rule.apply_to_intercept = scope_intercept
                rule.apply_to_forge  = scope_forge
                rule.apply_to_sequence = scope_sequence
                rule.compiled = compile_binary_pattern(pattern) if pattern else None
                rule.regex_compiled = None
            else:
                rule = ReplaceRule.create(
                    label, pattern, replacement,
                    direction=direction, enabled=enabled,
                    rule_type="binary",
                    apply_to_intercept=scope_intercept,
                    apply_to_forge=scope_forge,
                    apply_to_sequence=scope_sequence,
                )

        elif rule_type_val == "regex":
            regex_pattern = self.query_one("#r-regex-pattern", Input).value.strip()
            regex_replacement = self.query_one("#r-regex-replacement", Input).value

            if regex_pattern:
                try:
                    compile_regex_pattern(regex_pattern)
                except PatternError as exc:
                    msg_widget.update(f"Regex error: {exc}")
                    return

            msg_widget.update("")
            if self._existing:
                rule = self._existing
                rule.label            = label
                rule.rule_type        = "regex"
                rule.regex_pattern    = regex_pattern
                rule.regex_replacement = regex_replacement
                rule.direction        = direction
                rule.enabled          = enabled
                rule.apply_to_intercept = scope_intercept
                rule.apply_to_forge  = scope_forge
                rule.apply_to_sequence = scope_sequence
                rule.regex_compiled = compile_regex_pattern(regex_pattern) if regex_pattern else None
                rule.compiled = None
            else:
                rule = ReplaceRule.create(
                    label, "", b"",
                    direction=direction, enabled=enabled,
                    rule_type="regex",
                    regex_pattern=regex_pattern,
                    regex_replacement=regex_replacement,
                    apply_to_intercept=scope_intercept,
                    apply_to_forge=scope_forge,
                    apply_to_sequence=scope_sequence,
                )

        elif rule_type_val == "script":
            script_path = self.query_one("#r-script-path", Input).value.strip()
            if not script_path:
                msg_widget.update("Script path is required.")
                return

            msg_widget.update("")
            if self._existing:
                rule = self._existing
                rule.label       = label
                rule.rule_type   = "script"
                rule.script_path = script_path
                rule.direction   = direction
                rule.enabled     = enabled
                rule.apply_to_intercept = scope_intercept
                rule.apply_to_forge  = scope_forge
                rule.apply_to_sequence = scope_sequence
                rule.compiled = None
                rule.regex_compiled = None
                rule._script_module = None  # force reload on next apply
            else:
                rule = ReplaceRule.create(
                    label, "", b"",
                    direction=direction, enabled=enabled,
                    rule_type="script",
                    script_path=script_path,
                    apply_to_intercept=scope_intercept,
                    apply_to_forge=scope_forge,
                    apply_to_sequence=scope_sequence,
                )

        else:
            msg_widget.update("Please select a rule type.")
            return

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
        padding: 0 0;
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
            action_val = ex.action.value if ex else "tamper"
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
