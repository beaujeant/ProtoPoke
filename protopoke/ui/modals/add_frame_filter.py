"""AddFrameFilterModal — create or edit a FrameDisplayFilter."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Static, Switch
from textual.containers import Horizontal, Vertical

from ...filters.frame_filter import HIDE, SHOW, FrameDisplayFilter
from ...rules.rule import PatternError, compile_binary_pattern

_MODE_OPTIONS = [
    ("Show — display only matching frames", SHOW),
    ("Hide — exclude matching frames",      HIDE),
]


class AddFrameFilterModal(ModalScreen[FrameDisplayFilter | None]):
    """
    Modal form to create or edit a :class:`FrameDisplayFilter`.

    Dismisses with the new/updated filter, or ``None`` if cancelled.
    """

    DEFAULT_CSS = """
    AddFrameFilterModal > Vertical {
        width: 72;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    AddFrameFilterModal Label {
        margin-top: 1;
    }
    AddFrameFilterModal Input {
        margin-bottom: 0;
    }
    AddFrameFilterModal .hint {
        color: $text-muted;
    }
    AddFrameFilterModal .switch-row {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    AddFrameFilterModal .buttons {
        height: 3;
        margin-top: 2;
        align: right middle;
    }
    AddFrameFilterModal Button {
        margin-left: 1;
        padding: 0 0;
    }
    AddFrameFilterModal #validation-msg {
        color: $error;
        height: 1;
    }
    """

    def __init__(self, existing: FrameDisplayFilter | None = None) -> None:
        super().__init__()
        self._existing = existing

    def compose(self) -> ComposeResult:
        ex = self._existing
        with Vertical():
            yield Label("Frame Filter", classes="modal-title")

            yield Label("Label:")
            yield Input(
                value=ex.label if ex else "",
                placeholder="My filter",
                id="ff-label",
            )

            yield Label("Pattern (hex binary syntax, empty = match all):")
            yield Input(
                value=ex.pattern_str if ex else "",
                placeholder="e.g.  6D 76 .{20}  or leave blank to match everything",
                id="ff-pattern",
            )
            yield Static(
                "AB=literal  ??=any byte  [AB-CD]=range  .{N}=N bytes  (AB|CD)=alt  "
                "^=start  $=end  XX+=one+  XX*=zero+",
                classes="hint",
            )

            yield Label("Mode:")
            yield Select(
                [(lbl, val) for lbl, val in _MODE_OPTIONS],
                value=ex.mode if ex else SHOW,
                id="ff-mode",
            )

            with Horizontal(classes="switch-row"):
                yield Label("Enabled: ")
                yield Switch(value=ex.enabled if ex else True, id="ff-enabled")

            yield Static("", id="validation-msg")

            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Save",   variant="primary",  id="btn-save")

    def on_mount(self) -> None:
        self.query_one("#ff-label", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
            return
        self._try_save()

    def on_input_submitted(self, _: Input.Submitted) -> None:
        self._try_save()

    def _try_save(self) -> None:
        label       = self.query_one("#ff-label",   Input).value.strip() or "Filter"
        pattern_str = self.query_one("#ff-pattern", Input).value.strip()
        mode        = str(self.query_one("#ff-mode", Select).value)
        enabled     = self.query_one("#ff-enabled", Switch).value
        msg_widget  = self.query_one("#validation-msg", Static)

        if mode not in (SHOW, HIDE):
            mode = SHOW

        if pattern_str:
            try:
                compile_binary_pattern(pattern_str)
            except PatternError as exc:
                msg_widget.update(f"Pattern error: {exc}")
                return

        msg_widget.update("")

        if self._existing:
            f = self._existing
            f.label       = label
            f.pattern_str = pattern_str
            f.mode        = mode
            f.enabled     = enabled
            f.compiled    = compile_binary_pattern(pattern_str) if pattern_str else None
            self.dismiss(f)
        else:
            self.dismiss(FrameDisplayFilter.create(label, pattern_str, mode, enabled))
