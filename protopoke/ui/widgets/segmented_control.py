"""SegmentedControl — single-row tab-button switcher used across the TUI."""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.message import Message
from textual.widgets import Button


class SegmentedControl(Horizontal):
    """
    Horizontal row of mutually-exclusive segments (a "segmented control").

    Replaces the handcrafted Hex/Parsed, HEX/STR, and direction-filter button
    rows that previously lived inline in TamperTab, ForgeTab, and ParsedView.

    Each segment is a compact ``Button``; the active segment is marked by a
    CSS class ``active`` (filled $accent background, bold) and the others
    render transparent + muted. Disabled segments cannot be activated.

    Posts ``SegmentedControl.Changed`` when the user activates a different
    segment. Programmatic ``value`` assignment is silent so external state
    updates don't loop back through the host's handler.
    """

    DEFAULT_CSS = """
    SegmentedControl {
        width: auto;
        height: 1;
    }
    SegmentedControl Button.segment {
        height: 1;
        min-width: 5;
        padding: 0 1;
        margin: 0;
        border: none;
        background: transparent;
        color: $text-muted;
        text-style: none;
    }
    SegmentedControl Button.segment.active {
        background: $accent;
        color: $text;
        text-style: bold;
    }
    SegmentedControl Button.segment:hover {
        background: $primary 50%;
        border: none;
        padding: 0 1;
    }
    SegmentedControl Button.segment.active:hover {
        background: $accent;
        border: none;
        padding: 0 1;
    }
    SegmentedControl Button.segment:disabled {
        color: $text-disabled;
        background: transparent;
        text-style: none;
    }
    """

    class Changed(Message):
        """Posted when the user activates a different segment."""

        def __init__(self, segmented_control: "SegmentedControl", value: Any) -> None:
            super().__init__()
            self.segmented_control = segmented_control
            self.value = value
            self.control_name = segmented_control.name

        @property
        def control(self) -> "SegmentedControl":
            return self.segmented_control

    def __init__(
        self,
        options: list[tuple[str, Any]],
        *,
        value: Any = None,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
        disabled_values: set[Any] | None = None,
        compact: bool = True,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self._options: list[tuple[str, Any]] = list(options)
        self._compact = compact
        self._disabled_values: set[Any] = set(disabled_values or ())
        if value is None and options and not any(v is None for _, v in options):
            value = options[0][1]
        self._value: Any = value

    def compose(self) -> ComposeResult:
        for idx, (label, val) in enumerate(self._options):
            btn = Button(
                label,
                classes="segment",
                compact=self._compact,
                flat=True,
                id=f"_seg-{idx}",
            )
            btn._sc_value = val
            if val in self._disabled_values:
                btn.disabled = True
            yield btn

    def on_mount(self) -> None:
        self._apply_active_classes()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def value(self) -> Any:
        return self._value

    @value.setter
    def value(self, v: Any) -> None:
        self.set_value(v, post=False)

    def set_value(self, v: Any, *, post: bool = False) -> None:
        """Set the active value. By default does NOT post Changed."""
        if v == self._value:
            return
        if v in self._disabled_values:
            return
        self._value = v
        if self.is_mounted:
            self._apply_active_classes()
        if post:
            self.post_message(self.Changed(self, v))

    def set_disabled_values(self, values: set[Any]) -> None:
        """Update which segments render as disabled."""
        self._disabled_values = set(values)
        if not self.is_mounted:
            return
        for idx, (_, val) in enumerate(self._options):
            btn = self.query_one(f"#_seg-{idx}", Button)
            btn.disabled = val in self._disabled_values
        self._apply_active_classes()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _apply_active_classes(self) -> None:
        for idx, (_, val) in enumerate(self._options):
            btn = self.query_one(f"#_seg-{idx}", Button)
            btn.set_class(val == self._value and not btn.disabled, "active")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button
        if btn.parent is not self:
            return
        event.stop()
        if btn.disabled:
            return
        new_value = getattr(btn, "_sc_value", None)
        if new_value == self._value:
            return
        self._value = new_value
        self._apply_active_classes()
        self.post_message(self.Changed(self, new_value))
