"""FrameEditorHelpButton — self-contained help button for the frame editor header."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Button

from ..modals.format_help import FormatHelpModal


class FrameEditorHelpButton(Widget):
    """'?' button that opens the Frame Editor format help modal when clicked."""

    DEFAULT_CSS = """
    FrameEditorHelpButton {
        width: 5;
        min-width: 5;
        height: 1;
        margin-right: 1;
    }
    FrameEditorHelpButton > Button {
        width: 5;
        min-width: 5;
        height: 1;
        border: none;
        padding: 0;
        background: $primary-darken-1;
        color: $text;
    }
    FrameEditorHelpButton > Button:hover {
        background: $primary;
        border: none;
        padding: 0;
        color: $text;
    }
    """

    def compose(self) -> ComposeResult:
        yield Button("?", compact=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.app.push_screen(FormatHelpModal())
