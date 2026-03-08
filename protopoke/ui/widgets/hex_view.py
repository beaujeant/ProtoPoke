"""HexView widget — displays raw bytes as a Wireshark-style hex dump."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static
from textual.reactive import reactive

from ...models import Frame, ParsedMessage
from ...protocol.display.hexdump import render_hexdump, highlights_from_message


class HexView(Widget):
    """
    A read-only hex dump display widget.

    Usage::

        hex_view = HexView()
        hex_view.show_frame(frame)          # raw dump
        hex_view.show_frame(frame, message) # with field highlights
        hex_view.clear()
    """

    DEFAULT_CSS = """
    HexView {
        overflow-y: auto;
        padding: 0 1;
    }
    HexView Static {
        width: 1fr;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("", id="hex-content", markup=False)

    def show_frame(
        self,
        frame: Frame,
        message: ParsedMessage | None = None,
    ) -> None:
        """Render *frame* bytes into the hex dump, optionally with field highlights."""
        highlights = []
        if message is not None:
            highlights = highlights_from_message(message, color=False)
        text = render_hexdump(frame.raw_bytes, highlights=highlights, color=False)
        self.query_one("#hex-content", Static).update(text)

    def show_bytes(self, data: bytes) -> None:
        """Render raw bytes without any highlight context."""
        text = render_hexdump(data, color=False)
        self.query_one("#hex-content", Static).update(text)

    def clear(self) -> None:
        """Clear the hex dump view."""
        self.query_one("#hex-content", Static).update("")
