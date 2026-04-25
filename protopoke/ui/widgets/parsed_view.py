"""ParsedView widget — toggles between raw hex dump and protocol field tree."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Static

from ...models import Frame, ParsedMessage
from ...protocol.display.hexdump import highlights_from_message, render_hexdump
from ...protocol.display.tree import render_field_tree, render_frame_header
from .segmented_control import SegmentedControl


class ParsedView(Vertical):
    """
    Detail pane showing a frame in either hex-dump or parsed-field-tree mode.

    Inherits from Vertical so Textual handles layout/rendering as a container.

    Public API::

        pv.show_frame(frame)              # hex only (no decoder available)
        pv.show_frame(frame, message)     # hex + enables Parsed tab
        pv.clear()
    """

    DEFAULT_CSS = """
    ParsedView {
        height: 1fr;
    }
    ParsedView .view-toolbar {
        height: 3;
        background: $primary-darken-2;
        align: left middle;
        padding: 0 1;
    }
    ParsedView .view-toolbar Static {
        width: 1fr;
        height: 100%;
        color: $text;
        text-style: bold;
        content-align-horizontal: left;
        content-align-vertical: middle;
    }
    ParsedView #detail-scroll {
        height: 1fr;
    }
    ParsedView #detail-content {
        padding: 0 1;
    }
    """

    def __init__(self, title: str = "Frame Detail", *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._title = title
        self._frame: Frame | None = None
        self._message: ParsedMessage | None = None
        self._mode: str = "hex"  # "hex" or "parsed"

    def compose(self) -> ComposeResult:
        with Horizontal(classes="view-toolbar"):
            yield Static(self._title, id="view-title")
            yield SegmentedControl(
                [("Hex", "hex"), ("Parsed", "parsed")],
                value=self._mode,
                disabled_values={"parsed"},
                id="parsed-mode",
                name="parsed_view_mode",
            )
        with VerticalScroll(id="detail-scroll"):
            yield Static("", id="detail-content", markup=False)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def show_frame(
        self,
        frame: Frame,
        message: ParsedMessage | None = None,
    ) -> None:
        """Display *frame*.  If *message* is provided, the Parsed button is available."""
        self._frame = frame
        self._message = message
        sc = self.query_one("#parsed-mode", SegmentedControl)
        sc.set_disabled_values({"parsed"} if message is None else set())
        if message is None and self._mode == "parsed":
            self._mode = "hex"
            sc.value = "hex"
        self._refresh_content()

    def clear(self) -> None:
        """Clear the view."""
        self._frame = None
        self._message = None
        self.query_one("#detail-content", Static).update("")
        self.query_one("#parsed-mode", SegmentedControl).set_disabled_values({"parsed"})

    # ------------------------------------------------------------------
    # Mode toggle
    # ------------------------------------------------------------------

    def on_segmented_control_changed(self, event: SegmentedControl.Changed) -> None:
        if event.control_name != "parsed_view_mode":
            return
        self._mode = event.value
        self._refresh_content()

    def _refresh_content(self) -> None:
        """Update the detail-content Static with the current mode's text."""
        content = self.query_one("#detail-content", Static)
        if self._frame is None:
            content.update("")
            return

        if self._mode == "parsed" and self._message is not None:
            header = render_frame_header(self._frame, self._message)
            tree   = render_field_tree(self._message, width=100, color=False)
            content.update(header + "\n" + tree)
        else:
            highlights = (
                highlights_from_message(self._message, color=False)
                if self._message is not None
                else []
            )
            content.update(
                render_hexdump(self._frame.raw_bytes, highlights=highlights, color=False)
            )
