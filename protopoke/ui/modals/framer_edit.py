"""FramerEditModal — modal dialog for editing framer configuration."""

from __future__ import annotations

from typing import TypedDict

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Static
from textual.containers import Horizontal, Vertical

from .file_picker import FilePickerModal


class FramerSettings(TypedDict):
    framer_name: str
    framer_kwargs: dict
    custom_framer_path: str | None


_FRAMER_OPTIONS: list[tuple[str, str]] = [
    ("raw — pass raw read() chunks", "raw"),
    ("delimiter — split on byte sequence", "delimiter"),
    ("length_prefix — fixed-size length header", "length_prefix"),
    ("line — split on \\r\\n or \\n", "line"),
    ("custom — load from Python file", "custom"),
]

_PREFIX_LENGTH_OPTIONS: list[tuple[str, str]] = [
    ("1 byte", "1"),
    ("2 bytes", "2"),
    ("4 bytes", "4"),
    ("8 bytes", "8"),
]

_BYTE_ORDER_OPTIONS: list[tuple[str, str]] = [
    ("big-endian", "big"),
    ("little-endian", "little"),
]

_VALID_FRAMER_NAMES = {v for _, v in _FRAMER_OPTIONS}


class FramerEditModal(ModalScreen):
    """
    Modal dialog for editing framer configuration.

    Dismisses with a :class:`FramerSettings` dict on OK, or ``None`` on
    cancel/escape.
    """

    DEFAULT_CSS = """
    FramerEditModal > Vertical {
        width: 74;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    FramerEditModal .modal-title {
        text-style: bold;
        margin-bottom: 1;
        color: $text;
    }
    FramerEditModal .field-row {
        height: 3;
        align: left middle;
    }
    FramerEditModal .field-label {
        width: 24;
        padding: 0 1;
    }
    FramerEditModal .field-input {
        width: 1fr;
    }
    FramerEditModal .section {
        height: auto;
        margin-top: 1;
    }
    FramerEditModal .info-text {
        color: $text-muted;
        padding: 0 1;
        height: 3;
        content-align: left middle;
    }
    FramerEditModal .buttons {
        height: 3;
        margin-top: 1;
        align: right middle;
    }
    FramerEditModal Button {
        margin-left: 1;
    }
    FramerEditModal .btn-browse {
        width: 10;
        min-width: 10;
    }
    """

    def __init__(self, settings: FramerSettings) -> None:
        super().__init__()
        self._settings = settings

    def compose(self) -> ComposeResult:
        s = self._settings
        framer_name = s["framer_name"]
        if framer_name not in _VALID_FRAMER_NAMES:
            framer_name = "raw"
        kwargs = s["framer_kwargs"]
        custom_path = s.get("custom_framer_path") or ""

        # Derive initial field values from existing settings
        delim_bytes = kwargs.get("delimiter", b"\n")
        delim_hex = delim_bytes.hex() if isinstance(delim_bytes, bytes) else str(delim_bytes)

        prefix_len = str(kwargs.get("prefix_length", 4))
        byte_order = kwargs.get("byte_order", "big")
        prefix_offset = str(kwargs.get("prefix_offset", 0))
        length_add = str(kwargs.get("length_add", 0))

        with Vertical():
            yield Label("Edit Framer", classes="modal-title")

            # ---- Framer type selector ----
            with Horizontal(classes="field-row"):
                yield Label("Framer type:", classes="field-label")
                yield Select(
                    _FRAMER_OPTIONS,
                    value=framer_name,
                    id="modal-framer-type",
                    classes="field-input",
                )

            # ---- raw ----
            with Vertical(id="section-raw", classes="section"):
                yield Static(
                    "Each read() chunk becomes one frame — no buffering or boundary detection.",
                    classes="info-text",
                )

            # ---- delimiter ----
            with Vertical(id="section-delimiter", classes="section"):
                with Horizontal(classes="field-row"):
                    yield Label("Delimiter (hex):", classes="field-label")
                    yield Input(
                        value=delim_hex,
                        id="delim-bytes",
                        placeholder="e.g. 0d0a for \\r\\n, 00 for null byte",
                        classes="field-input",
                    )

            # ---- length_prefix ----
            with Vertical(id="section-length_prefix", classes="section"):
                with Horizontal(classes="field-row"):
                    yield Label("Prefix length:", classes="field-label")
                    yield Select(
                        _PREFIX_LENGTH_OPTIONS,
                        value=prefix_len,
                        id="lp-prefix-length",
                        classes="field-input",
                    )
                with Horizontal(classes="field-row"):
                    yield Label("Byte order:", classes="field-label")
                    yield Select(
                        _BYTE_ORDER_OPTIONS,
                        value=byte_order,
                        id="lp-byte-order",
                        classes="field-input",
                    )
                with Horizontal(classes="field-row"):
                    yield Label("Prefix offset:", classes="field-label")
                    yield Input(
                        value=prefix_offset,
                        id="lp-prefix-offset",
                        restrict=r"\d*",
                        placeholder="0",
                        classes="field-input",
                        tooltip=(
                            "Bytes before the length field. E.g. if the header is "
                            "[type 1B][flags 2B][length 4B] set offset to 3."
                        ),
                    )
                with Horizontal(classes="field-row"):
                    yield Label("Length adjust:", classes="field-label")
                    yield Input(
                        value=length_add,
                        id="lp-length-add",
                        restrict=r"-?\d*",
                        placeholder="0",
                        classes="field-input",
                        tooltip=(
                            "Added to the decoded length value to get actual payload size. "
                            "Use +N if a fixed footer is not counted in the length field. "
                            "Use -N if the length encodes the total frame size."
                        ),
                    )

            # ---- line ----
            with Vertical(id="section-line", classes="section"):
                yield Static(
                    "Convenience wrapper — splits on \\r\\n or \\n (bare newline).",
                    classes="info-text",
                )

            # ---- custom ----
            with Vertical(id="section-custom", classes="section"):
                with Horizontal(classes="field-row"):
                    yield Label("Script path:", classes="field-label")
                    yield Input(
                        value=custom_path,
                        id="custom-path",
                        placeholder="/path/to/my_framer.py",
                        classes="field-input",
                    )
                    yield Button("Browse", id="browse-custom-path", classes="btn-browse")

            # ---- buttons ----
            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("OK", variant="primary", id="btn-ok")

    def on_mount(self) -> None:
        framer_name = self._settings["framer_name"]
        if framer_name not in _VALID_FRAMER_NAMES:
            framer_name = "raw"
        self._show_section(framer_name)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _show_section(self, framer_name: str) -> None:
        """Show only the section matching *framer_name*, hide the others."""
        for name in ("raw", "delimiter", "length_prefix", "line", "custom"):
            self.query_one(f"#section-{name}").display = (name == framer_name)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "modal-framer-type":
            val = event.value
            if val and val is not Select.BLANK:
                self._show_section(str(val))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "browse-custom-path":
            current = self.query_one("#custom-path", Input).value.strip() or None
            def _on_pick(path: str | None) -> None:
                if path is not None:
                    self.query_one("#custom-path", Input).value = path
            self.app.push_screen(FilePickerModal(current), _on_pick)
        elif event.button.id == "btn-ok":
            self.dismiss(self._build_result())
        else:
            self.dismiss(None)

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)

    # ------------------------------------------------------------------
    # Result builder
    # ------------------------------------------------------------------

    def _build_result(self) -> FramerSettings:
        framer_name = str(self.query_one("#modal-framer-type", Select).value)
        kwargs: dict = {}
        custom_path: str | None = None

        if framer_name == "delimiter":
            delim_hex = self.query_one("#delim-bytes", Input).value.strip()
            try:
                delim_bytes = bytes.fromhex(delim_hex) if delim_hex else b"\n"
            except ValueError:
                delim_bytes = b"\n"
            kwargs["delimiter"] = delim_bytes

        elif framer_name == "length_prefix":
            prefix_len_val = self.query_one("#lp-prefix-length", Select).value
            byte_order_val = self.query_one("#lp-byte-order", Select).value
            kwargs["prefix_length"] = int(str(prefix_len_val))
            kwargs["byte_order"] = str(byte_order_val)
            try:
                kwargs["prefix_offset"] = int(self.query_one("#lp-prefix-offset", Input).value.strip() or "0")
            except ValueError:
                kwargs["prefix_offset"] = 0
            try:
                kwargs["length_add"] = int(self.query_one("#lp-length-add", Input).value.strip() or "0")
            except ValueError:
                kwargs["length_add"] = 0

        elif framer_name == "custom":
            custom_path = self.query_one("#custom-path", Input).value.strip() or None

        return {
            "framer_name": framer_name,
            "framer_kwargs": kwargs,
            "custom_framer_path": custom_path,
        }
