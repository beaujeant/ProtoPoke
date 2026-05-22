"""FormatHelpModal — explains the frame editor template syntax."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Static
from textual.containers import Vertical, VerticalScroll, Horizontal


_HELP_TEXT = """\
Frame data is entered as space-separated hex bytes, e.g.:
  48 65 6c 6c 6f 0a

──────────────────────────────────────────
Variables  {{NAME}}
──────────────────────────────────────────
Replace any bytes with a named variable:
  {{SESSION_TOKEN}}
  de ad {{MY_VAR}} 00

Variable values are supplied at run time and substituted before sending.

──────────────────────────────────────────
Transforms  {{NAME:transform(args)}}
──────────────────────────────────────────
Apply a transform to a variable's value:

  {{SEQ:uint32be_add(1)}}
    Interpret the variable as a big-endian uint32, add 1 to it, then
    encode back to bytes.  Useful for auto-incrementing sequence numbers.

  {{SEQ:uint32le_add(1)}}
    Same but little-endian.

  {{VAL:xor(ff)}}
    XOR every byte of the value with 0xff.

  {{VAL:xor(deadbeef)}}
    XOR the value (cycling) with the given hex key.

  {{BUF:append(0a0d)}}
    Append the given hex bytes to the end of the value.

  {{BUF:prepend(0a0d)}}
    Prepend the given hex bytes to the start of the value.

──────────────────────────────────────────
STR mode
──────────────────────────────────────────
Switch to STR mode (the STR button) to view and edit the frame as a
UTF-8 string with escape sequences:
  \\n  →  0a     \\r  →  0d     \\t  →  09
  \\xHH  →  arbitrary byte
  {{NAME}} variables are preserved in both modes.

──────────────────────────────────────────
Examples
──────────────────────────────────────────
  01 00 {{LEN:uint16be_add(0)}} {{BODY}}
    Two-byte type + two-byte big-endian length + body variable.

  {{SEQ:uint32be_add(1)}} de ad be ef
    Auto-incrementing sequence counter followed by fixed bytes.
"""


class FormatHelpModal(ModalScreen[None]):
    """Read-only modal explaining the frame editor format syntax."""

    DEFAULT_CSS = """
    FormatHelpModal {
        align: center middle;
    }
    FormatHelpModal > Vertical {
        width: 72;
        height: auto;
        max-height: 90%;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    FormatHelpModal .modal-title {
        text-style: bold;
        margin-bottom: 1;
    }
    FormatHelpModal #help-scroll {
        height: 1fr;
        max-height: 100%;
    }
    FormatHelpModal #help-body {
        margin-bottom: 1;
    }
    FormatHelpModal .buttons {
        height: 3;
        margin-top: 1;
        align: right middle;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("Frame Editor Format Help", classes="modal-title")
            with VerticalScroll(id="help-scroll"):
                yield Static(_HELP_TEXT, id="help-body", markup=False)
            with Horizontal(classes="buttons"):
                yield Button("Close", variant="primary", id="btn-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def on_key(self, event) -> None:
        if event.key in ("escape", "enter", "q"):
            self.dismiss(None)
