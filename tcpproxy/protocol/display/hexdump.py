"""
Wireshark-style hex dump renderer.

Produces output like:

    Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F    ASCII
    00000000  01 00 05 61 64 6D 69 6E  00 08 73 33 63 72 33 74    ...admin..s3cr3t
    00000010  21 21                                                !!

When a ParsedMessage is provided, highlighted byte ranges are marked with
ANSI colour codes (one colour per top-level field, cycling through a palette).
Highlighting is skipped when the terminal does not support colour or when
`color=False` is passed.

Public API:
    render_hexdump(data, highlights=(), width=16, color=True) -> str
    highlights_from_message(msg) -> list[Highlight]
    Highlight(start, end, label, color_code)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from ...models import ParsedField, ParsedMessage


# ---------------------------------------------------------------------------
# ANSI colours (foreground, bright variants, to be distinct on dark backgrounds)
# ---------------------------------------------------------------------------

_ANSI_COLORS = [
    "\033[92m",   # bright green
    "\033[93m",   # bright yellow
    "\033[94m",   # bright blue
    "\033[96m",   # bright cyan
    "\033[95m",   # bright magenta
    "\033[91m",   # bright red
    "\033[32m",   # green
    "\033[33m",   # yellow
    "\033[34m",   # blue
    "\033[36m",   # cyan
    "\033[35m",   # magenta
    "\033[31m",   # red
]
_RESET = "\033[0m"


@dataclass
class Highlight:
    """
    A byte range that should be visually highlighted in the hex dump.

    Attributes:
        start:      First byte offset (inclusive).
        end:        Last byte offset (exclusive).
        label:      Short label shown in a legend (field name).
        color_code: ANSI escape sequence for this highlight, or "" to skip.
    """
    start:      int
    end:        int
    label:      str
    color_code: str = ""


def highlights_from_message(msg: ParsedMessage, color: bool = True) -> list[Highlight]:
    """
    Build a list of Highlights from a ParsedMessage's top-level fields.

    Each top-level field gets a different colour.  Nested fields (TLV children,
    array items) are not separately highlighted to avoid visual noise —
    the parent field's range covers them.
    """
    highlights = []
    color_index = 0
    for pf in msg.fields:
        if pf.size == 0:
            continue
        code = _ANSI_COLORS[color_index % len(_ANSI_COLORS)] if color else ""
        highlights.append(Highlight(
            start=pf.offset,
            end=pf.offset + pf.size,
            label=pf.name,
            color_code=code,
        ))
        color_index += 1
    return highlights


def render_hexdump(
    data:       bytes,
    highlights: list[Highlight] = (),
    width:      int  = 16,
    color:      bool = True,
) -> str:
    """
    Render `data` as a Wireshark-style hex + ASCII dump.

    Args:
        data:       Bytes to display.
        highlights: List of Highlight objects for coloured ranges.
        width:      Bytes per row (16 is standard, 8 for narrow terminals).
        color:      Enable ANSI colour codes.  Auto-disabled when not a TTY
                    if the caller passes color=True but we detect no terminal.

    Returns:
        Multi-line string ready to print.
    """
    if not data:
        return "  (empty)\n"

    # Auto-detect TTY
    if color and not _supports_color():
        color = False

    # Build a lookup: byte_offset → (color_code, is_last_in_range)
    byte_colors: dict[int, str] = {}
    if color:
        for hl in highlights:
            for i in range(hl.start, min(hl.end, len(data))):
                byte_colors[i] = hl.color_code

    lines = []
    # Header
    half = width // 2
    hex_header = " ".join(f"{i:02X}" for i in range(half)) + "  " + \
                 " ".join(f"{i:02X}" for i in range(half, width))
    lines.append(f"  {'Offset':<10}{hex_header}    {'ASCII'}")
    lines.append("  " + "─" * (10 + width * 3 + 3 + width))

    for row_start in range(0, len(data), width):
        row = data[row_start : row_start + width]

        # Hex section
        hex_parts = []
        for col, byte in enumerate(row):
            abs_offset = row_start + col
            code = byte_colors.get(abs_offset, "")
            reset = _RESET if code else ""
            cell = f"{code}{byte:02X}{reset}"
            hex_parts.append(cell)
            if col == half - 1:
                hex_parts.append(" ")  # extra space between halves

        # Pad short rows
        missing = width - len(row)
        for col in range(missing):
            hex_parts.append("  ")
            if len(row) + col == half - 1:
                hex_parts.append(" ")

        hex_str = " ".join(hex_parts)

        # ASCII section
        ascii_parts = []
        for col, byte in enumerate(row):
            abs_offset = row_start + col
            code = byte_colors.get(abs_offset, "")
            reset = _RESET if code else ""
            ch = chr(byte) if 0x20 <= byte < 0x7F else "."
            ascii_parts.append(f"{code}{ch}{reset}")
        ascii_str = "".join(ascii_parts)

        offset_str = f"  {row_start:08X}  "
        lines.append(f"{offset_str}{hex_str}    {ascii_str}")

    return "\n".join(lines) + "\n"


def _supports_color() -> bool:
    """Return True if the current terminal likely supports ANSI colour."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(os, "isatty") and os.isatty(1)
