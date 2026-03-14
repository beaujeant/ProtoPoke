"""
Field tree renderer.

Produces a Wireshark-style packet details panel for the terminal:

    ┌─ LoginRequest ─────────────────────────────────────────────────┐
    │  opcode       [0x00, 1B]   0x01                                │
    │  version      [0x01, 1B]   0x03                                │
    │  username_len [0x02, 2B]   5                                   │
    │  username     [0x04, 5B]   "admin"                             │
    │  password_len [0x09, 2B]   8                                   │
    │  password     [0x0B, 8B]   73 33 63 72 33 74 21 21             │
    └────────────────────────────────────────────────────────────────┘

Nested fields (TLV, array items) are indented:

    │  attributes   [0x05, 32B]  (3 TLV entries)                    │
    │  ├─ ChannelID    [0x05, 8B]   [0x0001] 42                     │
    │  ├─ ChannelName  [0x0D, 10B]  [0x0002] "general"              │
    │  └─ Payload      [0x17, 14B]  [0x0003] DE AD BE EF …          │

Public API:
    render_field_tree(msg, width=70, color=True) -> str
    render_frame_header(frame, msg=None) -> str
"""

from __future__ import annotations

import datetime
import os

from ...models import Direction, Frame, ParsedField, ParsedMessage


# ANSI codes for structural chrome
_BOLD  = "\033[1m"
_DIM   = "\033[2m"
_RESET = "\033[0m"
_CYAN  = "\033[96m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"


def render_frame_header(frame: Frame, msg: ParsedMessage | None = None) -> str:
    """
    One-line summary bar for an intercepted / captured frame.

    Example:
        Frame #3  C→S  2024-01-15 10:23:45.123  48 bytes  LoginRequest
    """
    ts = datetime.datetime.fromtimestamp(frame.timestamp).strftime("%H:%M:%S.%f")[:-3]
    arrow = "C→S" if frame.direction is Direction.CLIENT_TO_SERVER else "S→C"
    msg_type = f"  {msg.message_type}" if msg and msg.message_type else ""
    protocol = f"  [{msg.protocol_name}]" if msg else ""
    err = "  ⚠ partial" if msg and msg.error else ""
    return (
        f"  Frame #{frame.sequence_number}  {arrow}  {ts}  "
        f"{len(frame.raw_bytes)} bytes{protocol}{msg_type}{err}"
    )


def render_field_tree(
    msg:   ParsedMessage,
    width: int  = 72,
    color: bool = True,
) -> str:
    """
    Render a ParsedMessage as a terminal field tree.

    Args:
        msg:   The parsed message to display.
        width: Total display width in characters.
        color: Enable ANSI codes.  Auto-disabled when not a TTY.

    Returns:
        Multi-line string ready to print.
    """
    if color and not _supports_color():
        color = False

    inner_w = width - 4  # room for "│  " prefix and " │" suffix

    title = f" {msg.message_type} " if msg.message_type else " (unknown) "
    if msg.protocol_name:
        title = f" {msg.protocol_name} / {msg.message_type} "

    top = "┌─" + title + "─" * max(0, width - 1 - len(title)) + "┐"
    bot = "└" + "─" * width + "┘"

    lines = [top]

    if msg.error:
        err_line = f"  ⚠  {msg.error}"
        lines.append(_field_row(err_line[:inner_w], inner_w, color=False, warn=True))

    for pf in msg.fields:
        lines.extend(_render_field(pf, inner_w, indent=0, color=color, is_last=True))

    lines.append(bot)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _render_field(
    pf:      ParsedField,
    inner_w: int,
    indent:  int,
    color:   bool,
    is_last: bool,
    prefix:  str = "",
) -> list[str]:
    """Render one field and its children recursively."""
    lines = []

    offset_str = f"0x{pf.offset:04X}"
    size_str   = f"{pf.size}B"
    meta       = f"[{offset_str}, {size_str:>4}]"

    name_col = 18 - indent * 2
    name_str = pf.name[:name_col].ljust(name_col)

    dv = pf.display_value or _auto_display(pf)
    # Truncate display value to fit
    budget = inner_w - indent * 2 - len(prefix) - name_col - len(meta) - 3
    if len(dv) > max(budget, 8):
        dv = dv[:max(budget, 8) - 1] + "…"

    content = f"{prefix}{name_str} {meta}  {dv}"
    lines.append(_field_row(content[:inner_w], inner_w, color))

    # Children (TLV entries, array items)
    if pf.children:
        child_indent = indent + 1
        for i, child in enumerate(pf.children):
            child_is_last = (i == len(pf.children) - 1)
            branch = "└─" if child_is_last else "├─"
            child_prefix = "  " * child_indent + branch + " "
            lines.extend(_render_field(
                child, inner_w,
                indent=child_indent,
                color=color,
                is_last=child_is_last,
                prefix=child_prefix,
            ))

    return lines


def _field_row(content: str, inner_w: int, color: bool = True, warn: bool = False) -> str:
    """Wrap content in the box-drawing row: │  content  …  │"""
    padded = content.ljust(inner_w)
    if color and warn:
        padded = _YELLOW + padded + _RESET
    return f"│  {padded}  │"


def _auto_display(pf: ParsedField) -> str:
    """Fallback display when display_value is empty."""
    v = pf.value
    if isinstance(v, bytes):
        if len(v) == 0:
            return "(empty)"
        preview = v[:24].hex(" ").upper()
        return (preview + " …") if len(v) > 24 else preview
    if isinstance(v, str):
        return repr(v) if len(v) <= 40 else repr(v[:40]) + "…"
    if isinstance(v, list):
        return f"({len(v)} items)"
    return str(v)


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(os, "isatty") and os.isatty(1)
