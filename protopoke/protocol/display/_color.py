"""Shared TTY/colour detection helper for display renderers."""

from __future__ import annotations

import os


def supports_color() -> bool:
    """Return True if the current terminal likely supports ANSI colour."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(os, "isatty") and os.isatty(1)
