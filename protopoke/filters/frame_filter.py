"""FrameDisplayFilter — a display-side filter for the Traffic tab's Frames pane."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Optional

from ..rules.rule import PatternError, compile_binary_pattern

SHOW = "show"
HIDE = "hide"


@dataclass
class FrameDisplayFilter:
    """
    A single display filter applied to the Traffic tab's Frames pane.

    Mode semantics (evaluated by TrafficTab._passes_filters):
      - ``hide``: frames matching this filter are always excluded.
      - ``show``: if any enabled show-filter exists, a frame must match at least
                  one of them to be displayed (OR logic).

    An empty ``pattern_str`` matches every frame (useful as a catch-all).

    Attributes:
        id:          Unique UUID4 string.
        label:       Human-readable name shown in the filter list.
        pattern_str: Binary-pattern syntax string (same format as ReplaceRule).
                     Empty string means "match all".
        mode:        ``"show"`` or ``"hide"``.
        enabled:     Whether this filter is currently active.
        compiled:    Compiled bytes regex; populated from ``pattern_str`` on init.
    """

    id:          str
    label:       str
    pattern_str: str
    mode:        str                            = SHOW
    enabled:     bool                           = True
    compiled:    Optional[re.Pattern[bytes]]    = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.compiled is None and self.pattern_str:
            self.compiled = compile_binary_pattern(self.pattern_str)

    @classmethod
    def create(
        cls,
        label:       str,
        pattern_str: str,
        mode:        str  = SHOW,
        enabled:     bool = True,
    ) -> "FrameDisplayFilter":
        """Factory — generates a fresh UUID and compiles the pattern."""
        return cls(
            id=str(uuid.uuid4()),
            label=label,
            pattern_str=pattern_str,
            mode=mode,
            enabled=enabled,
        )

    def matches(self, raw_bytes: bytes) -> bool:
        """Return True if *raw_bytes* satisfies this filter's pattern.

        An empty pattern always returns True (match-all semantics).
        """
        if not self.pattern_str:
            return True
        return bool(self.compiled and self.compiled.search(raw_bytes))

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "label":       self.label,
            "pattern_str": self.pattern_str,
            "mode":        self.mode,
            "enabled":     self.enabled,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FrameDisplayFilter":
        return cls(
            id=d["id"],
            label=d.get("label", "Filter"),
            pattern_str=d.get("pattern_str", ""),
            mode=d.get("mode", SHOW),
            enabled=d.get("enabled", True),
        )
