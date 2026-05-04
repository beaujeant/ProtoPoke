"""FrameDisplayFilter — a display-side filter for the Traffic tab's Frames pane."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Optional

from ..models import Direction
from ..rules.rule import compile_binary_pattern

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

    An empty ``pattern_str`` matches every frame in the configured direction
    (useful as a catch-all to e.g. show or hide an entire direction).

    Attributes:
        id:          Unique UUID4 string.
        label:       Human-readable name shown in the filter list.
        pattern_str: Binary-pattern syntax string (same format as ReplaceRule).
                     Empty string means "match all".
        mode:        ``"show"`` or ``"hide"``.
        direction:   Direction filter.  ``None`` = both directions.
        enabled:     Whether this filter is currently active.
        compiled:    Compiled bytes regex; populated from ``pattern_str`` on init.
    """

    id:          str
    label:       str
    pattern_str: str
    mode:        str                            = SHOW
    direction:   Optional[Direction]            = None
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
        mode:        str                  = SHOW,
        direction:   Optional[Direction]  = None,
        enabled:     bool                 = True,
    ) -> "FrameDisplayFilter":
        """Factory — generates a fresh UUID and compiles the pattern."""
        return cls(
            id=str(uuid.uuid4()),
            label=label,
            pattern_str=pattern_str,
            mode=mode,
            direction=direction,
            enabled=enabled,
        )

    def matches_frame(self, frame) -> bool:
        """Return True if *frame* satisfies this filter's direction and pattern.

        Direction is checked first: a filter with a specific direction never
        matches frames flowing in the other direction.  An empty
        ``pattern_str`` then matches every remaining frame.
        """
        if self.direction is not None and frame.direction is not self.direction:
            return False
        if not self.pattern_str:
            return True
        return bool(self.compiled and self.compiled.search(frame.raw_bytes))

    def matches(self, raw_bytes: bytes) -> bool:
        """Return True if *raw_bytes* satisfies this filter's pattern.

        Note: this overload ignores the direction filter — prefer
        :meth:`matches_frame` when a :class:`Frame` is available.
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
            "direction":   self.direction.value if self.direction else None,
            "enabled":     self.enabled,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FrameDisplayFilter":
        direction: Optional[Direction] = None
        if d.get("direction"):
            direction = Direction(d["direction"])
        return cls(
            id=d["id"],
            label=d.get("label", "Filter"),
            pattern_str=d.get("pattern_str", ""),
            mode=d.get("mode", SHOW),
            direction=direction,
            enabled=d.get("enabled", True),
        )
