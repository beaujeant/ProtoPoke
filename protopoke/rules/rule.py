"""
Binary pattern rules: ReplaceRule and InterceptRule.

Both use a user-friendly binary hex pattern syntax that is compiled to a
Python bytes regex (re.compile on bytes).  Python's ``re`` module works
natively on bytes objects, so ``re.compile(b'\\x01[\\x03-\\x09]')`` is
fully supported without any third-party library.

Pattern syntax
--------------
The following constructs are supported, space-separated:

    AB              — literal hex byte (case-insensitive)
    ??              — any single byte  (wildcard, equivalent to `.`)
    [AB-CD]         — byte range (hex endpoints, e.g. ``[03-09]``)
    .{N}            — exactly N arbitrary bytes
    .{N,M}          — between N and M arbitrary bytes
    (AB|CD|EF)      — alternation of literal hex bytes
    \\xNN           — raw Python bytes-regex escape (passed through)

Examples::

    "01 00 ??"              matches 0x01 0x00 <any>
    "FF [03-09] .{2}"       matches 0xFF <03..09> <any> <any>
    "(01|02) 00"            matches (0x01 or 0x02) followed by 0x00
    "?? .{4} FF"            matches <any> <4 bytes> 0xFF
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..models import Direction


# ---------------------------------------------------------------------------
# Pattern compilation
# ---------------------------------------------------------------------------

class PatternError(ValueError):
    """Raised when a binary pattern string is malformed."""


def compile_binary_pattern(pattern_str: str) -> "re.Pattern[bytes]":
    """
    Compile a human-readable binary pattern string to a bytes regex.

    Args:
        pattern_str: Pattern in the binary hex syntax described in the module
                     docstring.

    Returns:
        A compiled ``re.Pattern[bytes]`` with ``re.DOTALL`` enabled so that
        ``.`` (and ``??``) match any byte including ``\\x00``.

    Raises:
        PatternError: If the pattern string contains invalid syntax.
    """
    try:
        regex_bytes = _build_regex(pattern_str.strip())
        return re.compile(regex_bytes, re.DOTALL)
    except re.error as exc:
        raise PatternError(
            f"Invalid regex generated from pattern {pattern_str!r}: {exc}"
        ) from exc


def _build_regex(pattern: str) -> bytes:
    """Convert a full pattern string into a bytes regex."""
    result = bytearray()
    for token in _tokenize(pattern):
        result.extend(_token_to_regex(token))
    return bytes(result)


def _tokenize(pattern: str) -> list[str]:
    """
    Split a pattern string into a list of tokens.

    Each token is one of:
      - A two-char hex string ("FF")
      - The wildcard "??"
      - A bracket expression "[AB-CD]"
      - A quantifier ".{N}" or ".{N,M}"
      - An alternation group "(AB|CD|EF)"
      - A Python escape "\\xNN"
    """
    tokens: list[str] = []
    s = pattern.strip()
    i = 0

    while i < len(s):
        # Skip whitespace
        if s[i].isspace():
            i += 1
            continue

        # Python regex escape: \xNN
        if s[i:i+2] in ("\\x", "\\X"):
            if i + 4 > len(s):
                raise PatternError(f"Incomplete \\x escape at position {i}")
            tokens.append(s[i:i+4])
            i += 4
            continue

        # Byte range or character class: [...]
        if s[i] == "[":
            end = s.find("]", i)
            if end == -1:
                raise PatternError(f"Unclosed '[' at position {i}")
            tokens.append(s[i:end + 1])
            i = end + 1
            continue

        # Alternation group: (AB|CD)
        if s[i] == "(":
            end = s.find(")", i)
            if end == -1:
                raise PatternError(f"Unclosed '(' at position {i}")
            tokens.append(s[i:end + 1])
            i = end + 1
            continue

        # Quantifier: .{N} or .{N,M}
        if s[i] == "." and i + 1 < len(s) and s[i + 1] == "{":
            end = s.find("}", i)
            if end == -1:
                raise PatternError(f"Unclosed '{{' at position {i}")
            tokens.append(s[i:end + 1])
            i = end + 1
            continue

        # Wildcard: ??
        if s[i:i+2] == "??":
            tokens.append("??")
            i += 2
            continue

        # Hex byte: two hex chars
        if (
            i + 2 <= len(s)
            and all(c in "0123456789abcdefABCDEF" for c in s[i:i+2])
        ):
            tokens.append(s[i:i+2].upper())
            i += 2
            continue

        raise PatternError(
            f"Unexpected character {s[i]!r} at position {i} in pattern {pattern!r}"
        )

    return tokens


def _token_to_regex(token: str) -> bytes:
    """Convert a single token string into its bytes-regex fragment."""

    # Wildcard ??
    if token == "??":
        return b"."

    # Python escape \xNN — convert to a literal-match fragment
    if token[:2] in ("\\x", "\\X"):
        byte_val = int(token[2:], 16)
        return re.escape(bytes([byte_val]))

    # Quantifier: .{N} or .{N,M}
    if token.startswith(".{") and token.endswith("}"):
        return token.encode("ascii")

    # Byte range: [AB-CD]
    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1]
        if "-" in inner:
            parts = [p.strip() for p in inner.split("-", 1)]
            if (
                len(parts) == 2
                and len(parts[0]) == 2
                and len(parts[1]) == 2
                and all(c in "0123456789abcdefABCDEF" for p in parts for c in p)
            ):
                lo = int(parts[0], 16)
                hi = int(parts[1], 16)
                return f"[\\x{lo:02X}-\\x{hi:02X}]".encode("ascii")
        # Treat as a list of literal hex bytes inside []
        byte_chars: list[str] = []
        j = 0
        while j < len(inner):
            if (
                j + 2 <= len(inner)
                and all(c in "0123456789abcdefABCDEF" for c in inner[j:j+2])
            ):
                byte_val = int(inner[j:j+2], 16)
                byte_chars.append(f"\\x{byte_val:02X}")
                j += 2
            else:
                j += 1
        return ("[" + "".join(byte_chars) + "]").encode("ascii")

    # Alternation: (AB|CD|EF)
    if token.startswith("(") and token.endswith(")"):
        inner = token[1:-1]
        alts = inner.split("|")
        regex_alts: list[str] = []
        for alt in alts:
            alt = alt.strip()
            if len(alt) == 2 and all(c in "0123456789abcdefABCDEF" for c in alt):
                byte_val = int(alt, 16)
                regex_alts.append(f"\\x{byte_val:02X}")
            else:
                raise PatternError(f"Invalid byte value in alternation: {alt!r}")
        return ("(" + "|".join(regex_alts) + ")").encode("ascii")

    # Plain hex byte: "AB" → \xAB
    if len(token) == 2 and all(c in "0123456789ABCDEF" for c in token):
        byte_val = int(token, 16)
        return f"\\x{byte_val:02X}".encode("ascii")

    raise PatternError(f"Cannot convert token to bytes regex: {token!r}")


def pattern_to_display(pattern_str: str) -> str:
    """
    Normalise and return the canonical display form of a pattern string.

    Hex bytes are upper-cased and redundant whitespace is collapsed.
    Returns the original string unchanged if it cannot be parsed.
    """
    try:
        tokens = _tokenize(pattern_str.strip())
        return " ".join(tokens)
    except PatternError:
        return pattern_str


# ---------------------------------------------------------------------------
# Rule action enum (intercept rules)
# ---------------------------------------------------------------------------

class RuleAction(Enum):
    """
    Decision produced by an InterceptRule when it matches a frame.

    INTERCEPT: hold the frame in the operator queue for manual review.
    FORWARD:   auto-forward the frame, skipping the queue entirely.
    """
    INTERCEPT = "intercept"
    FORWARD   = "forward"


# ---------------------------------------------------------------------------
# ReplaceRule
# ---------------------------------------------------------------------------

@dataclass
class ReplaceRule:
    """
    A find-and-replace rule applied to frame bytes before forwarding.

    The ``pattern_str`` is compiled to a Python bytes regex.  All non-
    overlapping matches are replaced with ``replacement`` (like
    ``re.sub``).  Multiple rules can be stacked; they are applied in the
    order they appear in the RulesEngine list.

    Attributes:
        id:          Unique ID (UUID4 string).
        label:       Human-readable name shown in the UI.
        pattern_str: Binary hex pattern (see module docstring).
        replacement: Bytes to substitute for each match.  May use
                     regex backreferences (e.g. ``b'\\g<0>'``).
        direction:   Direction filter.  ``None`` = apply to both directions.
        enabled:     When ``False``, the rule is skipped entirely.
        created_at:  Unix timestamp; used to preserve insertion order.
        compiled:    Compiled regex — set automatically, not serialised.
    """

    id:          str
    label:       str
    pattern_str: str
    replacement: bytes
    direction:   Optional[Direction]        = None
    enabled:     bool                       = True
    created_at:  float                      = field(default_factory=time.time)
    compiled:    Optional["re.Pattern[bytes]"] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.compiled is None and self.pattern_str:
            self.compiled = compile_binary_pattern(self.pattern_str)

    @classmethod
    def create(
        cls,
        label:       str,
        pattern_str: str,
        replacement: bytes,
        direction:   Optional[Direction] = None,
        enabled:     bool = True,
    ) -> "ReplaceRule":
        """Factory: generates a unique ID and compiles the pattern."""
        return cls(
            id=str(uuid.uuid4()),
            label=label,
            pattern_str=pattern_str,
            replacement=replacement,
            direction=direction,
            enabled=enabled,
        )

    def apply(self, data: bytes) -> bytes:
        """
        Apply the substitution to *data*.

        Returns modified bytes if the pattern matches; otherwise returns
        *data* unchanged.
        """
        if not self.enabled or self.compiled is None:
            return data
        return self.compiled.sub(self.replacement, data)

    def matches(self, data: bytes) -> bool:
        """Return ``True`` if the pattern matches anywhere in *data*."""
        if self.compiled is None:
            return False
        return bool(self.compiled.search(data))

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dict."""
        return {
            "id":          self.id,
            "label":       self.label,
            "pattern_str": self.pattern_str,
            "replacement": self.replacement.hex(),
            "direction":   self.direction.value if self.direction else None,
            "enabled":     self.enabled,
            "created_at":  self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ReplaceRule":
        """Deserialise from a dict produced by ``to_dict()``."""
        direction: Optional[Direction] = None
        if d.get("direction"):
            direction = Direction(d["direction"])
        raw = d["replacement"]
        replacement = bytes.fromhex(raw) if isinstance(raw, str) else bytes(raw)
        return cls(
            id=d["id"],
            label=d["label"],
            pattern_str=d["pattern_str"],
            replacement=replacement,
            direction=direction,
            enabled=d.get("enabled", True),
            created_at=d.get("created_at", time.time()),
        )


# ---------------------------------------------------------------------------
# InterceptRule
# ---------------------------------------------------------------------------

@dataclass
class InterceptRule:
    """
    A rule that controls whether a frame is held in the intercept queue.

    Rules are evaluated top-to-bottom; the *first* matching rule wins.
    If no rule matches, the caller's default applies (auto-forward).

    The "invert" toggle in the UI maps directly to the ``action`` field:
    a rule with ``action=RuleAction.FORWARD`` is an "inverted" rule that
    causes matching frames to bypass the queue.

    Attributes:
        id:          Unique ID (UUID4 string).
        label:       Human-readable name.
        pattern_str: Binary hex pattern.  Empty string matches *all* frames.
        action:      What to do when the rule matches.
        direction:   Direction filter.  ``None`` = both directions.
        session_ids: Set of session IDs this rule applies to.  ``None`` = all.
        enabled:     When ``False`` the rule is skipped during evaluation.
        created_at:  Unix timestamp for insertion-order preservation.
        compiled:    Compiled regex (``None`` when pattern_str is empty).
    """

    id:          str
    label:       str
    pattern_str: str
    action:      RuleAction
    direction:   Optional[Direction]        = None
    session_ids: Optional[set[str]]         = None
    enabled:     bool                       = True
    created_at:  float                      = field(default_factory=time.time)
    compiled:    Optional["re.Pattern[bytes]"] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.compiled is None and self.pattern_str:
            self.compiled = compile_binary_pattern(self.pattern_str)
        # Ensure session_ids is always a set or None
        if self.session_ids is not None and not isinstance(self.session_ids, set):
            self.session_ids = set(self.session_ids)

    @classmethod
    def create(
        cls,
        label:       str,
        pattern_str: str,
        action:      RuleAction,
        direction:   Optional[Direction] = None,
        session_ids: Optional[set[str]] = None,
        enabled:     bool = True,
    ) -> "InterceptRule":
        """Factory: generates a unique ID and compiles the pattern."""
        return cls(
            id=str(uuid.uuid4()),
            label=label,
            pattern_str=pattern_str,
            action=action,
            direction=direction,
            session_ids=session_ids,
            enabled=enabled,
        )

    def matches_frame(self, frame) -> bool:
        """
        Return ``True`` if this rule applies to *frame*.

        Checks direction filter, session filter, and byte pattern in that
        order.  An empty ``pattern_str`` matches every frame that passes
        the other filters.
        """
        if not self.enabled:
            return False

        if self.direction is not None and frame.direction is not self.direction:
            return False

        if self.session_ids is not None and frame.session_id not in self.session_ids:
            return False

        # Empty pattern = catch-all (matches any bytes)
        if not self.pattern_str:
            return True

        if self.compiled is not None:
            return bool(self.compiled.search(frame.raw_bytes))

        return False

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dict."""
        return {
            "id":          self.id,
            "label":       self.label,
            "pattern_str": self.pattern_str,
            "action":      self.action.value,
            "direction":   self.direction.value if self.direction else None,
            "session_ids": list(self.session_ids) if self.session_ids else None,
            "enabled":     self.enabled,
            "created_at":  self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "InterceptRule":
        """Deserialise from a dict produced by ``to_dict()``."""
        direction: Optional[Direction] = None
        if d.get("direction"):
            direction = Direction(d["direction"])
        session_ids: Optional[set[str]] = None
        if d.get("session_ids"):
            session_ids = set(d["session_ids"])
        return cls(
            id=d["id"],
            label=d["label"],
            pattern_str=d.get("pattern_str", ""),
            action=RuleAction(d.get("action", "intercept")),
            direction=direction,
            session_ids=session_ids,
            enabled=d.get("enabled", True),
            created_at=d.get("created_at", time.time()),
        )
