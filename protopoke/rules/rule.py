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

import codecs
import importlib.util
import logging
import re
import time
import types
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..models import Direction

logger = logging.getLogger(__name__)


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


def _consume_quantifier_suffix(s: str, i: int, tokens: list[str]) -> int:
    """If the next non-space char is '+' or '*', fold it into the last token."""
    j = i
    while j < len(s) and s[j].isspace():
        j += 1
    if j < len(s) and s[j] in ("+", "*"):
        tokens[-1] = tokens[-1] + s[j]
        return j + 1
    return i


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

        # Anchors: ^ (start of data) and $ (end of data)
        if s[i] in ("^", "$"):
            tokens.append(s[i])
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
            i = _consume_quantifier_suffix(s, i, tokens)
            continue

        # Alternation group: (AB|CD)
        if s[i] == "(":
            end = s.find(")", i)
            if end == -1:
                raise PatternError(f"Unclosed '(' at position {i}")
            tokens.append(s[i:end + 1])
            i = end + 1
            i = _consume_quantifier_suffix(s, i, tokens)
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
            i = _consume_quantifier_suffix(s, i, tokens)
            continue

        # Hex byte: two hex chars
        if (
            i + 2 <= len(s)
            and all(c in "0123456789abcdefABCDEF" for c in s[i:i+2])
        ):
            tokens.append(s[i:i+2].upper())
            i += 2
            i = _consume_quantifier_suffix(s, i, tokens)
            continue

        raise PatternError(
            f"Unexpected character {s[i]!r} at position {i} in pattern {pattern!r}"
        )

    return tokens


def _token_to_regex(token: str) -> bytes:
    """Convert a single token string into its bytes-regex fragment."""

    # Anchors
    if token == "^":
        return b"\\A"
    if token == "$":
        return b"\\Z"

    # Quantifier suffix: recurse on the base token, then reattach + or *
    if token and token[-1] in ("+", "*"):
        return _token_to_regex(token[:-1]) + token[-1].encode("ascii")

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


def _decode_pattern_bytes(s: str) -> bytes:
    """
    Convert a user-typed bytes-regex pattern string to bytes.

    Handles ``\\xNN``, ``\\n``, ``\\r``, ``\\t`` escape sequences.  Used
    when compiling a ``"regex"``-type rule pattern.
    """
    try:
        # unicode_escape handles \\xNN / \\n / \\r / \\t → Unicode code points;
        # latin-1 encodes them back to bytes (works for \\x00–\\xFF).
        return codecs.decode(s, "unicode_escape").encode("latin-1")
    except (ValueError, UnicodeDecodeError, UnicodeEncodeError):
        return s.encode("latin-1", errors="replace")


def _decode_replacement_str(s: str) -> bytes:
    """
    Decode a regex replacement string to bytes for ``re.sub``.

    Interprets ``\\xNN``, ``\\n``, ``\\r``, ``\\t`` as their byte values.
    Keeps ``\\g<N>``, ``\\g<name>``, and ``\\N`` (digit backreferences)
    intact as raw byte sequences so that ``re.sub`` can resolve them.
    """
    result = bytearray()
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            c = s[i + 1]
            if c == "x" and i + 3 < len(s):
                try:
                    result.append(int(s[i + 2 : i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            elif c == "n":
                result.append(0x0A)
                i += 2
                continue
            elif c == "r":
                result.append(0x0D)
                i += 2
                continue
            elif c == "t":
                result.append(0x09)
                i += 2
                continue
            elif c == "\\":
                result.append(ord("\\"))
                result.append(ord("\\"))
                i += 2
                continue
            # \\g<...> and \\N digit backreferences: keep as-is for re.sub
            result.append(ord("\\"))
            result.append(ord(c))
            i += 2
            continue
        result.append(ord(s[i]))
        i += 1
    return bytes(result)


def compile_regex_pattern(pattern_str: str) -> "re.Pattern[bytes]":
    """
    Compile a Python bytes-regex string to a compiled pattern.

    The pattern string uses Python escape sequences (e.g. ``\\x01\\x00``)
    and standard regex metacharacters.  ``re.DOTALL`` is always enabled.

    Raises:
        PatternError: If the compiled regex is invalid.
    """
    try:
        pattern_bytes = _decode_pattern_bytes(pattern_str)
        return re.compile(pattern_bytes, re.DOTALL)
    except re.error as exc:
        raise PatternError(
            f"Invalid regex pattern {pattern_str!r}: {exc}"
        ) from exc


def _load_replace_script(path: str) -> types.ModuleType:
    """Dynamically load a replacement script from *path*."""
    spec = importlib.util.spec_from_file_location("_replace_script", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Cannot create module spec for: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


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
    A find-and-replace rule applied to frame bytes.

    Three rule types are supported, selected by ``rule_type``:

    ``"binary"``
        The original binary hex pattern + hex replacement (see module
        docstring for pattern syntax).  ``pattern_str`` and
        ``replacement`` are used.

    ``"regex"``
        A Python bytes-regex pattern.  ``regex_pattern`` holds the
        pattern string (with ``\\xNN`` escapes) and ``regex_replacement``
        holds the replacement string (may use ``\\g<N>`` backreferences
        and ``\\xNN`` escapes).

    ``"script"``
        A Python script at ``script_path`` that exports an
        ``apply(data: bytes, variables: dict) -> bytes`` function.
        ``variables`` is the shared global variable store; scripts can read
        from or write to it to pass state between pipelines (e.g. save a
        captured token in traffic, then use it in a forge playbook via
        ``{{VAR}}``).

    Scope flags control which pipeline stages apply the rule:

        ``apply_to_traffic`` — relay pipeline (every frame flowing through the
                               proxy, before the tamper controller).  Visible
                               in the Traffic tab.
        ``apply_to_tamper``  — bytes an operator just modified in the Tamper
                               tab, applied after ``Modify+Forward``.
        ``apply_to_forge``   — Forge tab / playbook send (before each send).

    All three default to ``True``.
    """

    id:          str
    label:       str

    # ---- Binary type -------------------------------------------------------
    pattern_str: str   = ""
    replacement: bytes = b""

    # ---- Regex type --------------------------------------------------------
    regex_pattern:     str = ""
    regex_replacement: str = ""

    # ---- Script type -------------------------------------------------------
    script_path: str = ""

    # ---- Common ------------------------------------------------------------
    rule_type:          str              = "binary"   # "binary" | "regex" | "script"
    direction:          Optional[Direction] = None
    enabled:            bool             = True
    created_at:         float            = field(default_factory=time.time)

    # ---- Scope flags -------------------------------------------------------
    apply_to_traffic: bool = True
    apply_to_tamper:  bool = True
    apply_to_forge:   bool = True

    # ---- Runtime (not serialised) -----------------------------------------
    compiled:       Optional["re.Pattern[bytes]"] = field(default=None, repr=False)
    regex_compiled: Optional["re.Pattern[bytes]"] = field(default=None, repr=False)
    _script_module: Optional[types.ModuleType]   = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.rule_type == "binary":
            if self.compiled is None and self.pattern_str:
                self.compiled = compile_binary_pattern(self.pattern_str)
        elif self.rule_type == "regex":
            if self.regex_compiled is None and self.regex_pattern:
                self.regex_compiled = compile_regex_pattern(self.regex_pattern)

    @classmethod
    def create(
        cls,
        label:       str,
        pattern_str: str,
        replacement: bytes,
        direction:   Optional[Direction] = None,
        enabled:     bool = True,
        *,
        rule_type:         str  = "binary",
        regex_pattern:     str  = "",
        regex_replacement: str  = "",
        script_path:       str  = "",
        apply_to_traffic:  bool = True,
        apply_to_tamper:   bool = True,
        apply_to_forge:    bool = True,
    ) -> "ReplaceRule":
        """Factory: generates a unique ID and compiles the pattern."""
        return cls(
            id=str(uuid.uuid4()),
            label=label,
            rule_type=rule_type,
            pattern_str=pattern_str,
            replacement=replacement,
            regex_pattern=regex_pattern,
            regex_replacement=regex_replacement,
            script_path=script_path,
            direction=direction,
            enabled=enabled,
            apply_to_traffic=apply_to_traffic,
            apply_to_tamper=apply_to_tamper,
            apply_to_forge=apply_to_forge,
        )

    # ------------------------------------------------------------------
    # Apply
    # ------------------------------------------------------------------

    def apply(self, data: bytes, scope: Optional[str] = None,
              variables: Optional[dict] = None) -> bytes:
        """
        Apply the substitution to *data*.

        Args:
            data:      The bytes to transform.
            scope:     Optional scope name — ``"traffic"`` (relay pipeline),
                       ``"tamper"`` (after operator Modify+Forward), or
                       ``"forge"`` (Forge/playbook pipeline).  When set and
                       the corresponding ``apply_to_*`` flag is ``False``,
                       the rule is skipped.
            variables: Optional shared global variable store.  Passed to
                       script-type rules so that ``apply(data, variables)``
                       hooks can read and write cross-pipeline state.

        Returns modified bytes, or *data* unchanged if the rule does not
        apply or does not match.
        """
        if not self.enabled:
            return data
        if scope == "traffic" and not self.apply_to_traffic:
            return data
        if scope == "tamper" and not self.apply_to_tamper:
            return data
        if scope == "forge" and not self.apply_to_forge:
            return data

        if self.rule_type == "binary":
            if self.compiled is None:
                return data
            return self.compiled.sub(self.replacement, data)

        elif self.rule_type == "regex":
            if self.regex_compiled is None:
                return data
            repl_bytes = _decode_replacement_str(self.regex_replacement)
            return self.regex_compiled.sub(repl_bytes, data)

        elif self.rule_type == "script":
            return self._apply_script(data, variables if variables is not None else {})

        return data

    def _apply_script(self, data: bytes, variables: dict) -> bytes:
        """
        Run the ``apply(data, variables)`` hook in the configured script.

        ``variables`` is the shared global variable store.  The script may
        read from it (e.g. to use a previously captured sequence number) or
        write to it (e.g. to save a value extracted from traffic for use in
        subsequent frames).  Mutations are visible to all pipelines
        immediately.

        If loading or execution raises any exception, the error is logged,
        the cached module is cleared (so a fixed script reloads automatically
        on the next frame), and the original data is returned unchanged.
        """
        if not self.script_path:
            return data
        if self._script_module is None:
            try:
                self._script_module = _load_replace_script(self.script_path)
            except Exception as exc:
                logger.error(
                    "Replace rule %r: failed to load script %s: %s",
                    self.label, self.script_path, exc,
                )
                return data
        try:
            fn = getattr(self._script_module, "apply", None)
            if fn is None:
                logger.warning(
                    "Replace rule %r: script %s has no apply() function",
                    self.label, self.script_path,
                )
                return data
            result = fn(data, variables)
            if not isinstance(result, (bytes, bytearray)):
                logger.error(
                    "Replace rule %r: apply() returned %s, expected bytes; skipping",
                    self.label, type(result).__name__,
                )
                return data
            return bytes(result)
        except Exception as exc:
            logger.error(
                "Replace rule %r: apply() raised %s: %s; script will reload on next frame",
                self.label, type(exc).__name__, exc,
            )
            # Clear the cache so a fixed script on disk is reloaded automatically.
            self._script_module = None
            return data

    def reset_script_state(self) -> None:
        """
        Unload the cached script module.

        The next call to ``apply()`` will reload the script from disk,
        re-running all module-level initialisation.  Useful when the script
        carries state (e.g. a counter) that the operator wants to reset.
        """
        self._script_module = None

    # ------------------------------------------------------------------
    # Matching (binary / regex only)
    # ------------------------------------------------------------------

    def matches(self, data: bytes) -> bool:
        """Return ``True`` if the pattern matches anywhere in *data*."""
        if self.rule_type == "binary":
            if self.compiled is None:
                return False
            return bool(self.compiled.search(data))
        elif self.rule_type == "regex":
            if self.regex_compiled is None:
                return False
            return bool(self.regex_compiled.search(data))
        return False

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dict."""
        return {
            "id":                self.id,
            "label":             self.label,
            "rule_type":         self.rule_type,
            "pattern_str":       self.pattern_str,
            "replacement":       self.replacement.hex(),
            "regex_pattern":     self.regex_pattern,
            "regex_replacement": self.regex_replacement,
            "script_path":       self.script_path,
            "direction":         self.direction.value if self.direction else None,
            "enabled":           self.enabled,
            "created_at":        self.created_at,
            "apply_to_traffic": self.apply_to_traffic,
            "apply_to_tamper":  self.apply_to_tamper,
            "apply_to_forge":   self.apply_to_forge,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ReplaceRule":
        """Deserialise from a dict produced by ``to_dict()``."""
        direction: Optional[Direction] = None
        if d.get("direction"):
            direction = Direction(d["direction"])
        raw = d.get("replacement", "")
        replacement = bytes.fromhex(raw) if isinstance(raw, str) else bytes(raw)
        return cls(
            id=d["id"],
            label=d["label"],
            rule_type=d.get("rule_type", "binary"),
            pattern_str=d.get("pattern_str", ""),
            replacement=replacement,
            regex_pattern=d.get("regex_pattern", ""),
            regex_replacement=d.get("regex_replacement", ""),
            script_path=d.get("script_path", ""),
            direction=direction,
            enabled=d.get("enabled", True),
            created_at=d.get("created_at", time.time()),
            apply_to_traffic=d.get("apply_to_traffic", d.get("apply_to_intercept", True)),
            apply_to_tamper=d.get("apply_to_tamper", d.get("apply_to_sequence", True)),
            apply_to_forge=d.get("apply_to_forge", d.get("apply_to_repeater", True)),
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
