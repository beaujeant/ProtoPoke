"""
Conversion utilities between the two frame-editing representations.

HEX mode
--------
Space-separated hex pairs, with optional ``{{VAR}}`` placeholder tokens
as whole whitespace-delimited tokens (sequencer steps only).

    01 02 {{SESS_ID}} 48 65 6c 6c 6f

STR mode
--------
Python-like string: printable ASCII shown as characters, everything else
as ``\\xNN``.  ``\\n`` / ``\\r`` / ``\\t`` / ``\\\\`` are supported.
Sequencer placeholders are embedded inline.

    \\x01\\x02{{SESS_ID}}Hello

Escaping rule for STR mode
--------------------------
``{{`` is the start of a placeholder.  If the raw data contains the two
bytes ``7b 7b`` (i.e. the characters ``{{``), write the first brace as
``\\x7b`` so the parser does not mistake it for a placeholder::

    \\x7b{anything}   →  bytes  7b 7b ...

The helpers below apply this rule automatically when converting hex → str.
A lone ``{`` is always literal (only ``{{`` is special).
"""

from __future__ import annotations

import re

# Matches a complete inline placeholder: {{NAME}} or {{NAME:transform}}
# The content must not contain unbalanced braces.
_PLACEHOLDER_INLINE_RE = re.compile(r"\{\{([^{}]+)\}\}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _byte_to_str_char(b: int, next_b: int | None) -> str:
    """Encode one byte for STR-mode output."""
    if b == 0x5c:   # backslash
        return "\\\\"
    if b == 0x0a:
        return "\\n"
    if b == 0x0d:
        return "\\r"
    if b == 0x09:
        return "\\t"
    if b == 0x00:
        return "\\0"
    # Printable ASCII 0x20–0x7e
    if 0x20 <= b <= 0x7e:
        # Escape the first '{' when followed by another '{' to prevent '{{' being
        # read as a placeholder start on the way back.
        if b == 0x7b and next_b == 0x7b:
            return "\\x7b"
        return chr(b)
    return f"\\x{b:02x}"


# ---------------------------------------------------------------------------
# Sequencer template conversions  (hex-template  ↔  STR-template)
# ---------------------------------------------------------------------------

def hex_template_to_str(hex_template: str) -> str:
    """
    Convert a HEX-mode sequencer template to STR mode.

    Placeholder tokens such as ``{{SESS_ID}}`` are passed through unchanged.
    Hex-pair tokens are decoded and re-encoded as a python-like string.

    Args:
        hex_template: Space-separated hex pairs / placeholder tokens.

    Returns:
        STR-mode string ready to display in the editor.
    """
    tokens = hex_template.split()
    result_parts: list[str] = []
    byte_buf: list[int] = []

    def flush() -> None:
        if not byte_buf:
            return
        chars: list[str] = []
        for i, b in enumerate(byte_buf):
            nxt = byte_buf[i + 1] if i + 1 < len(byte_buf) else None
            chars.append(_byte_to_str_char(b, nxt))
        result_parts.append("".join(chars))
        byte_buf.clear()

    for tok in tokens:
        if tok.startswith("{{") and tok.endswith("}}"):
            flush()
            result_parts.append(tok)
        else:
            try:
                byte_buf.append(int(tok, 16))
            except ValueError:
                # Non-hex, non-placeholder token — pass through unchanged
                flush()
                result_parts.append(tok)

    flush()
    return "".join(result_parts)


def str_to_hex_template(s: str) -> str:
    """
    Parse a STR-mode sequencer template and return the HEX-mode representation.

    Supported escapes: ``\\xNN``, ``\\n``, ``\\r``, ``\\t``, ``\\\\``, ``\\0``.

    To write a literal ``{{`` (bytes ``7b 7b``) without triggering a placeholder,
    escape the first brace: ``\\x7b{``.

    Args:
        s: STR-mode template string from the editor.

    Returns:
        HEX-mode template: space-separated hex pairs / placeholder tokens.

    Raises:
        ValueError: On invalid escape sequences or malformed ``{{`` sequences.
    """
    hex_tokens: list[str] = []
    byte_buf: list[int] = []
    i = 0

    def flush() -> None:
        for b in byte_buf:
            hex_tokens.append(f"{b:02x}")
        byte_buf.clear()

    while i < len(s):
        # --- placeholder: {{...}} ---
        if s[i : i + 2] == "{{":
            m = _PLACEHOLDER_INLINE_RE.match(s, i)
            if m:
                flush()
                hex_tokens.append(m.group(0))   # single whitespace token
                i = m.end()
                continue
            raise ValueError(
                f"'{{{{' at position {i} does not form a valid placeholder "
                f"'{{{{NAME}}}}' or '{{{{NAME:transform}}}}'.  "
                f"To write literal '{{{{', use '\\x7b{{' instead."
            )

        # --- backslash escapes ---
        if s[i] == "\\":
            if i + 1 >= len(s):
                raise ValueError("Trailing backslash at end of string.")
            c = s[i + 1]
            if c in ("x", "X"):
                if i + 3 >= len(s):
                    raise ValueError(f"Incomplete \\x escape at position {i}.")
                hex_part = s[i + 2 : i + 4]
                try:
                    byte_buf.append(int(hex_part, 16))
                except ValueError:
                    raise ValueError(
                        f"Invalid \\x escape '\\x{hex_part}' at position {i}."
                    )
                i += 4
            elif c == "n":
                byte_buf.append(0x0A)
                i += 2
            elif c == "r":
                byte_buf.append(0x0D)
                i += 2
            elif c == "t":
                byte_buf.append(0x09)
                i += 2
            elif c == "\\":
                byte_buf.append(0x5C)
                i += 2
            elif c == "0":
                byte_buf.append(0x00)
                i += 2
            else:
                raise ValueError(
                    f"Unknown escape '\\{c}' at position {i}.  "
                    f"Supported: \\xNN, \\n, \\r, \\t, \\\\, \\0"
                )
            continue

        # --- regular character ---
        byte_buf.append(ord(s[i]))
        i += 1

    flush()
    return " ".join(hex_tokens)


# ---------------------------------------------------------------------------
# Plain bytes conversions  (bytes  ↔  STR)  — used by intercept / repeater
# ---------------------------------------------------------------------------

def bytes_to_str(data: bytes) -> str:
    """Encode raw *data* as a python-like STR string (no placeholder support)."""
    chars: list[str] = []
    for i, b in enumerate(data):
        nxt = data[i + 1] if i + 1 < len(data) else None
        chars.append(_byte_to_str_char(b, nxt))
    return "".join(chars)


def str_to_bytes(s: str) -> bytes:
    """
    Parse a python-like STR string to bytes (no placeholder support).

    Raises:
        ValueError: If the string contains ``{{...}}`` placeholders or
                    invalid escape sequences.
    """
    hex_tmpl = str_to_hex_template(s)
    if "{{" in hex_tmpl:
        raise ValueError(
            "Placeholder {{...}} found in a non-template editor.  "
            "Variable substitution is only supported in Sequencer steps."
        )
    hex_clean = hex_tmpl.replace(" ", "")
    return bytes.fromhex(hex_clean) if hex_clean else b""


# ---------------------------------------------------------------------------
# Convenience: convert plain hex-pair string  ↔  STR  (no placeholders)
# ---------------------------------------------------------------------------

def hex_pairs_to_str(hex_str: str) -> str:
    """Convert plain space-separated hex pairs to STR mode (no placeholders)."""
    hex_clean = hex_str.replace(" ", "").replace("\n", "")
    if not hex_clean:
        return ""
    return bytes_to_str(bytes.fromhex(hex_clean))


def str_to_hex_pairs(s: str) -> str:
    """Parse STR mode (no placeholders) and return space-separated hex pairs."""
    data = str_to_bytes(s)
    return " ".join(f"{b:02x}" for b in data)
