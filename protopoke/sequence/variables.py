"""
Variable substitution for {{VAR}} placeholders in sequence hex templates.

Placeholder syntax (embedded as whitespace-separated tokens in a hex template):

    {{VARNAME}}
        Direct substitution — replaces the token with the raw bytes stored
        under VARNAME in the variable store (hex-encoded).

    {{VARNAME:uint8_add(1)}}
    {{VARNAME:uint16le_add(1)}}
    {{VARNAME:uint16be_add(1)}}
    {{VARNAME:uint32le_add(1)}}
    {{VARNAME:uint32be_add(1)}}
    {{VARNAME:uint64le_add(1)}}
    {{VARNAME:uint64be_add(1)}}
        Decode the stored bytes as the given unsigned integer type, apply the
        arithmetic (add, sub, or xor), re-encode, and substitute.

    {{VARNAME:xor(ff)}}
        XOR every byte of the variable with the single hex byte argument.

    {{VARNAME:script(value[::-1])}}
        Evaluate the Python expression with ``value`` bound to the variable's
        bytes.  The expression must return ``bytes``.

Variable store format
---------------------
Variables are stored as ``dict[str, str]`` where the value is the
hex-encoded bytes representation (e.g. ``{"SESS_ID": "deadbeef"}``).
This makes them trivially serialisable to JSON/YAML without encoding issues.
"""

from __future__ import annotations

import re
import struct
from typing import Dict

# Matches a complete placeholder token: {{NAME}} or {{NAME:transform}}
# The token must be the *entire* whitespace-separated token in the hex template.
_PLACEHOLDER_RE = re.compile(r"^\{\{([^{}]+)\}\}$")


def resolve_hex(raw_hex: str, variables: Dict[str, str]) -> bytes:
    """
    Resolve all ``{{VAR}}`` placeholders in *raw_hex* and return the final bytes.

    The hex string is split on whitespace.  Each token is either:
      - A 2-character hex pair  → kept as-is.
      - A ``{{NAME[:{transform}]}}`` placeholder → replaced with the variable's
        bytes (after optional transform), expanded as space-separated hex pairs.

    Args:
        raw_hex:   Space-separated hex pairs with optional placeholders.
        variables: Mapping of variable name → hex-encoded bytes value.

    Returns:
        The resolved bytes.

    Raises:
        ValueError: If a placeholder references an undefined variable,
                    a transform is malformed, or the final hex is invalid.
    """
    tokens = raw_hex.split()
    resolved: list[str] = []

    for token in tokens:
        m = _PLACEHOLDER_RE.match(token)
        if m:
            inner = m.group(1)
            hex_bytes = _resolve_placeholder(inner, variables)
            # Expand: "deadbeef" → ["de", "ad", "be", "ef"]
            resolved.extend(hex_bytes[i : i + 2] for i in range(0, len(hex_bytes), 2))
        else:
            resolved.append(token)

    hex_str = "".join(resolved)
    try:
        return bytes.fromhex(hex_str)
    except ValueError as exc:
        raise ValueError(f"Invalid hex after placeholder resolution: {exc}") from exc


def _resolve_placeholder(inner: str, variables: Dict[str, str]) -> str:
    """
    Resolve one placeholder (the text between the ``{{`` and ``}}`` delimiters).

    Returns:
        Hex string of the resolved (and optionally transformed) bytes.

    Raises:
        ValueError: Unknown variable or malformed transform.
    """
    if ":" in inner:
        name, transform = inner.split(":", 1)
    else:
        name, transform = inner, ""

    name = name.strip()
    transform = transform.strip()

    if name not in variables:
        raise ValueError(
            f"Sequence variable '{{{{ {name} }}}}' is not defined. "
            f"Define it in the variable store or capture it via the script."
        )

    raw_hex = variables[name]
    raw_bytes = bytes.fromhex(raw_hex)

    if not transform:
        return raw_hex

    result = _apply_transform(raw_bytes, transform)
    return result.hex()


# ---------------------------------------------------------------------------
# Transform implementations
# ---------------------------------------------------------------------------

#: Supported integer encodings: name → (struct_fmt, byte_size)
_INT_ENCODINGS: dict[str, tuple[str, int]] = {
    "uint8":    (">B", 1),
    "uint16le": ("<H", 2),
    "uint16be": (">H", 2),
    "uint32le": ("<I", 4),
    "uint32be": (">I", 4),
    "uint64le": ("<Q", 8),
    "uint64be": (">Q", 8),
}

# Matches: uint32be_add(1), uint16le_sub(10), uint8_xor(0xff), …
_INT_TRANSFORM_RE = re.compile(
    r"^(uint(?:8|16|32|64)(?:le|be)?)_(add|sub|xor)\(([^)]+)\)$"
)

# Matches: xor(ff) — XOR every byte with a single byte value
_XOR_RE = re.compile(r"^xor\(([0-9a-fA-F]{1,2})\)$")

# Matches: script(expr) — arbitrary Python expression
_SCRIPT_RE = re.compile(r"^script\((.+)\)$", re.DOTALL)


def _apply_transform(value: bytes, transform: str) -> bytes:
    """Apply *transform* to *value* and return the result bytes."""

    # Integer arithmetic: uint32be_add(1), uint16le_xor(0xff), …
    m = _INT_TRANSFORM_RE.match(transform)
    if m:
        encoding, op, arg_str = m.group(1), m.group(2), m.group(3)
        try:
            arg = int(arg_str, 0)   # handles 10, 0xff, 0b1010, etc.
        except ValueError:
            raise ValueError(
                f"Transform argument must be an integer, got: {arg_str!r}"
            )
        return _int_transform(value, encoding, op, arg)

    # Single-byte XOR: xor(ff)
    m = _XOR_RE.match(transform)
    if m:
        mask = int(m.group(1), 16)
        return bytes(b ^ mask for b in value)

    # Inline Python expression: script(value[::-1])
    m = _SCRIPT_RE.match(transform)
    if m:
        expr = m.group(1).strip()
        _safe_globals: dict = {"__builtins__": {}}
        _safe_locals: dict = {"value": value, "bytes": bytes, "bytearray": bytearray,
                              "int": int, "struct": struct, "len": len}
        try:
            result = eval(expr, _safe_globals, _safe_locals)  # noqa: S307
        except Exception as exc:
            raise ValueError(f"Script transform raised an error: {exc}") from exc
        if not isinstance(result, (bytes, bytearray)):
            raise ValueError(
                f"Script transform must return bytes or bytearray, "
                f"got {type(result).__name__}"
            )
        return bytes(result)

    raise ValueError(
        f"Unknown transform: {transform!r}. "
        f"Supported: uint{{8|16|32|64}}{{le|be}}_{{add|sub|xor}}(n), "
        f"xor(hex), script(expr)"
    )


def _int_transform(value: bytes, encoding: str, op: str, arg: int) -> bytes:
    """Decode *value* as *encoding*, apply *op* with *arg*, re-encode."""
    if encoding not in _INT_ENCODINGS:
        raise ValueError(
            f"Unknown integer encoding: {encoding!r}. "
            f"Valid: {', '.join(_INT_ENCODINGS)}"
        )
    fmt, size = _INT_ENCODINGS[encoding]
    if len(value) != size:
        raise ValueError(
            f"Variable has {len(value)} byte(s) but {encoding} requires {size}"
        )
    (n,) = struct.unpack(fmt, value)
    mask = (1 << (size * 8)) - 1
    if op == "add":
        n = (n + arg) & mask
    elif op == "sub":
        n = (n - arg) & mask
    elif op == "xor":
        n = n ^ arg
    return struct.pack(fmt, n)
