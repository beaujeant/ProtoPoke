"""
Per-type field parsers.

Each `parse_*` function takes:
  - `data`:      the full frame bytes
  - `offset`:    current byte offset within `data`
  - `field_def`: the FieldDefinition describing what to parse
  - `context`:   dict of field_name → int value built from previously parsed fields
  - `endianness`: "big" or "little"

And returns a `ParsedField` with the decoded value, raw bytes, offset, and size.

Composite types (TLV_SEQUENCE, ARRAY, BITFIELD) produce ParsedField.children.

Errors:
    ParseError is raised on truncated data or invalid field definitions.
    The engine wraps it in a partial ParsedMessage with error set.
"""

from __future__ import annotations

import struct
from typing import Any

from ...models import ParsedField
from ..definition.schema import (
    DisplayHint,
    FieldDefinition,
    FieldType,
    TLVConfig,
    TLVTagDefinition,
)
from .expression import evaluate


class ParseError(Exception):
    """Raised when a field cannot be parsed due to truncated or malformed data."""


# ---------------------------------------------------------------------------
# Integer type descriptors
# ---------------------------------------------------------------------------

# Maps FieldType → (struct format char, byte count)
_INT_FORMATS: dict[FieldType, tuple[str, int]] = {
    FieldType.UINT8:   ("B", 1),
    FieldType.UINT16:  ("H", 2),
    FieldType.UINT32:  ("I", 4),
    FieldType.UINT64:  ("Q", 8),
    FieldType.INT8:    ("b", 1),
    FieldType.INT16:   ("h", 2),
    FieldType.INT32:   ("i", 4),
    FieldType.INT64:   ("q", 8),
    FieldType.FLOAT32: ("f", 4),
    FieldType.FLOAT64: ("d", 8),
}


# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------

def parse_field(
    data:       bytes,
    offset:     int,
    field_def:  FieldDefinition,
    context:    dict[str, int],
    endianness: str = "big",
) -> ParsedField:
    """
    Dispatch to the appropriate parser based on field_def.type.

    Returns a ParsedField.  Raises ParseError on truncated data.
    """
    ftype = field_def.type

    if ftype in _INT_FORMATS:
        return _parse_integer(data, offset, field_def, context, endianness)

    if ftype is FieldType.BYTES:
        return _parse_bytes(data, offset, field_def, context)

    if ftype is FieldType.STRING:
        return _parse_string(data, offset, field_def, context)

    if ftype is FieldType.PADDING:
        return _parse_padding(data, offset, field_def, context)

    if ftype is FieldType.BITFIELD:
        return _parse_bitfield(data, offset, field_def, context, endianness)

    if ftype is FieldType.ARRAY:
        return _parse_array(data, offset, field_def, context, endianness)

    if ftype is FieldType.TLV_SEQUENCE:
        return _parse_tlv_sequence(data, offset, field_def, context, endianness)

    raise ParseError(f"Unhandled field type {ftype!r}")


# ---------------------------------------------------------------------------
# Scalar parsers
# ---------------------------------------------------------------------------

def _parse_integer(
    data:       bytes,
    offset:     int,
    field_def:  FieldDefinition,
    context:    dict[str, int],
    endianness: str,
) -> ParsedField:
    fmt_char, size = _INT_FORMATS[field_def.type]
    endian_char = ">" if endianness == "big" else "<"
    fmt = endian_char + fmt_char

    _require(data, offset, size, field_def.name)
    raw = data[offset : offset + size]
    (value,) = struct.unpack_from(fmt, raw)

    display_hint, display_value = _display_int(value, field_def)
    return ParsedField(
        name=field_def.name,
        value=value,
        raw_bytes=raw,
        offset=offset,
        size=size,
        display_hint=display_hint,
        display_value=display_value,
    )


def _parse_bytes(
    data:      bytes,
    offset:    int,
    field_def: FieldDefinition,
    context:   dict[str, int],
) -> ParsedField:
    length = _resolve_length(field_def, context, data, offset)
    _require(data, offset, length, field_def.name)
    raw = data[offset : offset + length]

    hint = field_def.display if field_def.display is not DisplayHint.AUTO else DisplayHint.HEX
    display_value = _hex_str(raw)
    return ParsedField(
        name=field_def.name,
        value=raw,
        raw_bytes=raw,
        offset=offset,
        size=length,
        display_hint=hint.value,
        display_value=display_value,
    )


def _parse_string(
    data:      bytes,
    offset:    int,
    field_def: FieldDefinition,
    context:   dict[str, int],
) -> ParsedField:
    if field_def.null_terminated:
        # Scan for NUL, optionally bounded by max length
        end = offset
        max_len = None
        if field_def.length is not None:
            max_len = _resolve_length(field_def, context, data, offset)
        limit = offset + max_len if max_len is not None else len(data)
        while end < limit and data[end] != 0:
            end += 1
        raw_str = data[offset:end]
        size = end - offset + (1 if end < len(data) and data[end] == 0 else 0)
        raw = data[offset : offset + size]
    else:
        length = _resolve_length(field_def, context, data, offset)
        _require(data, offset, length, field_def.name)
        raw = data[offset : offset + length]
        raw_str = raw
        size = length

    encoding = field_def.encoding or "utf8"
    try:
        value = raw_str.decode(encoding, errors="replace")
    except Exception:
        value = raw_str.decode("latin-1", errors="replace")

    hint = field_def.display if field_def.display is not DisplayHint.AUTO else DisplayHint.ASCII
    return ParsedField(
        name=field_def.name,
        value=value,
        raw_bytes=raw,
        offset=offset,
        size=size,
        display_hint=hint.value,
        display_value=repr(value) if "\x00" in value else value,
    )


def _parse_padding(
    data:      bytes,
    offset:    int,
    field_def: FieldDefinition,
    context:   dict[str, int],
) -> ParsedField:
    length = _resolve_length(field_def, context, data, offset)
    _require(data, offset, length, field_def.name)
    raw = data[offset : offset + length]
    return ParsedField(
        name=field_def.name,
        value=None,
        raw_bytes=raw,
        offset=offset,
        size=length,
        display_hint="hex",
        display_value=f"({length} padding bytes)",
    )


# ---------------------------------------------------------------------------
# Composite parsers
# ---------------------------------------------------------------------------

def _parse_bitfield(
    data:       bytes,
    offset:     int,
    field_def:  FieldDefinition,
    context:    dict[str, int],
    endianness: str,
) -> ParsedField:
    """Parse a BITFIELD — an integer with named bits as children."""
    # The underlying integer type is inferred from the length if set,
    # or defaults to uint8.
    if field_def.length is not None:
        size = _resolve_length(field_def, context, data, offset)
    else:
        size = 1

    _require(data, offset, size, field_def.name)
    raw = data[offset : offset + size]
    endian_char = ">" if endianness == "big" else "<"
    fmt_map = {1: "B", 2: "H", 4: "I", 8: "Q"}
    fmt_char = fmt_map.get(size, "B")
    (int_val,) = struct.unpack_from(endian_char + fmt_char, raw)

    children: list[ParsedField] = []
    if field_def.bitfield:
        for bit_idx, bit_name in sorted(field_def.bitfield.bits.items()):
            bit_val = (int_val >> bit_idx) & 1
            children.append(ParsedField(
                name=bit_name,
                value=bit_val,
                raw_bytes=raw,
                offset=offset,
                size=size,
                display_hint="decimal",
                display_value=str(bit_val),
            ))

    return ParsedField(
        name=field_def.name,
        value=int_val,
        raw_bytes=raw,
        offset=offset,
        size=size,
        display_hint="hex",
        display_value=f"0x{int_val:0{size*2}X}",
        children=children,
    )


def _parse_array(
    data:       bytes,
    offset:     int,
    field_def:  FieldDefinition,
    context:    dict[str, int],
    endianness: str,
) -> ParsedField:
    """Parse an ARRAY — repeated sub-structure."""
    if not field_def.array:
        raise ParseError(f"Field {field_def.name!r} is type ARRAY but has no array config")

    count = evaluate(field_def.array.count, context)
    start_offset = offset
    children: list[ParsedField] = []

    for i in range(count):
        item_children: list[ParsedField] = []
        item_context = dict(context)
        item_offset = offset

        for sub_def in field_def.array.item:
            sub_field = parse_field(data, offset, sub_def, item_context, endianness)
            item_children.append(sub_field)
            if isinstance(sub_field.value, (int, float)):
                item_context[sub_def.name] = int(sub_field.value)
            offset += sub_field.size

        item_raw = data[item_offset:offset]
        children.append(ParsedField(
            name=f"[{i}]",
            value=item_children,
            raw_bytes=item_raw,
            offset=item_offset,
            size=offset - item_offset,
            display_hint="auto",
            display_value="",
            children=item_children,
        ))

    total_raw = data[start_offset:offset]
    return ParsedField(
        name=field_def.name,
        value=children,
        raw_bytes=total_raw,
        offset=start_offset,
        size=offset - start_offset,
        display_hint="auto",
        display_value=f"({count} items)",
        children=children,
    )


def _parse_tlv_sequence(
    data:       bytes,
    offset:     int,
    field_def:  FieldDefinition,
    context:    dict[str, int],
    endianness: str,
) -> ParsedField:
    """Parse a TLV_SEQUENCE — a series of Type-Length-Value triples."""
    cfg: TLVConfig = field_def.tlv or TLVConfig()

    # Determine the byte range for the TLV block
    if field_def.length is not None:
        total_len = _resolve_length(field_def, context, data, offset)
        if total_len == -1:
            end = len(data)
        else:
            end = offset + total_len
    else:
        end = len(data)

    end = min(end, len(data))
    start_offset = offset
    endian_char = ">" if cfg.endianness == "big" else "<"

    t_fmt = {1: "B", 2: "H", 4: "I"}[cfg.type_size]
    l_fmt = {1: "B", 2: "H", 4: "I"}[cfg.length_size]
    tl_size = cfg.type_size + cfg.length_size

    children: list[ParsedField] = []

    while offset + tl_size <= end:
        tag_raw = data[offset : offset + cfg.type_size]
        (tag_int,) = struct.unpack_from(endian_char + t_fmt, tag_raw)

        len_raw = data[offset + cfg.type_size : offset + tl_size]
        (val_len,) = struct.unpack_from(endian_char + l_fmt, len_raw)

        val_offset = offset + tl_size
        if val_offset + val_len > end:
            # Truncated TLV — capture as-is
            val_len = end - val_offset

        val_raw = data[val_offset : val_offset + val_len]

        tag_def: TLVTagDefinition | None = cfg.tags.get(tag_int)

        if tag_def is not None:
            tag_name = tag_def.name
            value, dv = _decode_tlv_value(val_raw, tag_def, endianness)
            disp = tag_def.display.value if tag_def.display is not DisplayHint.AUTO else "hex"
        else:
            tag_name = f"tag_0x{tag_int:0{cfg.type_size*2}X}"
            value = val_raw
            dv = _hex_str(val_raw)
            disp = "hex"

        children.append(ParsedField(
            name=tag_name,
            value=value,
            raw_bytes=data[offset : val_offset + val_len],
            offset=offset,
            size=tl_size + val_len,
            display_hint=disp,
            display_value=f"[0x{tag_int:0{cfg.type_size*2}X}] {dv}",
        ))

        offset = val_offset + val_len

    total_raw = data[start_offset:offset]
    return ParsedField(
        name=field_def.name,
        value=children,
        raw_bytes=total_raw,
        offset=start_offset,
        size=offset - start_offset,
        display_hint="auto",
        display_value=f"({len(children)} TLV entries)",
        children=children,
    )


# ---------------------------------------------------------------------------
# Encoding helpers (for re-assembly during replay)
# ---------------------------------------------------------------------------

def encode_field(
    field_def:  FieldDefinition,
    value:      Any,
    context:    dict[str, int],
    endianness: str = "big",
) -> bytes:
    """
    Encode a single field value back to bytes.

    Used by DefinitionBasedEncoder when producing modified frames.

    Args:
        field_def:  The field definition describing the type and encoding.
        value:      The Python value to encode (int, str, bytes, etc.)
        context:    Previously encoded field values for length calculations.
        endianness: Byte order for integers.

    Returns:
        Bytes representing the encoded field.

    Raises:
        ValueError: value cannot be encoded as the specified type.
    """
    ftype = field_def.type
    endian_char = ">" if endianness == "big" else "<"

    if ftype in _INT_FORMATS:
        fmt_char, size = _INT_FORMATS[ftype]
        return struct.pack(endian_char + fmt_char, int(value))

    if ftype is FieldType.BYTES:
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        if isinstance(value, str):
            return bytes.fromhex(value.replace(" ", ""))
        raise ValueError(f"Cannot encode {type(value).__name__} as bytes")

    if ftype is FieldType.STRING:
        if isinstance(value, str):
            encoded = value.encode(field_def.encoding or "utf8")
        elif isinstance(value, (bytes, bytearray)):
            encoded = bytes(value)
        else:
            raise ValueError(f"Cannot encode {type(value).__name__} as string")
        if field_def.null_terminated:
            encoded += b"\x00"
        return encoded

    if ftype is FieldType.PADDING:
        length = _resolve_length(field_def, context, b"", 0)
        return b"\x00" * length

    # For composite types, fall back to raw bytes if that's what we have
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)

    raise ValueError(f"Cannot encode field type {ftype!r}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolve_length(
    field_def: FieldDefinition,
    context:   dict[str, int],
    data:      bytes,
    offset:    int,
) -> int:
    if field_def.length is None:
        raise ParseError(
            f"Field {field_def.name!r} has no length specified and "
            f"type {field_def.type!r} requires one"
        )
    length = evaluate(field_def.length, context)
    if length == -1:
        return len(data) - offset
    return length


def _require(data: bytes, offset: int, size: int, name: str) -> None:
    if offset + size > len(data):
        raise ParseError(
            f"Truncated data parsing field {name!r}: "
            f"need {size} bytes at offset {offset}, "
            f"but frame is only {len(data)} bytes"
        )


def _display_int(value: int, field_def: FieldDefinition) -> tuple[str, str]:
    """Return (display_hint, display_value) for an integer field."""
    hint = field_def.display

    if hint is DisplayHint.AUTO:
        if field_def.enum:
            # If an enum map is defined, default to enum display
            hint = DisplayHint.ENUM
        else:
            # For single-byte fields, show hex; otherwise decimal
            _, size = _INT_FORMATS.get(field_def.type, ("", 1))
            hint = DisplayHint.HEX if size == 1 else DisplayHint.DECIMAL

    if hint is DisplayHint.ENUM and field_def.enum:
        label = field_def.enum.get(value, f"<unknown: 0x{value:X}>")
        return "enum", label

    if hint is DisplayHint.HEX:
        _, size = _INT_FORMATS.get(field_def.type, ("", 1))
        return "hex", f"0x{value:0{size*2}X}"

    return hint.value, str(value)


def _hex_str(data: bytes) -> str:
    if not data:
        return "(empty)"
    if len(data) <= 32:
        return data.hex(" ").upper()
    return data[:32].hex(" ").upper() + f" … ({len(data)} bytes)"


def _decode_tlv_value(
    raw: bytes,
    tag_def: TLVTagDefinition,
    endianness: str,
) -> tuple[Any, str]:
    """Decode a TLV value according to its tag definition."""
    endian_char = ">" if endianness == "big" else "<"
    vtype = tag_def.value_type

    if vtype in _INT_FORMATS:
        fmt_char, expected_size = _INT_FORMATS[vtype]
        if len(raw) == expected_size:
            (v,) = struct.unpack(endian_char + fmt_char, raw)
            return v, str(v)
        return raw, _hex_str(raw)

    if vtype is FieldType.STRING:
        try:
            v = raw.decode(tag_def.encoding or "utf8", errors="replace")
        except Exception:
            v = raw.decode("latin-1", errors="replace")
        return v, v

    # BYTES or anything else
    return raw, _hex_str(raw)
