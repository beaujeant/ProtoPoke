"""
Protocol definition loader.

Loads a ProtocolDefinition from:
  - A YAML file          (load_protocol_file("myproto.yaml"))
  - A JSON file          (load_protocol_file("myproto.json"))
  - A raw dict           (load_protocol(d))

YAML support requires PyYAML.  If not installed, YAML files raise ImportError
with a helpful message.  JSON files and dict loading work without extra deps.

The loader converts the raw dict structure into typed ProtocolDefinition
dataclasses and raises ValueError with descriptive messages on bad input.

Value coercions performed by the loader:

  match.value:
      Accepts any of the common notations used in protocol specs:
        "0x01"         → [1]
        [0x01, 0x02]   → [1, 2]
        "0x01 0x02"    → [1, 2]
        1              → [1]

  field.length:
      Normalised to a string.  Int 4 → "4",  str "{n}" → "{n}", -1 → "-1".

  field.type:
      Case-insensitive: "UINT8" == "uint8".

  field.display:
      Case-insensitive: "HEX" == "hex".  Unknown values fall back to "auto".

  tlv.tags:
      Keys accepted as int (0x0001) or hex string ("0x0001" / "1").
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .schema import (
    ArrayConfig,
    BitfieldConfig,
    DirectionFilter,
    DisplayHint,
    FieldDefinition,
    FieldType,
    MatchRule,
    MatchType,
    MessageDefinition,
    ProtocolDefinition,
    TLVConfig,
    TLVTagDefinition,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_protocol_file(path: str | Path) -> ProtocolDefinition:
    """
    Load a ProtocolDefinition from a YAML or JSON file.

    Args:
        path: Path to a .yaml, .yml, or .json file.

    Returns:
        Validated ProtocolDefinition.

    Raises:
        FileNotFoundError: path does not exist.
        ImportError:       YAML file but PyYAML not installed.
        ValueError:        File contents are invalid.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Protocol definition file not found: {path}")

    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "PyYAML is required to load .yaml protocol definitions. "
                "Install it with:  pip install pyyaml"
            ) from exc
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    elif suffix == ".json":
        with path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
    else:
        raise ValueError(
            f"Unsupported file extension {suffix!r}. Use .yaml, .yml, or .json."
        )

    return load_protocol(raw, source=str(path))


def load_protocol(raw: dict, source: str = "<dict>") -> ProtocolDefinition:
    """
    Load a ProtocolDefinition from a raw dict (already parsed from YAML/JSON).

    Args:
        raw:    The raw dict, typically the top-level YAML/JSON mapping.
                May have a top-level "protocol:" key (wrapping style) or
                be the protocol dict directly.
        source: Descriptive label used in error messages.

    Returns:
        Validated ProtocolDefinition.

    Raises:
        ValueError: raw is invalid in any way.
    """
    if not isinstance(raw, dict):
        raise ValueError(f"[{source}] Protocol definition must be a YAML/JSON object, got {type(raw).__name__}")

    # Support both `{protocol: {name: ...}}` and `{name: ...}` at root
    if "protocol" in raw and isinstance(raw["protocol"], dict):
        raw = raw["protocol"]

    return _parse_protocol(raw, source)


# ---------------------------------------------------------------------------
# Internal parsers
# ---------------------------------------------------------------------------

def _parse_protocol(d: dict, source: str) -> ProtocolDefinition:
    name = _req_str(d, "name", source)
    version    = _opt_str(d, "version",    "1.0")
    endianness = _opt_str(d, "endianness", "big").lower()
    if endianness not in ("big", "little"):
        raise ValueError(f"[{source}] endianness must be 'big' or 'little', got {endianness!r}")

    raw_msgs = d.get("messages", [])
    if not isinstance(raw_msgs, list):
        raise ValueError(f"[{source}] 'messages' must be a list")

    messages = [
        _parse_message(m, i, source)
        for i, m in enumerate(raw_msgs)
    ]

    return ProtocolDefinition(
        name=name,
        version=version,
        endianness=endianness,
        messages=messages,
    )


def _parse_message(d: dict, idx: int, source: str) -> MessageDefinition:
    ctx = f"{source}:messages[{idx}]"
    name = _req_str(d, "name", ctx)

    description = _opt_str(d, "description", "")
    direction   = _parse_direction(d.get("direction", "both"), ctx)
    match       = _parse_match(d.get("match", {"type": "always"}), ctx)

    raw_fields = d.get("fields", [])
    if not isinstance(raw_fields, list):
        raise ValueError(f"[{ctx}] 'fields' must be a list")

    fields = [_parse_field(f, i, ctx) for i, f in enumerate(raw_fields)]

    return MessageDefinition(
        name=name,
        description=description,
        direction=direction,
        match=match,
        fields=fields,
    )


def _parse_match(d: Any, ctx: str) -> MatchRule:
    if not isinstance(d, dict):
        raise ValueError(f"[{ctx}] 'match' must be a dict, got {type(d).__name__}")

    match_type_raw = d.get("type", "always").lower()
    try:
        match_type = MatchType(match_type_raw)
    except ValueError:
        raise ValueError(
            f"[{ctx}] match.type must be one of "
            f"{[t.value for t in MatchType]}, got {match_type_raw!r}"
        )

    if match_type is MatchType.MAGIC:
        offset = int(d.get("offset", 0))
        raw_val = d.get("value")
        if raw_val is None:
            raise ValueError(f"[{ctx}] match.value is required for type=magic")
        value = _parse_magic_value(raw_val, ctx)
        return MatchRule(type=match_type, offset=offset, value=value)

    elif match_type is MatchType.SEQUENCE:
        direction = _parse_direction(d.get("direction", "both"), ctx)
        index     = int(d.get("index", 0))
        return MatchRule(type=match_type, direction=direction, index=index)

    else:  # ALWAYS
        return MatchRule(type=match_type)


def _parse_field(d: Any, idx: int, ctx: str) -> FieldDefinition:
    # Fields can be inline dicts like {name: x, type: uint8}
    if not isinstance(d, dict):
        raise ValueError(f"[{ctx}:fields[{idx}]] field must be a dict")

    fctx = f"{ctx}:fields[{idx}]"
    name = _req_str(d, "name", fctx)

    type_raw = d.get("type", "bytes").lower().replace("-", "_")
    try:
        ftype = FieldType(type_raw)
    except ValueError:
        raise ValueError(
            f"[{fctx}] field type {type_raw!r} is not recognised. "
            f"Valid types: {[t.value for t in FieldType]}"
        )

    # Length normalisation
    raw_length = d.get("length", None)
    length: Optional[str] = None
    if raw_length is not None:
        length = str(raw_length)   # int 4 → "4", str "{n}" → "{n}"

    null_terminated = bool(d.get("null_terminated", False))
    encoding        = _opt_str(d, "encoding", "utf8")

    display_raw = d.get("display", "auto").lower()
    try:
        display = DisplayHint(display_raw)
    except ValueError:
        display = DisplayHint.AUTO

    # Enum mapping: keys can be int or hex string
    raw_enum = d.get("enum", {})
    enum_map: dict[int, str] = {}
    if isinstance(raw_enum, dict):
        for k, v in raw_enum.items():
            enum_map[_parse_int_key(k, fctx)] = str(v)

    tlv     = _parse_tlv_config(d.get("tlv", None), fctx) if ftype is FieldType.TLV_SEQUENCE else None
    array   = _parse_array_config(d.get("array", None), fctx) if ftype is FieldType.ARRAY else None
    bitfield = _parse_bitfield_config(d.get("bits", None), fctx) if ftype is FieldType.BITFIELD else None

    return FieldDefinition(
        name=name,
        type=ftype,
        length=length,
        null_terminated=null_terminated,
        encoding=encoding,
        display=display,
        enum=enum_map,
        tlv=tlv,
        array=array,
        bitfield=bitfield,
    )


def _parse_tlv_config(d: Any, ctx: str) -> TLVConfig:
    if d is None:
        return TLVConfig()
    if not isinstance(d, dict):
        raise ValueError(f"[{ctx}] tlv must be a dict")

    type_size   = int(d.get("type_size",   1))
    length_size = int(d.get("length_size", 2))
    endianness  = _opt_str(d, "endianness", "big").lower()

    if type_size not in (1, 2, 4):
        raise ValueError(f"[{ctx}] tlv.type_size must be 1, 2, or 4; got {type_size}")
    if length_size not in (1, 2, 4):
        raise ValueError(f"[{ctx}] tlv.length_size must be 1, 2, or 4; got {length_size}")

    raw_tags = d.get("tags", {})
    tags: dict[int, TLVTagDefinition] = {}
    if isinstance(raw_tags, dict):
        for k, v in raw_tags.items():
            tag_int = _parse_int_key(k, ctx)
            if not isinstance(v, dict):
                raise ValueError(f"[{ctx}] tlv.tags[{k}] must be a dict")
            tag_name   = _req_str(v, "name", f"{ctx}:tag[{k}]")
            vtype_raw  = v.get("value_type", "bytes").lower()
            try:
                vtype = FieldType(vtype_raw)
            except ValueError:
                vtype = FieldType.BYTES
            tenc    = _opt_str(v, "encoding", "utf8")
            disp_raw = v.get("display", "auto").lower()
            try:
                tdisp = DisplayHint(disp_raw)
            except ValueError:
                tdisp = DisplayHint.AUTO
            tags[tag_int] = TLVTagDefinition(
                name=tag_name, value_type=vtype, encoding=tenc, display=tdisp
            )

    return TLVConfig(
        type_size=type_size,
        length_size=length_size,
        endianness=endianness,
        tags=tags,
    )


def _parse_array_config(d: Any, ctx: str) -> ArrayConfig:
    if d is None:
        raise ValueError(f"[{ctx}] array field type requires an 'array' config dict")
    if not isinstance(d, dict):
        raise ValueError(f"[{ctx}] array must be a dict")

    raw_count = d.get("count")
    if raw_count is None:
        raise ValueError(f"[{ctx}] array.count is required")
    count = str(raw_count)

    raw_item = d.get("item", [])
    if not isinstance(raw_item, list):
        raise ValueError(f"[{ctx}] array.item must be a list of field defs")
    item = [_parse_field(f, i, f"{ctx}:array.item") for i, f in enumerate(raw_item)]

    return ArrayConfig(count=count, item=item)


def _parse_bitfield_config(d: Any, ctx: str) -> BitfieldConfig:
    if d is None:
        return BitfieldConfig()
    if not isinstance(d, dict):
        raise ValueError(f"[{ctx}] bits must be a dict of bit-index → name")
    bits: dict[int, str] = {}
    for k, v in d.items():
        bits[int(k)] = str(v)
    return BitfieldConfig(bits=bits)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _req_str(d: dict, key: str, ctx: str) -> str:
    val = d.get(key)
    if val is None:
        raise ValueError(f"[{ctx}] required key {key!r} is missing")
    return str(val)


def _opt_str(d: dict, key: str, default: str) -> str:
    val = d.get(key, default)
    return str(val) if val is not None else default


def _parse_direction(raw: Any, ctx: str) -> DirectionFilter:
    if raw is None:
        return DirectionFilter.BOTH
    val = str(raw).lower().replace("-", "_")
    try:
        return DirectionFilter(val)
    except ValueError:
        # Accept short forms
        if val in ("c2s", "client"):
            return DirectionFilter.CLIENT_TO_SERVER
        if val in ("s2c", "server"):
            return DirectionFilter.SERVER_TO_CLIENT
        raise ValueError(
            f"[{ctx}] direction must be 'both', 'client_to_server', or "
            f"'server_to_client'; got {raw!r}"
        )


def _parse_magic_value(raw: Any, ctx: str) -> list[int]:
    """Convert the many accepted magic-value notations into list[int]."""
    if isinstance(raw, int):
        return [raw]
    if isinstance(raw, list):
        return [_parse_single_byte(v, ctx) for v in raw]
    if isinstance(raw, str):
        parts = raw.split()
        return [_parse_single_byte(p, ctx) for p in parts]
    raise ValueError(f"[{ctx}] match.value must be an int, list, or hex string; got {type(raw).__name__}")


def _parse_single_byte(v: Any, ctx: str) -> int:
    if isinstance(v, int):
        b = v
    elif isinstance(v, str):
        try:
            b = int(v, 0)   # handles "0x01", "1", "0b1", etc.
        except ValueError:
            raise ValueError(f"[{ctx}] cannot parse byte value {v!r}")
    else:
        raise ValueError(f"[{ctx}] byte value must be int or str, got {type(v).__name__}")
    if not 0 <= b <= 255:
        raise ValueError(f"[{ctx}] byte value {b} is out of range 0-255")
    return b


def _parse_int_key(k: Any, ctx: str) -> int:
    if isinstance(k, int):
        return k
    try:
        return int(str(k), 0)
    except ValueError:
        raise ValueError(f"[{ctx}] cannot parse integer key {k!r}")
