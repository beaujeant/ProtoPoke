"""
Serialise a ``ProtocolDefinition`` (and its children) back to a plain dict.

The loader (:mod:`protopoke.protocol.definition.loader`) is the inverse —
it consumes a dict and produces typed dataclasses.  Round-tripping through
``protocol_to_dict`` → ``load_protocol`` MUST be lossless for everything the
parser actually uses.

Used by:
    * MCP tools that let an AI introspect / save the current protocol.
    * ``save_protocol_to_file`` (writes YAML or JSON).
"""

from __future__ import annotations

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


def protocol_to_dict(defn: ProtocolDefinition) -> dict:
    """Serialise a full ``ProtocolDefinition`` to a JSON-compatible dict."""
    return {
        "name":       defn.name,
        "version":    defn.version,
        "endianness": defn.endianness,
        "messages":   [message_to_dict(m) for m in defn.messages],
    }


def message_to_dict(msg: MessageDefinition) -> dict:
    """Serialise a ``MessageDefinition``."""
    d: dict = {
        "name":      msg.name,
        "direction": msg.direction.value,
        "match":     match_to_dict(msg.match),
        "fields":    [field_to_dict(f) for f in msg.fields],
    }
    if msg.description:
        d["description"] = msg.description
    return d


def match_to_dict(m: MatchRule) -> dict:
    """Serialise a ``MatchRule`` in a form the loader accepts."""
    if m.type is MatchType.MAGIC:
        return {
            "type":   "magic",
            "offset": m.offset,
            "value":  list(m.value),
        }
    if m.type is MatchType.SEQUENCE:
        return {
            "type":      "sequence",
            "direction": m.direction.value,
            "index":     m.index,
        }
    return {"type": "always"}


def field_to_dict(f: FieldDefinition) -> dict:
    """Serialise a ``FieldDefinition``."""
    d: dict = {
        "name": f.name,
        "type": f.type.value,
    }
    if f.length is not None:
        d["length"] = f.length
    if f.null_terminated:
        d["null_terminated"] = True
    if f.encoding != "utf8":
        d["encoding"] = f.encoding
    if f.display is not DisplayHint.AUTO:
        d["display"] = f.display.value
    if f.enum:
        d["enum"] = {str(k): v for k, v in f.enum.items()}
    if f.tlv is not None:
        d["tlv"] = _tlv_to_dict(f.tlv)
    if f.array is not None:
        d["array"] = _array_to_dict(f.array)
    if f.bitfield is not None:
        d["bits"] = {str(k): v for k, v in f.bitfield.bits.items()}
    return d


def _tlv_to_dict(t: TLVConfig) -> dict:
    return {
        "type_size":   t.type_size,
        "length_size": t.length_size,
        "endianness":  t.endianness,
        "tags":        {
            str(k): _tlv_tag_to_dict(v) for k, v in t.tags.items()
        },
    }


def _tlv_tag_to_dict(t: TLVTagDefinition) -> dict:
    d: dict = {"name": t.name, "value_type": t.value_type.value}
    if t.encoding != "utf8":
        d["encoding"] = t.encoding
    if t.display is not DisplayHint.AUTO:
        d["display"] = t.display.value
    return d


def _array_to_dict(a: ArrayConfig) -> dict:
    return {
        "count": a.count,
        "item":  [field_to_dict(f) for f in a.item],
    }
