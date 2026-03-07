"""
Tests for the protocol definition schema and loader.

Covers:
  - Loading from dicts (all field types, match types, displays)
  - Validation errors
  - YAML file loading (skipped if PyYAML not installed)
  - JSON file loading
"""

from __future__ import annotations

import json
import pytest
import tempfile
from pathlib import Path

from tcpproxy.protocol.definition.schema import (
    DirectionFilter,
    DisplayHint,
    FieldType,
    MatchType,
)
from tcpproxy.protocol.definition.loader import load_protocol, load_protocol_file


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_proto(**kwargs) -> dict:
    base = {"name": "TestProto", "endianness": "big", "messages": []}
    base.update(kwargs)
    return base


def make_msg(**kwargs) -> dict:
    base = {"name": "Packet", "match": {"type": "always"}, "fields": []}
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Top-level protocol loading
# ---------------------------------------------------------------------------

def test_load_minimal():
    defn = load_protocol({"name": "Foo"})
    assert defn.name == "Foo"
    assert defn.endianness == "big"
    assert defn.messages == []


def test_load_wrapped_protocol_key():
    raw = {"protocol": {"name": "Bar", "version": "2.0"}}
    defn = load_protocol(raw)
    assert defn.name == "Bar"
    assert defn.version == "2.0"


def test_load_endianness_little():
    defn = load_protocol({"name": "X", "endianness": "little"})
    assert defn.endianness == "little"


def test_invalid_endianness():
    with pytest.raises(ValueError, match="endianness"):
        load_protocol({"name": "X", "endianness": "middle"})


def test_missing_name():
    with pytest.raises(ValueError, match="name"):
        load_protocol({"endianness": "big"})


def test_not_a_dict():
    with pytest.raises(ValueError):
        load_protocol([1, 2, 3])


# ---------------------------------------------------------------------------
# Message definitions
# ---------------------------------------------------------------------------

def test_message_match_always():
    defn = load_protocol(make_proto(messages=[make_msg(name="Pkt")]))
    assert len(defn.messages) == 1
    assert defn.messages[0].match.type is MatchType.ALWAYS


def test_message_match_magic():
    msg = make_msg(match={"type": "magic", "offset": 0, "value": "0x01"})
    defn = load_protocol(make_proto(messages=[msg]))
    rule = defn.messages[0].match
    assert rule.type is MatchType.MAGIC
    assert rule.offset == 0
    assert rule.value == [1]


def test_message_match_magic_multivalue():
    msg = make_msg(match={"type": "magic", "offset": 2, "value": [0x01, 0x02]})
    defn = load_protocol(make_proto(messages=[msg]))
    assert defn.messages[0].match.value == [1, 2]


def test_message_match_magic_hex_string():
    msg = make_msg(match={"type": "magic", "offset": 0, "value": "0x01 0x02 0xFF"})
    defn = load_protocol(make_proto(messages=[msg]))
    assert defn.messages[0].match.value == [1, 2, 255]


def test_message_match_sequence():
    msg = make_msg(match={
        "type": "sequence",
        "direction": "server_to_client",
        "index": 0,
    })
    defn = load_protocol(make_proto(messages=[msg]))
    rule = defn.messages[0].match
    assert rule.type is MatchType.SEQUENCE
    assert rule.direction is DirectionFilter.SERVER_TO_CLIENT
    assert rule.index == 0


def test_message_direction_filter():
    msg = make_msg(direction="client_to_server")
    defn = load_protocol(make_proto(messages=[msg]))
    assert defn.messages[0].direction is DirectionFilter.CLIENT_TO_SERVER


def test_message_missing_name():
    with pytest.raises(ValueError, match="name"):
        load_protocol(make_proto(messages=[{"match": {"type": "always"}, "fields": []}]))


# ---------------------------------------------------------------------------
# Field definitions
# ---------------------------------------------------------------------------

def _load_fields(*field_dicts) -> list:
    msg = make_msg(fields=list(field_dicts))
    defn = load_protocol(make_proto(messages=[msg]))
    return defn.messages[0].fields


def test_field_uint8():
    fields = _load_fields({"name": "opcode", "type": "uint8"})
    assert fields[0].type is FieldType.UINT8


def test_field_uint32():
    fields = _load_fields({"name": "len", "type": "uint32"})
    assert fields[0].type is FieldType.UINT32


def test_field_bytes_with_length():
    fields = _load_fields(
        {"name": "n", "type": "uint16"},
        {"name": "data", "type": "bytes", "length": "{n}"},
    )
    assert fields[1].length == "{n}"


def test_field_bytes_fixed_length():
    fields = _load_fields({"name": "token", "type": "bytes", "length": 16})
    assert fields[0].length == "16"


def test_field_string_null_terminated():
    fields = _load_fields({"name": "s", "type": "string", "null_terminated": True})
    assert fields[0].null_terminated is True


def test_field_display_hex():
    fields = _load_fields({"name": "x", "type": "bytes", "length": 4, "display": "hex"})
    assert fields[0].display is DisplayHint.HEX


def test_field_enum():
    fields = _load_fields({
        "name": "status",
        "type": "uint8",
        "enum": {"0x00": "OK", "0x01": "Error"},
    })
    assert fields[0].enum == {0: "OK", 1: "Error"}


def test_field_tlv_sequence():
    fields = _load_fields({
        "name": "attrs",
        "type": "tlv_sequence",
        "length": "{total - 5}",
        "tlv": {
            "type_size": 2,
            "length_size": 2,
            "endianness": "big",
            "tags": {
                "0x0001": {"name": "ChannelID", "value_type": "uint32"},
                "0x0002": {"name": "Text",      "value_type": "string"},
            },
        },
    })
    tlv = fields[0].tlv
    assert tlv is not None
    assert tlv.type_size == 2
    assert 1 in tlv.tags
    assert tlv.tags[1].name == "ChannelID"
    assert tlv.tags[2].name == "Text"


def test_field_array():
    fields = _load_fields({
        "name": "users",
        "type": "array",
        "array": {
            "count": "{user_count}",
            "item": [
                {"name": "id",   "type": "uint32"},
                {"name": "name", "type": "string", "length": 8},
            ],
        },
    })
    arr = fields[0].array
    assert arr is not None
    assert arr.count == "{user_count}"
    assert len(arr.item) == 2


def test_field_bitfield():
    fields = _load_fields({
        "name": "flags",
        "type": "bitfield",
        "bits": {"0": "online", "1": "away", "2": "admin"},
    })
    bf = fields[0].bitfield
    assert bf is not None
    assert bf.bits[0] == "online"
    assert bf.bits[2] == "admin"


def test_field_unknown_type():
    with pytest.raises(ValueError, match="type"):
        _load_fields({"name": "x", "type": "exotic_future_type"})


# ---------------------------------------------------------------------------
# JSON file loading
# ---------------------------------------------------------------------------

def test_load_json_file(tmp_path: Path):
    data = {
        "name": "JsonProto",
        "messages": [{"name": "Pkt", "match": {"type": "always"}, "fields": []}],
    }
    p = tmp_path / "test.json"
    p.write_text(json.dumps(data))
    defn = load_protocol_file(p)
    assert defn.name == "JsonProto"


def test_load_file_not_found(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_protocol_file(tmp_path / "missing.yaml")


def test_load_unsupported_extension(tmp_path: Path):
    p = tmp_path / "test.toml"
    p.write_text("[foo]")
    with pytest.raises(ValueError, match="extension"):
        load_protocol_file(p)


# ---------------------------------------------------------------------------
# YAML file loading (optional — skip if PyYAML not installed)
# ---------------------------------------------------------------------------

pytest.importorskip("yaml", reason="PyYAML not installed; skipping YAML tests")


def test_load_yaml_file(tmp_path: Path):
    content = """
protocol:
  name: YamlProto
  endianness: little
  messages:
    - name: Ping
      match:
        type: magic
        offset: 0
        value: "0xAA"
      fields:
        - name: opcode
          type: uint8
        - name: seq
          type: uint16
"""
    p = tmp_path / "test.yaml"
    p.write_text(content)
    defn = load_protocol_file(p)
    assert defn.name == "YamlProto"
    assert defn.endianness == "little"
    assert len(defn.messages) == 1
    assert defn.messages[0].match.value == [0xAA]
    assert len(defn.messages[0].fields) == 2
