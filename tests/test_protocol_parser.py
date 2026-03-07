"""
Tests for the protocol parser: expression evaluator, field parsers,
message matcher, and the full DefinitionBasedDecoder/Encoder.
"""

from __future__ import annotations

import struct
import pytest

from protopoke.models import Direction, Frame, ParsedField
from protopoke.protocol.definition.loader import load_protocol
from protopoke.protocol.definition.schema import (
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
from protopoke.protocol.parser.engine import DefinitionBasedDecoder, DefinitionBasedEncoder
from protopoke.protocol.parser.expression import evaluate
from protopoke.protocol.parser.fields import ParseError, parse_field
from protopoke.protocol.parser.matcher import MessageMatcher


# ---------------------------------------------------------------------------
# Expression evaluator
# ---------------------------------------------------------------------------

class TestExpressionEvaluator:
    def test_plain_integer(self):
        assert evaluate("4", {}) == 4

    def test_negative_integer(self):
        assert evaluate("-1", {}) == -1

    def test_field_reference(self):
        assert evaluate("{n}", {"n": 7}) == 7

    def test_arithmetic(self):
        assert evaluate("{a + b}", {"a": 10, "b": 3}) == 13
        assert evaluate("{a - b}", {"a": 10, "b": 3}) == 7
        assert evaluate("{a * b}", {"a": 4, "b": 5}) == 20
        assert evaluate("{total - 5}", {"total": 20}) == 15

    def test_nested_arithmetic(self):
        assert evaluate("{(a + b) * c}", {"a": 2, "b": 3, "c": 4}) == 20

    def test_safe_builtins(self):
        assert evaluate("{min(a, b)}", {"a": 3, "b": 7}) == 3
        assert evaluate("{max(a, b)}", {"a": 3, "b": 7}) == 7
        assert evaluate("{abs(n)}", {"n": -5}) == 5

    def test_undefined_name(self):
        with pytest.raises(ValueError, match="Undefined name"):
            evaluate("{missing}", {})

    def test_unsafe_import(self):
        with pytest.raises(ValueError, match="Unsafe"):
            evaluate("{__import__('os')}", {})

    def test_unsafe_attribute(self):
        with pytest.raises(ValueError, match="Unsafe"):
            evaluate("{x.y}", {"x": 1})

    def test_bad_format(self):
        with pytest.raises(ValueError, match="expression"):
            evaluate("not_a_number_and_no_braces", {})


# ---------------------------------------------------------------------------
# Field parsers — scalar
# ---------------------------------------------------------------------------

def _make_field(name="f", ftype=FieldType.UINT8, length=None, **kwargs) -> FieldDefinition:
    return FieldDefinition(name=name, type=ftype, length=str(length) if length is not None else None, **kwargs)


class TestScalarParsers:
    def test_uint8(self):
        data = bytes([0x42])
        pf = parse_field(data, 0, _make_field(ftype=FieldType.UINT8), {})
        assert pf.value == 0x42
        assert pf.size == 1
        assert pf.offset == 0
        assert pf.raw_bytes == b"\x42"

    def test_uint16_big(self):
        data = struct.pack(">H", 1000)
        pf = parse_field(data, 0, _make_field(ftype=FieldType.UINT16), {}, "big")
        assert pf.value == 1000
        assert pf.size == 2

    def test_uint16_little(self):
        data = struct.pack("<H", 1000)
        pf = parse_field(data, 0, _make_field(ftype=FieldType.UINT16), {}, "little")
        assert pf.value == 1000

    def test_uint32(self):
        data = struct.pack(">I", 0xDEADBEEF)
        pf = parse_field(data, 0, _make_field(ftype=FieldType.UINT32), {})
        assert pf.value == 0xDEADBEEF
        assert pf.size == 4

    def test_int16_signed(self):
        data = struct.pack(">h", -1000)
        pf = parse_field(data, 0, _make_field(ftype=FieldType.INT16), {})
        assert pf.value == -1000

    def test_bytes_fixed(self):
        data = b"\xDE\xAD\xBE\xEF"
        fd = _make_field(ftype=FieldType.BYTES, length=4)
        pf = parse_field(data, 0, fd, {})
        assert pf.value == b"\xDE\xAD\xBE\xEF"
        assert pf.size == 4

    def test_bytes_from_context(self):
        data = b"\x00\x03" + b"abc"
        # Parse length field first, then bytes
        len_fd = _make_field(name="n", ftype=FieldType.UINT16)
        len_pf = parse_field(data, 0, len_fd, {})
        context = {"n": len_pf.value}
        str_fd = _make_field(name="s", ftype=FieldType.BYTES, length="{n}")
        str_pf = parse_field(data, 2, str_fd, context)
        assert str_pf.value == b"abc"
        assert str_pf.size == 3

    def test_bytes_rest_of_frame(self):
        data = b"\x01\x02\x03\x04"
        fd = _make_field(ftype=FieldType.BYTES, length=-1)
        pf = parse_field(data, 1, fd, {})
        assert pf.value == b"\x02\x03\x04"
        assert pf.size == 3

    def test_string_utf8(self):
        s = "héllo"
        encoded = s.encode("utf8")
        fd = FieldDefinition(name="s", type=FieldType.STRING, length=str(len(encoded)), encoding="utf8")
        pf = parse_field(encoded, 0, fd, {})
        assert pf.value == s

    def test_string_null_terminated(self):
        data = b"hello\x00extra"
        fd = FieldDefinition(name="s", type=FieldType.STRING, null_terminated=True)
        pf = parse_field(data, 0, fd, {})
        assert pf.value == "hello"
        assert pf.size == 6  # includes the NUL

    def test_truncated_raises(self):
        data = b"\x01"
        fd = _make_field(ftype=FieldType.UINT32)
        with pytest.raises(ParseError, match="Truncated"):
            parse_field(data, 0, fd, {})

    def test_enum_display(self):
        data = bytes([0x01])
        fd = FieldDefinition(
            name="status",
            type=FieldType.UINT8,
            display=DisplayHint.ENUM,
            enum={0x00: "OK", 0x01: "Error"},
        )
        pf = parse_field(data, 0, fd, {})
        assert pf.display_value == "Error"
        assert pf.display_hint == "enum"


class TestBitfieldParser:
    def test_bitfield(self):
        data = bytes([0b00000101])  # bits 0 and 2 set
        fd = FieldDefinition(
            name="flags",
            type=FieldType.BITFIELD,
            bitfield=BitfieldConfig(bits={0: "online", 1: "away", 2: "admin"}),
        )
        pf = parse_field(data, 0, fd, {})
        assert pf.value == 0b00000101
        children = {c.name: c.value for c in pf.children}
        assert children["online"] == 1
        assert children["away"] == 0
        assert children["admin"] == 1


class TestArrayParser:
    def test_array(self):
        # 2 users: each is uint32 id + uint8 name_len + name bytes
        users = b""
        users += struct.pack(">I", 1) + bytes([5]) + b"alice"
        users += struct.pack(">I", 2) + bytes([3]) + b"bob"
        data = struct.pack(">H", 2) + users

        count_fd = FieldDefinition(name="user_count", type=FieldType.UINT16)
        count_pf = parse_field(data, 0, count_fd, {})
        context = {"user_count": count_pf.value}

        arr_fd = FieldDefinition(
            name="users",
            type=FieldType.ARRAY,
            array=ArrayConfig(
                count="{user_count}",
                item=[
                    FieldDefinition(name="id",       type=FieldType.UINT32),
                    FieldDefinition(name="name_len",  type=FieldType.UINT8),
                    FieldDefinition(name="name",      type=FieldType.STRING, length="{name_len}"),
                ],
            ),
        )
        arr_pf = parse_field(data, 2, arr_fd, context)
        assert len(arr_pf.children) == 2
        names = [c.children[2].value for c in arr_pf.children]
        assert names == ["alice", "bob"]


class TestTLVParser:
    def _make_tlv(self, type_val: int, value: bytes, type_size=2, length_size=2) -> bytes:
        return (
            type_val.to_bytes(type_size, "big") +
            len(value).to_bytes(length_size, "big") +
            value
        )

    def test_tlv_sequence(self):
        tlv_data = (
            self._make_tlv(0x0001, struct.pack(">I", 42)) +   # ChannelID = 42
            self._make_tlv(0x0002, b"general")                 # Text = "general"
        )
        fd = FieldDefinition(
            name="attrs",
            type=FieldType.TLV_SEQUENCE,
            length=str(len(tlv_data)),
            tlv=TLVConfig(
                type_size=2,
                length_size=2,
                tags={
                    0x0001: TLVTagDefinition(name="ChannelID", value_type=FieldType.UINT32),
                    0x0002: TLVTagDefinition(name="Text",      value_type=FieldType.STRING),
                },
            ),
        )
        pf = parse_field(tlv_data, 0, fd, {})
        assert len(pf.children) == 2
        assert pf.children[0].name == "ChannelID"
        assert pf.children[0].value == 42
        assert pf.children[1].name == "Text"
        assert pf.children[1].value == "general"

    def test_unknown_tlv_tag(self):
        tlv_data = self._make_tlv(0xFFFF, b"\xDE\xAD")
        fd = FieldDefinition(
            name="attrs",
            type=FieldType.TLV_SEQUENCE,
            length=str(len(tlv_data)),
            tlv=TLVConfig(type_size=2, length_size=2, tags={}),
        )
        pf = parse_field(tlv_data, 0, fd, {})
        assert len(pf.children) == 1
        assert "FFFF" in pf.children[0].name.upper()
        assert pf.children[0].value == b"\xDE\xAD"


# ---------------------------------------------------------------------------
# Message Matcher
# ---------------------------------------------------------------------------

def _frame(raw: bytes, direction=Direction.CLIENT_TO_SERVER, seq=0) -> Frame:
    return Frame(
        id="test",
        session_id="sess",
        direction=direction,
        raw_bytes=raw,
        timestamp=0.0,
        sequence_number=seq,
        framer_name="raw",
    )


class TestMessageMatcher:
    def _msg(self, name, match_rule, direction=DirectionFilter.BOTH) -> MessageDefinition:
        return MessageDefinition(name=name, match=match_rule, direction=direction)

    def test_magic_match(self):
        msgs = [
            self._msg("Login", MatchRule(type=MatchType.MAGIC, offset=0, value=[0x01])),
            self._msg("Data",  MatchRule(type=MatchType.MAGIC, offset=0, value=[0x10])),
        ]
        m = MessageMatcher(msgs)
        assert m.match(_frame(b"\x01\x00\x05"), 0).name == "Login"
        assert m.match(_frame(b"\x10\x00\x05"), 0).name == "Data"
        assert m.match(_frame(b"\xFF\x00\x05"), 0) is None

    def test_magic_offset(self):
        msgs = [self._msg("X", MatchRule(type=MatchType.MAGIC, offset=2, value=[0xAB]))]
        m = MessageMatcher(msgs)
        assert m.match(_frame(b"\x00\x00\xAB"), 0).name == "X"
        assert m.match(_frame(b"\x00\xAB\x00"), 0) is None

    def test_magic_direction_filter(self):
        msgs = [
            self._msg("CS", MatchRule(type=MatchType.MAGIC, offset=0, value=[0x01]),
                      direction=DirectionFilter.CLIENT_TO_SERVER),
        ]
        m = MessageMatcher(msgs)
        assert m.match(_frame(b"\x01", Direction.CLIENT_TO_SERVER), 0).name == "CS"
        assert m.match(_frame(b"\x01", Direction.SERVER_TO_CLIENT), 0) is None

    def test_sequence_match(self):
        msgs = [
            self._msg("First",  MatchRule(type=MatchType.SEQUENCE, index=0)),
            self._msg("Second", MatchRule(type=MatchType.SEQUENCE, index=1)),
        ]
        m = MessageMatcher(msgs)
        assert m.match(_frame(b"\x00"), 0).name == "First"
        assert m.match(_frame(b"\x00"), 1).name == "Second"
        assert m.match(_frame(b"\x00"), 2) is None

    def test_sequence_direction_filter(self):
        msgs = [
            self._msg("Banner", MatchRule(
                type=MatchType.SEQUENCE,
                direction=DirectionFilter.SERVER_TO_CLIENT,
                index=0,
            )),
        ]
        m = MessageMatcher(msgs)
        assert m.match(_frame(b"\x00", Direction.SERVER_TO_CLIENT), 0).name == "Banner"
        assert m.match(_frame(b"\x00", Direction.CLIENT_TO_SERVER), 0) is None

    def test_always_match(self):
        msgs = [self._msg("Catch", MatchRule(type=MatchType.ALWAYS))]
        m = MessageMatcher(msgs)
        assert m.match(_frame(b"\xFF"), 99).name == "Catch"

    def test_first_match_wins(self):
        msgs = [
            self._msg("First",  MatchRule(type=MatchType.ALWAYS)),
            self._msg("Second", MatchRule(type=MatchType.ALWAYS)),
        ]
        m = MessageMatcher(msgs)
        assert m.match(_frame(b"\x00"), 0).name == "First"


# ---------------------------------------------------------------------------
# DefinitionBasedDecoder integration
# ---------------------------------------------------------------------------

CHAT_PROTO_DICT = {
    "name": "ChatProto",
    "endianness": "big",
    "messages": [
        {
            "name": "LoginRequest",
            "direction": "client_to_server",
            "match": {"type": "magic", "offset": 0, "value": "0x01"},
            "fields": [
                {"name": "opcode",       "type": "uint8"},
                {"name": "username_len", "type": "uint16"},
                {"name": "username",     "type": "string", "length": "{username_len}", "encoding": "utf8"},
                {"name": "password_len", "type": "uint16"},
                {"name": "password",     "type": "bytes",  "length": "{password_len}", "display": "hex"},
            ],
        },
        {
            "name": "LoginResponse",
            "direction": "server_to_client",
            "match": {"type": "magic", "offset": 0, "value": "0x02"},
            "fields": [
                {"name": "opcode",  "type": "uint8"},
                {"name": "status",  "type": "uint8",
                 "enum": {"0x00": "Success", "0x01": "Bad creds"}},
                {"name": "token",   "type": "bytes", "length": 4, "display": "hex"},
            ],
        },
        {
            "name": "Unknown",
            "match": {"type": "always"},
            "fields": [{"name": "raw", "type": "bytes", "length": -1}],
        },
    ],
}


def _build_login_request(username: str, password: bytes) -> bytes:
    uname = username.encode("utf8")
    return (
        b"\x01" +
        len(uname).to_bytes(2, "big") +
        uname +
        len(password).to_bytes(2, "big") +
        password
    )


def _make_frame(raw: bytes, direction=Direction.CLIENT_TO_SERVER, session="sess", seq=0) -> Frame:
    return Frame(
        id="f1",
        session_id=session,
        direction=direction,
        raw_bytes=raw,
        timestamp=0.0,
        sequence_number=seq,
        framer_name="raw",
    )


class TestDefinitionBasedDecoder:
    def setup_method(self):
        defn = load_protocol(CHAT_PROTO_DICT)
        self.decoder = DefinitionBasedDecoder(defn)

    def test_decode_login_request(self):
        raw = _build_login_request("admin", b"secret")
        msg = self.decoder.decode(_make_frame(raw))
        assert msg.message_type == "LoginRequest"
        assert msg.protocol_name == "ChatProto"
        assert msg.error is None
        fields = {f.name: f.value for f in msg.fields}
        assert fields["opcode"] == 1
        assert fields["username_len"] == 5
        assert fields["username"] == "admin"
        assert fields["password"] == b"secret"

    def test_decode_login_response(self):
        raw = b"\x02\x00\xAA\xBB\xCC\xDD"
        msg = self.decoder.decode(_make_frame(raw, direction=Direction.SERVER_TO_CLIENT))
        assert msg.message_type == "LoginResponse"
        fields = {f.name: f.value for f in msg.fields}
        assert fields["status"] == 0
        assert fields["token"] == b"\xAA\xBB\xCC\xDD"

    def test_status_enum_display(self):
        raw = b"\x02\x01\xAA\xBB\xCC\xDD"
        msg = self.decoder.decode(_make_frame(raw, direction=Direction.SERVER_TO_CLIENT))
        status_field = msg.field_by_name("status")
        assert status_field.display_value == "Bad creds"

    def test_unknown_opcode_falls_through_to_always(self):
        raw = b"\xFF\x01\x02\x03"
        msg = self.decoder.decode(_make_frame(raw))
        assert msg.message_type == "Unknown"

    def test_sequence_counter_increments(self):
        raw_a = b"\xFF\x01"
        raw_b = b"\xFF\x02"
        msg_a = self.decoder.decode(_make_frame(raw_a, seq=0))
        msg_b = self.decoder.decode(_make_frame(raw_b, seq=1))
        # Both match Unknown (always), sequence counter advances
        assert msg_a.message_type == "Unknown"
        assert msg_b.message_type == "Unknown"

    def test_parsed_field_offset_and_size(self):
        raw = _build_login_request("ab", b"pw")
        msg = self.decoder.decode(_make_frame(raw))
        opcode = msg.field_by_name("opcode")
        assert opcode.offset == 0
        assert opcode.size == 1
        uname_len = msg.field_by_name("username_len")
        assert uname_len.offset == 1
        assert uname_len.size == 2
        uname = msg.field_by_name("username")
        assert uname.offset == 3
        assert uname.size == 2

    def test_truncated_graceful(self):
        raw = b"\x01"  # opcode only, rest missing
        msg = self.decoder.decode(_make_frame(raw))
        assert msg.error is not None
        assert "opcode" in [f.name for f in msg.fields]

    def test_as_dict(self):
        raw = _build_login_request("user", b"pass")
        msg = self.decoder.decode(_make_frame(raw))
        d = msg.as_dict()
        assert d["username"] == "user"

    def test_reset_session(self):
        # Should not raise
        self.decoder.reset_session("nonexistent")
        raw = _build_login_request("a", b"b")
        self.decoder.decode(_make_frame(raw, session="s1"))
        self.decoder.reset_session("s1")


# ---------------------------------------------------------------------------
# DefinitionBasedEncoder integration
# ---------------------------------------------------------------------------

class TestDefinitionBasedEncoder:
    def setup_method(self):
        defn = load_protocol(CHAT_PROTO_DICT)
        self.decoder = DefinitionBasedDecoder(defn)
        self.encoder = DefinitionBasedEncoder(defn)

    def test_round_trip(self):
        original = _build_login_request("admin", b"secret")
        msg = self.decoder.decode(_make_frame(original))
        encoded = self.encoder.encode(msg)
        assert encoded == original

    def test_edit_string_field(self):
        original = _build_login_request("admin", b"secret")
        msg = self.decoder.decode(_make_frame(original))
        encoded = self.encoder.encode_with_edits(msg, {"username": "hacker"})
        # Parse it back
        msg2 = self.decoder.decode(_make_frame(encoded, session="s2"))
        fields = {f.name: f.value for f in msg2.fields}
        assert fields["username"] == "hacker"
        # username_len should be auto-recomputed
        assert fields["username_len"] == len("hacker")

    def test_edit_bytes_field(self):
        original = _build_login_request("admin", b"secret")
        msg = self.decoder.decode(_make_frame(original))
        new_pass = b"newpassword"
        encoded = self.encoder.encode_with_edits(msg, {"password": new_pass})
        msg2 = self.decoder.decode(_make_frame(encoded, session="s3"))
        fields = {f.name: f.value for f in msg2.fields}
        assert fields["password"] == new_pass
        assert fields["password_len"] == len(new_pass)

    def test_unknown_message_type_raw_fallback(self):
        raw = b"\xFF\x01\x02"
        msg = self.decoder.decode(_make_frame(raw, session="s4"))
        encoded = self.encoder.encode(msg)
        assert encoded == raw
