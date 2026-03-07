"""
Tests for the protocol display renderers (hexdump + field tree).
"""

from __future__ import annotations

import pytest

from tcpproxy.models import Direction, Frame, ParsedField, ParsedMessage
from tcpproxy.protocol.display.hexdump import Highlight, highlights_from_message, render_hexdump
from tcpproxy.protocol.display.tree import render_field_tree, render_frame_header


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _frame(raw: bytes) -> Frame:
    return Frame(
        id="test",
        session_id="sess",
        direction=Direction.CLIENT_TO_SERVER,
        raw_bytes=raw,
        timestamp=1700000000.0,
        sequence_number=3,
        framer_name="raw",
    )


def _field(name: str, value, offset: int, size: int, raw: bytes, dv: str = "") -> ParsedField:
    return ParsedField(
        name=name,
        value=value,
        raw_bytes=raw,
        offset=offset,
        size=size,
        display_hint="auto",
        display_value=dv or str(value),
    )


def _msg(frame: Frame, fields: list[ParsedField], message_type: str = "TestMsg") -> ParsedMessage:
    return ParsedMessage(
        id="pmsg",
        frame=frame,
        protocol_name="TestProto",
        message_type=message_type,
        fields=fields,
    )


# ---------------------------------------------------------------------------
# Hex dump
# ---------------------------------------------------------------------------

class TestHexDump:
    def test_empty(self):
        output = render_hexdump(b"", color=False)
        assert "empty" in output.lower()

    def test_single_row(self):
        data = bytes(range(8))
        output = render_hexdump(data, color=False, width=16)
        assert "00 01 02 03 04 05 06 07" in output
        assert "00000000" in output

    def test_multi_row(self):
        data = bytes(range(24))
        output = render_hexdump(data, color=False, width=16)
        assert "00000000" in output
        assert "00000010" in output

    def test_ascii_printable(self):
        data = b"Hello!"
        output = render_hexdump(data, color=False)
        assert "Hello!" in output

    def test_ascii_non_printable_shown_as_dot(self):
        data = bytes([0x01, 0x41, 0x00])  # SOH, 'A', NUL
        output = render_hexdump(data, color=False)
        # A should appear, 0x01 and 0x00 as dots
        assert ".A." in output

    def test_highlights_no_ansi_when_no_color(self):
        data = b"\x01\x02\x03\x04"
        hl = [Highlight(start=0, end=2, label="hdr", color_code="\033[92m")]
        output = render_hexdump(data, highlights=hl, color=False)
        assert "\033[" not in output

    def test_highlights_with_ansi(self, monkeypatch):
        # Force color on even if not a TTY
        monkeypatch.setenv("FORCE_COLOR", "1")
        data = b"\x01\x02\x03\x04"
        hl = [Highlight(start=0, end=2, label="hdr", color_code="\033[92m")]
        output = render_hexdump(data, highlights=hl, color=True)
        assert "\033[92m" in output

    def test_highlights_from_message(self):
        raw = b"\x01\x00\x05hello"
        frame = _frame(raw)
        fields = [
            _field("opcode",     1,       0, 1, b"\x01"),
            _field("length",     5,       1, 2, b"\x00\x05"),
            _field("payload",    b"hello", 3, 5, b"hello"),
        ]
        msg = _msg(frame, fields)
        hls = highlights_from_message(msg, color=False)
        assert len(hls) == 3
        assert hls[0].start == 0 and hls[0].end == 1
        assert hls[1].start == 1 and hls[1].end == 3
        assert hls[2].start == 3 and hls[2].end == 8

    def test_width_8(self):
        data = bytes(range(10))
        output = render_hexdump(data, color=False, width=8)
        # Should have at least two rows
        lines = [l for l in output.splitlines() if l.strip() and "Offset" not in l and "─" not in l]
        assert len(lines) >= 2

    def test_no_color_env(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        data = b"\x01\x02"
        hl = [Highlight(0, 2, "f", "\033[92m")]
        output = render_hexdump(data, highlights=hl, color=True)
        assert "\033[" not in output


# ---------------------------------------------------------------------------
# Field tree
# ---------------------------------------------------------------------------

class TestFieldTree:
    def test_basic_structure(self):
        raw = b"\x01\x00\x05hello"
        frame = _frame(raw)
        fields = [
            _field("opcode",  1,       0, 1, b"\x01", "0x01"),
            _field("payload", b"hello", 1, 5, b"hello", "hello"),
        ]
        msg = _msg(frame, fields)
        output = render_field_tree(msg, color=False)
        assert "TestMsg" in output
        assert "opcode" in output
        assert "payload" in output
        assert "┌" in output
        assert "└" in output
        assert "│" in output

    def test_error_shown(self):
        raw = b"\x01"
        frame = _frame(raw)
        fields = [_field("opcode", 1, 0, 1, b"\x01", "0x01")]
        msg = ParsedMessage(
            id="x", frame=frame, protocol_name="P", message_type="M",
            fields=fields, error="Truncated at byte 1",
        )
        output = render_field_tree(msg, color=False)
        assert "Truncated" in output

    def test_nested_children(self):
        raw = b"\x01\x00\x00\x01\x00\x04" + b"\xDE\xAD\xBE\xEF"
        frame = _frame(raw)
        child = ParsedField(
            name="ChannelID", value=42, raw_bytes=b"\xDE\xAD\xBE\xEF",
            offset=6, size=4, display_hint="decimal", display_value="42",
        )
        parent = ParsedField(
            name="attrs", value=[child], raw_bytes=raw[1:],
            offset=1, size=len(raw)-1, display_hint="auto",
            display_value="(1 TLV entries)", children=[child],
        )
        opcode = _field("opcode", 1, 0, 1, b"\x01", "0x01")
        msg = _msg(frame, [opcode, parent])
        output = render_field_tree(msg, color=False)
        assert "attrs" in output
        assert "ChannelID" in output
        assert "├" in output or "└" in output

    def test_long_values_truncated(self):
        raw = b"x" * 100
        frame = _frame(raw)
        fields = [_field("data", raw, 0, 100, raw, "x" * 100)]
        msg = _msg(frame, fields)
        output = render_field_tree(msg, color=False)
        # Should not exceed width
        for line in output.splitlines():
            assert len(line) <= 80, f"Line too long: {len(line)}"


class TestFrameHeader:
    def test_basic(self):
        raw = b"\x01\x02"
        frame = _frame(raw)
        output = render_frame_header(frame)
        assert "C→S" in output
        assert "3" in output       # sequence_number
        assert "2 bytes" in output

    def test_with_message(self):
        raw = b"\x01"
        frame = _frame(raw)
        fields = [_field("opcode", 1, 0, 1, b"\x01", "0x01")]
        msg = _msg(frame, fields, message_type="LoginRequest")
        output = render_frame_header(frame, msg)
        assert "LoginRequest" in output
        assert "TestProto" in output

    def test_server_direction(self):
        raw = b"\x02"
        frame = Frame(
            id="t", session_id="s", direction=Direction.SERVER_TO_CLIENT,
            raw_bytes=raw, timestamp=0.0, sequence_number=1, framer_name="raw",
        )
        output = render_frame_header(frame)
        assert "S→C" in output

    def test_error_indicated(self):
        raw = b"\x01"
        frame = _frame(raw)
        fields = [_field("opcode", 1, 0, 1, b"\x01")]
        msg = ParsedMessage(
            id="x", frame=frame, protocol_name="P", message_type="M",
            fields=fields, error="Something went wrong",
        )
        output = render_frame_header(frame, msg)
        assert "partial" in output or "⚠" in output
