"""Tests for the Sequence feature."""

from __future__ import annotations

import struct
from typing import List

import pytest

from protopoke.sequence.models import HistoryEntry, SequenceSession, SequenceFrame
from protopoke.sequence.variables import resolve_hex
from protopoke.sequence.engine import SequenceEngine


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestSequenceFrame:
    def test_create_defaults(self):
        frame = SequenceFrame.create()
        assert frame.label == ""
        assert frame.raw_hex == ""
        assert len(frame.id) == 36  # UUID4

    def test_byte_length_plain(self):
        frame = SequenceFrame.create(raw_hex="01 02 03 04")
        assert frame.byte_length() == 4

    def test_byte_length_with_placeholder(self):
        frame = SequenceFrame.create(raw_hex="01 {{SESS_ID}} 02")
        # placeholder contributes 0, only 01 and 02 count
        assert frame.byte_length() == 2

    def test_preview_truncates(self):
        frame = SequenceFrame.create(raw_hex=" ".join(["aa"] * 20))
        preview = frame.preview(max_bytes=12)
        assert "…" in preview

    def test_preview_includes_placeholder(self):
        frame = SequenceFrame.create(raw_hex="01 {{SESS_ID}} 02")
        preview = frame.preview()
        assert "{{SESS_ID}}" in preview

    def test_roundtrip(self):
        frame = SequenceFrame.create(label="Login", raw_hex="01 02 {{SESS_ID}} 03")
        restored = SequenceFrame.from_dict(frame.to_dict())
        assert restored.id == frame.id
        assert restored.label == frame.label
        assert restored.raw_hex == frame.raw_hex


# ---------------------------------------------------------------------------
# HistoryEntry
# ---------------------------------------------------------------------------

class TestHistoryEntry:
    def test_create_sent(self):
        entry = HistoryEntry.create_sent(b"\x01\x02", "Login")
        assert entry.direction == "sent"
        assert entry.raw_bytes == b"\x01\x02"
        assert entry.frame_label == "Login"

    def test_create_received(self):
        entry = HistoryEntry.create_received(b"\x61\x62")
        assert entry.direction == "received"
        assert entry.raw_bytes == b"\x61\x62"

    def test_roundtrip(self):
        entry = HistoryEntry.create_sent(b"\xde\xad\xbe\xef", "frame1")
        restored = HistoryEntry.from_dict(entry.to_dict())
        assert restored.id == entry.id
        assert restored.raw_bytes == entry.raw_bytes
        assert restored.direction == entry.direction
        assert restored.frame_label == entry.frame_label


# ---------------------------------------------------------------------------
# SequenceSession
# ---------------------------------------------------------------------------

class TestSequenceSession:
    def test_create(self):
        seq = SequenceSession.create("My Seq", host="localhost", port=9090, tls=False)
        assert seq.label == "My Seq"
        assert seq.host == "localhost"
        assert seq.port == 9090
        assert not seq.tls
        assert seq.frames == []
        assert seq.variables == {}
        assert seq.history == []

    def test_roundtrip_empty(self):
        seq = SequenceSession.create("Empty")
        restored = SequenceSession.from_dict(seq.to_dict())
        assert restored.id == seq.id
        assert restored.label == seq.label

    def test_roundtrip_with_frames_and_vars(self):
        seq = SequenceSession.create("Full", host="h", port=1, tls=True)
        seq.frames.append(SequenceFrame.create("f1", "01 02 {{X}}"))
        seq.variables["X"] = "deadbeef"
        seq.history.append(HistoryEntry.create_sent(b"\x01", "f1"))
        restored = SequenceSession.from_dict(seq.to_dict())
        assert len(restored.frames) == 1
        assert restored.frames[0].label == "f1"
        assert restored.variables["X"] == "deadbeef"
        assert len(restored.history) == 1


# ---------------------------------------------------------------------------
# Variable resolution
# ---------------------------------------------------------------------------

class TestResolveHex:
    def test_plain_hex(self):
        assert resolve_hex("01 02 03", {}) == b"\x01\x02\x03"

    def test_placeholder_direct(self):
        result = resolve_hex("01 {{ID}} 02", {"ID": "aabb"})
        assert result == b"\x01\xaa\xbb\x02"

    def test_placeholder_missing_raises(self):
        with pytest.raises(ValueError, match="ID"):
            resolve_hex("{{ID}}", {})

    def test_placeholder_uint32be_add(self):
        # 0x00000001 + 1 = 0x00000002
        result = resolve_hex("{{SEQ:uint32be_add(1)}}", {"SEQ": "00000001"})
        assert result == b"\x00\x00\x00\x02"

    def test_placeholder_uint32be_add_wraparound(self):
        result = resolve_hex("{{SEQ:uint32be_add(1)}}", {"SEQ": "ffffffff"})
        assert result == b"\x00\x00\x00\x00"

    def test_placeholder_uint32le_add(self):
        n = struct.pack("<I", 5)
        result = resolve_hex("{{N:uint32le_add(3)}}", {"N": n.hex()})
        assert struct.unpack("<I", result)[0] == 8

    def test_placeholder_uint16be_sub(self):
        n = struct.pack(">H", 10)
        result = resolve_hex("{{N:uint16be_sub(3)}}", {"N": n.hex()})
        assert struct.unpack(">H", result)[0] == 7

    def test_placeholder_xor(self):
        result = resolve_hex("{{B:xor(ff)}}", {"B": "aa"})
        assert result == bytes([0xaa ^ 0xff])

    def test_placeholder_xor_all_bytes(self):
        result = resolve_hex("{{B:xor(0f)}}", {"B": "f0f0"})
        assert result == bytes([0xf0 ^ 0x0f, 0xf0 ^ 0x0f])

    def test_placeholder_script(self):
        result = resolve_hex("{{B:script(value[::-1])}}", {"B": "0102"})
        assert result == b"\x02\x01"

    def test_placeholder_script_must_return_bytes(self):
        with pytest.raises(ValueError, match="bytes"):
            resolve_hex("{{B:script(42)}}", {"B": "01"})

    def test_multiple_placeholders(self):
        result = resolve_hex("{{A}} {{B}}", {"A": "0102", "B": "0304"})
        assert result == b"\x01\x02\x03\x04"

    def test_invalid_final_hex_raises(self):
        # A token that's not a placeholder and not valid 2-char hex
        with pytest.raises(ValueError):
            resolve_hex("gg", {})

    def test_unknown_transform_raises(self):
        with pytest.raises(ValueError, match="Unknown transform"):
            resolve_hex("{{B:rotate(1)}}", {"B": "01"})


# ---------------------------------------------------------------------------
# SequenceEngine
# ---------------------------------------------------------------------------

class TestSequenceEngine:
    @pytest.mark.asyncio
    async def test_run_simple(self):
        seq = SequenceSession.create("test", host="h", port=1)
        seq.frames.append(SequenceFrame.create("f1", "01 02 03"))
        seq.frames.append(SequenceFrame.create("f2", "04 05"))

        sent: list[bytes] = []
        received_resp = [b"\xaa\xbb", b"\xcc"]

        async def send_fn(data: bytes) -> list[bytes]:
            sent.append(data)
            return received_resp if len(sent) == 1 else []

        engine = SequenceEngine()
        entries: list[HistoryEntry] = []
        await engine.run(seq, send_fn=send_fn, on_entry=entries.append)

        assert sent[0] == b"\x01\x02\x03"
        assert sent[1] == b"\x04\x05"

        # 2 sent + 2 received (from frame 1) = 4 entries
        assert len(entries) == 4
        assert entries[0].direction == "sent"
        assert entries[0].raw_bytes == b"\x01\x02\x03"
        assert entries[1].direction == "received"
        assert entries[1].raw_bytes == b"\xaa\xbb"
        assert entries[2].direction == "received"
        assert entries[2].raw_bytes == b"\xcc"
        assert entries[3].direction == "sent"
        assert entries[3].raw_bytes == b"\x04\x05"

        # All entries persisted to seq.history
        assert len(seq.history) == 4

    @pytest.mark.asyncio
    async def test_run_with_variable_substitution(self):
        seq = SequenceSession.create("test")
        seq.variables["ID"] = "aabb"
        seq.frames.append(SequenceFrame.create("f1", "01 {{ID}} 02"))

        sent: list[bytes] = []

        async def send_fn(data: bytes) -> list[bytes]:
            sent.append(data)
            return []

        engine = SequenceEngine()
        await engine.run(seq, send_fn=send_fn)
        assert sent[0] == b"\x01\xaa\xbb\x02"

    @pytest.mark.asyncio
    async def test_run_skips_frame_on_resolve_error(self):
        """A frame with an undefined variable is skipped, others still run."""
        seq = SequenceSession.create("test")
        seq.frames.append(SequenceFrame.create("bad",  "01 {{MISSING}}"))
        seq.frames.append(SequenceFrame.create("good", "02 03"))

        sent: list[bytes] = []

        async def send_fn(data: bytes) -> list[bytes]:
            sent.append(data)
            return []

        engine = SequenceEngine()
        await engine.run(seq, send_fn=send_fn)
        assert len(sent) == 1
        assert sent[0] == b"\x02\x03"

