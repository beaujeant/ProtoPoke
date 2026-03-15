"""Tests for the Sequencer feature."""

from __future__ import annotations

import struct
import tempfile
import textwrap
from pathlib import Path
from typing import List

import pytest

from protopoke.sequence.models import HistoryEntry, SequenceSession, SequenceStep
from protopoke.sequence.variables import resolve_hex
from protopoke.sequence.engine import SequenceEngine, load_script


# ---------------------------------------------------------------------------
# SequenceStep
# ---------------------------------------------------------------------------

class TestSequenceStep:
    def test_create_defaults(self):
        step = SequenceStep.create()
        assert step.label == ""
        assert step.raw_hex == ""
        assert len(step.id) == 36  # UUID4

    def test_byte_length_plain(self):
        step = SequenceStep.create(raw_hex="01 02 03 04")
        assert step.byte_length() == 4

    def test_byte_length_with_placeholder(self):
        step = SequenceStep.create(raw_hex="01 ##SESS_ID## 02")
        # placeholder contributes 0, only 01 and 02 count
        assert step.byte_length() == 2

    def test_preview_truncates(self):
        step = SequenceStep.create(raw_hex=" ".join(["aa"] * 20))
        preview = step.preview(max_bytes=12)
        assert "…" in preview

    def test_preview_includes_placeholder(self):
        step = SequenceStep.create(raw_hex="01 ##SESS_ID## 02")
        preview = step.preview()
        assert "##SESS_ID##" in preview

    def test_roundtrip(self):
        step = SequenceStep.create(label="Login", raw_hex="01 02 ##SESS_ID## 03")
        restored = SequenceStep.from_dict(step.to_dict())
        assert restored.id == step.id
        assert restored.label == step.label
        assert restored.raw_hex == step.raw_hex


# ---------------------------------------------------------------------------
# HistoryEntry
# ---------------------------------------------------------------------------

class TestHistoryEntry:
    def test_create_sent(self):
        entry = HistoryEntry.create_sent(b"\x01\x02", "Login")
        assert entry.direction == "sent"
        assert entry.raw_bytes == b"\x01\x02"
        assert entry.step_label == "Login"

    def test_create_received(self):
        entry = HistoryEntry.create_received(b"\x61\x62")
        assert entry.direction == "received"
        assert entry.raw_bytes == b"\x61\x62"

    def test_roundtrip(self):
        entry = HistoryEntry.create_sent(b"\xde\xad\xbe\xef", "step1")
        restored = HistoryEntry.from_dict(entry.to_dict())
        assert restored.id == entry.id
        assert restored.raw_bytes == entry.raw_bytes
        assert restored.direction == entry.direction
        assert restored.step_label == entry.step_label


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
        assert seq.steps == []
        assert seq.variables == {}
        assert seq.history == []

    def test_roundtrip_empty(self):
        seq = SequenceSession.create("Empty")
        restored = SequenceSession.from_dict(seq.to_dict())
        assert restored.id == seq.id
        assert restored.label == seq.label

    def test_roundtrip_with_steps_and_vars(self):
        seq = SequenceSession.create("Full", host="h", port=1, tls=True)
        seq.steps.append(SequenceStep.create("s1", "01 02 ##X##"))
        seq.variables["X"] = "deadbeef"
        seq.history.append(HistoryEntry.create_sent(b"\x01", "s1"))
        restored = SequenceSession.from_dict(seq.to_dict())
        assert len(restored.steps) == 1
        assert restored.steps[0].label == "s1"
        assert restored.variables["X"] == "deadbeef"
        assert len(restored.history) == 1


# ---------------------------------------------------------------------------
# Variable resolution
# ---------------------------------------------------------------------------

class TestResolveHex:
    def test_plain_hex(self):
        assert resolve_hex("01 02 03", {}) == b"\x01\x02\x03"

    def test_placeholder_direct(self):
        result = resolve_hex("01 ##ID## 02", {"ID": "aabb"})
        assert result == b"\x01\xaa\xbb\x02"

    def test_placeholder_missing_raises(self):
        with pytest.raises(ValueError, match="ID"):
            resolve_hex("##ID##", {})

    def test_placeholder_uint32be_add(self):
        # 0x00000001 + 1 = 0x00000002
        result = resolve_hex("##SEQ:uint32be_add(1)##", {"SEQ": "00000001"})
        assert result == b"\x00\x00\x00\x02"

    def test_placeholder_uint32be_add_wraparound(self):
        result = resolve_hex("##SEQ:uint32be_add(1)##", {"SEQ": "ffffffff"})
        assert result == b"\x00\x00\x00\x00"

    def test_placeholder_uint32le_add(self):
        n = struct.pack("<I", 5)
        result = resolve_hex("##N:uint32le_add(3)##", {"N": n.hex()})
        assert struct.unpack("<I", result)[0] == 8

    def test_placeholder_uint16be_sub(self):
        n = struct.pack(">H", 10)
        result = resolve_hex("##N:uint16be_sub(3)##", {"N": n.hex()})
        assert struct.unpack(">H", result)[0] == 7

    def test_placeholder_xor(self):
        result = resolve_hex("##B:xor(ff)##", {"B": "aa"})
        assert result == bytes([0xaa ^ 0xff])

    def test_placeholder_xor_all_bytes(self):
        result = resolve_hex("##B:xor(0f)##", {"B": "f0f0"})
        assert result == bytes([0xf0 ^ 0x0f, 0xf0 ^ 0x0f])

    def test_placeholder_script(self):
        result = resolve_hex("##B:script(value[::-1])##", {"B": "0102"})
        assert result == b"\x02\x01"

    def test_placeholder_script_must_return_bytes(self):
        with pytest.raises(ValueError, match="bytes"):
            resolve_hex("##B:script(42)##", {"B": "01"})

    def test_multiple_placeholders(self):
        result = resolve_hex("##A## ##B##", {"A": "0102", "B": "0304"})
        assert result == b"\x01\x02\x03\x04"

    def test_invalid_final_hex_raises(self):
        # A token that's not a placeholder and not valid 2-char hex
        with pytest.raises(ValueError):
            resolve_hex("gg", {})

    def test_unknown_transform_raises(self):
        with pytest.raises(ValueError, match="Unknown transform"):
            resolve_hex("##B:rotate(1)##", {"B": "01"})


# ---------------------------------------------------------------------------
# SequenceEngine
# ---------------------------------------------------------------------------

class TestSequenceEngine:
    @pytest.mark.asyncio
    async def test_run_simple(self):
        seq = SequenceSession.create("test", host="h", port=1)
        seq.steps.append(SequenceStep.create("s1", "01 02 03"))
        seq.steps.append(SequenceStep.create("s2", "04 05"))

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

        # 2 sent + 2 received (from step 1) = 4 entries
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
        seq.steps.append(SequenceStep.create("s1", "01 ##ID## 02"))

        sent: list[bytes] = []

        async def send_fn(data: bytes) -> list[bytes]:
            sent.append(data)
            return []

        engine = SequenceEngine()
        await engine.run(seq, send_fn=send_fn)
        assert sent[0] == b"\x01\xaa\xbb\x02"

    @pytest.mark.asyncio
    async def test_run_with_on_response_hook(self):
        """on_response captures a variable; next step uses it."""
        seq = SequenceSession.create("test")
        seq.steps.append(SequenceStep.create("handshake", "01"))
        seq.steps.append(SequenceStep.create("auth", "02 ##TOKEN##"))

        responses = [b"\x61\x62\xde\xad\xbe\xef", b""]

        async def send_fn(data: bytes) -> list[bytes]:
            return [responses.pop(0)] if responses else []

        # Script: on_response extracts bytes 2..6 as TOKEN
        script_src = textwrap.dedent("""\
            def on_response(response, variables, step_idx, step_label):
                if step_idx == 0 and len(response) >= 6:
                    variables['TOKEN'] = response[2:6].hex()
        """)
        script_mod = _load_script_from_source(script_src)

        sent: list[bytes] = []
        orig_send = send_fn

        async def tracking_send_fn(data: bytes) -> list[bytes]:
            sent.append(data)
            return await orig_send(data)

        engine = SequenceEngine()
        await engine.run(seq, send_fn=tracking_send_fn, script=script_mod)

        assert sent[0] == b"\x01"
        # Second step should have TOKEN=deadbeef substituted
        assert sent[1] == b"\x02\xde\xad\xbe\xef"
        # Variable persisted back to session
        assert seq.variables.get("TOKEN") == "deadbeef"

    @pytest.mark.asyncio
    async def test_run_with_on_send_hook(self):
        """on_send can modify the bytes before sending."""
        seq = SequenceSession.create("test")
        seq.steps.append(SequenceStep.create("s1", "01 02"))

        script_src = textwrap.dedent("""\
            def on_send(data, variables, step_idx, step_label):
                return bytes([b ^ 0xff for b in data])
        """)
        script_mod = _load_script_from_source(script_src)

        sent: list[bytes] = []

        async def send_fn(data: bytes) -> list[bytes]:
            sent.append(data)
            return []

        engine = SequenceEngine()
        await engine.run(seq, send_fn=send_fn, script=script_mod)
        # 01 02 XOR ff = fe fd
        assert sent[0] == b"\xfe\xfd"

    @pytest.mark.asyncio
    async def test_run_skips_step_on_resolve_error(self):
        """A step with an undefined variable is skipped, others still run."""
        seq = SequenceSession.create("test")
        seq.steps.append(SequenceStep.create("bad",  "01 ##MISSING##"))
        seq.steps.append(SequenceStep.create("good", "02 03"))

        sent: list[bytes] = []

        async def send_fn(data: bytes) -> list[bytes]:
            sent.append(data)
            return []

        engine = SequenceEngine()
        await engine.run(seq, send_fn=send_fn)
        assert len(sent) == 1
        assert sent[0] == b"\x02\x03"

    @pytest.mark.asyncio
    async def test_variables_persist_after_run(self):
        seq = SequenceSession.create("test")
        seq.steps.append(SequenceStep.create("s1", "01"))

        script_src = textwrap.dedent("""\
            def on_response(response, variables, step_idx, step_label):
                variables['CAPTURED'] = 'cafebabe'
        """)
        script_mod = _load_script_from_source(script_src)

        async def send_fn(data):
            return [b"\xff"]

        engine = SequenceEngine()
        await engine.run(seq, send_fn=send_fn, script=script_mod)
        assert seq.variables.get("CAPTURED") == "cafebabe"


# ---------------------------------------------------------------------------
# load_script
# ---------------------------------------------------------------------------

class TestLoadScript:
    def test_load_valid_script(self, tmp_path):
        script_file = tmp_path / "myscript.py"
        script_file.write_text("def on_response(r, v, i, l): v['X'] = 'aa'")
        mod = load_script(str(script_file))
        variables: dict = {}
        mod.on_response(b"", variables, 0, "")
        assert variables["X"] == "aa"

    def test_load_missing_file(self, tmp_path):
        with pytest.raises(Exception):
            load_script(str(tmp_path / "nonexistent.py"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_script_from_source(source: str):
    """Create a module from a source string (for tests only)."""
    import types
    mod = types.ModuleType("_test_script")
    exec(compile(source, "<test>", "exec"), mod.__dict__)  # noqa: S102
    return mod
