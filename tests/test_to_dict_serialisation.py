"""Tests for to_dict() serialisation on all core models."""

from __future__ import annotations

import json

import pytest

from protopoke.models import (
    Direction,
    Frame,
    InterceptAction,
    TamperedUnit,
    ParsedField,
    ParsedMessage,
    SessionState,
)
from protopoke.core.session import Session, SessionRegistry
from protopoke.forge.models import ForgeRequest, ForgeRecord


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_session() -> Session:
    registry = SessionRegistry()
    return registry.create("127.0.0.1", 50001, "10.0.0.1", 443)


def make_frame(session_id: str = "s1", data: bytes = b"\x01\x02\x03") -> Frame:
    return Frame.create(session_id, Direction.CLIENT_TO_SERVER, data, 0)


# ---------------------------------------------------------------------------
# Frame.to_dict()
# ---------------------------------------------------------------------------

class TestFrameToDict:
    def test_returns_dict(self):
        f = make_frame()
        d = f.to_dict()
        assert isinstance(d, dict)

    def test_raw_bytes_is_hex_string(self):
        f = make_frame(data=b"\xDE\xAD\xBE\xEF")
        d = f.to_dict()
        assert d["raw_bytes"] == "deadbeef"
        assert isinstance(d["raw_bytes"], str)

    def test_raw_bytes_len(self):
        f = make_frame(data=b"\x01\x02\x03")
        assert f.to_dict()["raw_bytes_len"] == 3

    def test_direction_is_string(self):
        f = make_frame()
        assert f.to_dict()["direction"] == "client_to_server"

    def test_contains_all_keys(self):
        keys = {"id", "session_id", "direction", "raw_bytes", "raw_bytes_len",
                "timestamp", "sequence_number", "framer_name"}
        d = make_frame().to_dict()
        assert keys.issubset(d.keys())

    def test_json_serialisable(self):
        d = make_frame().to_dict()
        # Should not raise
        json.dumps(d)


# ---------------------------------------------------------------------------
# SessionInfo.to_dict()
# ---------------------------------------------------------------------------

class TestSessionInfoToDict:
    def test_contains_all_keys(self):
        session = make_session()
        d = session.info.to_dict()
        keys = {"id", "client_host", "client_port", "server_host", "server_port",
                "state", "created_at", "closed_at"}
        assert keys.issubset(d.keys())

    def test_state_is_string(self):
        session = make_session()
        # New sessions start in CONNECTING state
        assert isinstance(session.info.to_dict()["state"], str)

    def test_closed_at_is_none_when_open(self):
        session = make_session()
        assert session.info.to_dict()["closed_at"] is None

    def test_closed_at_set_after_close(self):
        session = make_session()
        session.mark_closed()
        d = session.info.to_dict()
        assert d["state"] == "closed"
        assert d["closed_at"] is not None

    def test_json_serialisable(self):
        json.dumps(make_session().info.to_dict())


# ---------------------------------------------------------------------------
# TamperedUnit.to_dict()
# ---------------------------------------------------------------------------

class TestTamperedUnitToDict:
    def test_contains_expected_keys(self):
        frame = make_frame(data=b"\xAA\xBB")
        unit = TamperedUnit.from_frame(frame)
        d = unit.to_dict()
        assert "id" in d
        assert "frame" in d
        assert "action" in d
        assert "effective_bytes" in d

    def test_frame_is_nested_dict(self):
        frame = make_frame(data=b"\x01")
        unit = TamperedUnit.from_frame(frame)
        d = unit.to_dict()
        assert isinstance(d["frame"], dict)
        assert "raw_bytes" in d["frame"]

    def test_effective_bytes_hex(self):
        frame = make_frame(data=b"\xCA\xFE")
        unit = TamperedUnit.from_frame(frame)
        assert unit.to_dict()["effective_bytes"] == "cafe"

    def test_modified_effective_bytes(self):
        frame = make_frame(data=b"\x01\x02")
        unit = TamperedUnit.from_frame(frame)
        unit.modified_data = b"\xFF\xFE"
        unit.action = InterceptAction.MODIFIED
        d = unit.to_dict()
        assert d["effective_bytes"] == "fffe"
        assert d["action"] == "modified"

    def test_json_serialisable(self):
        json.dumps(TamperedUnit.from_frame(make_frame()).to_dict())


# ---------------------------------------------------------------------------
# ParsedField.to_dict()
# ---------------------------------------------------------------------------

class TestParsedFieldToDict:
    def test_basic_int_value(self):
        pf = ParsedField(
            name="length", value=42, raw_bytes=b"\x00\x2A",
            offset=0, size=2,
        )
        d = pf.to_dict()
        assert d["name"] == "length"
        assert d["value"] == 42
        assert d["raw_bytes"] == "002a"

    def test_bytes_value_hex_encoded(self):
        pf = ParsedField(
            name="payload", value=b"\xDE\xAD", raw_bytes=b"\xDE\xAD",
            offset=2, size=2,
        )
        d = pf.to_dict()
        assert d["value"] == "dead"

    def test_children_recursive(self):
        child = ParsedField(name="child", value=1, raw_bytes=b"\x01", offset=1, size=1)
        parent = ParsedField(
            name="parent", value=b"\x00\x01", raw_bytes=b"\x00\x01",
            offset=0, size=2, children=[child],
        )
        d = parent.to_dict()
        assert len(d["children"]) == 1
        assert d["children"][0]["name"] == "child"

    def test_json_serialisable(self):
        pf = ParsedField(name="x", value=b"\x01", raw_bytes=b"\x01", offset=0, size=1)
        json.dumps(pf.to_dict())


# ---------------------------------------------------------------------------
# ParsedMessage.to_dict()
# ---------------------------------------------------------------------------

class TestParsedMessageToDict:
    def test_contains_expected_keys(self):
        frame = make_frame()
        msg = ParsedMessage.from_frame(frame, "TestProto", "Handshake")
        d = msg.to_dict()
        assert "id" in d
        assert "frame_id" in d
        assert "protocol_name" in d
        assert "message_type" in d
        assert "fields" in d
        assert "display_name" in d
        assert "error" in d

    def test_frame_id_not_full_frame(self):
        frame = make_frame()
        msg = ParsedMessage.from_frame(frame, "P", "M")
        d = msg.to_dict()
        # frame_id should be the string ID, not a nested dict
        assert d["frame_id"] == frame.id
        assert isinstance(d["frame_id"], str)

    def test_json_serialisable(self):
        frame = make_frame()
        msg = ParsedMessage.from_frame(frame, "P", "M")
        json.dumps(msg.to_dict())


# ---------------------------------------------------------------------------
# ForgeRequest.to_dict() / from_dict()
# ---------------------------------------------------------------------------

class TestForgeRequestToDict:
    def test_round_trip(self):
        req = ForgeRequest.create("Tab 1", "10.0.0.1", 443, current_bytes=b"\x01\x02")
        rec = ForgeRecord.create(b"\x01\x02", b"\x03\x04", "10.0.0.1", 443)
        req.add_record(rec)
        d = req.to_dict()
        restored = ForgeRequest.from_dict(d)
        assert restored.label == "Tab 1"
        assert restored.host == "10.0.0.1"
        assert restored.current_bytes == b"\x01\x02"
        assert len(restored.history) == 1
        assert restored.history[0].sent_bytes == b"\x01\x02"

    def test_json_serialisable(self):
        req = ForgeRequest.create("T", "localhost", 80)
        json.dumps(req.to_dict())


# ---------------------------------------------------------------------------
# ForgeRecord.to_dict() / from_dict()
# ---------------------------------------------------------------------------

class TestForgeRecordToDict:
    def test_bytes_are_hex(self):
        rec = ForgeRecord.create(b"\xAA", b"\xBB", "host", 1234)
        d = rec.to_dict()
        assert d["sent_bytes"] == "aa"
        assert d["received_bytes"] == "bb"

    def test_round_trip(self):
        rec = ForgeRecord.create(b"\x01", b"\x02", "localhost", 8080, tls=True)
        rec2 = ForgeRecord.from_dict(rec.to_dict())
        assert rec2.sent_bytes == b"\x01"
        assert rec2.received_bytes == b"\x02"
        assert rec2.tls is True

    def test_json_serialisable(self):
        json.dumps(ForgeRecord.create(b"\x00", b"\x00", "h", 1).to_dict())
