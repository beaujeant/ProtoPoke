"""Tests for core data models (models.py)."""

from __future__ import annotations

import time

import pytest

from protopoke.models import (
    Direction,
    Frame,
    InterceptAction,
    InterceptedUnit,
    ParsedMessage,
    SessionInfo,
    SessionState,
    new_id,
)


class TestNewId:
    def test_returns_string(self):
        assert isinstance(new_id(), str)

    def test_unique(self):
        ids = {new_id() for _ in range(200)}
        assert len(ids) == 200


class TestDirection:
    def test_opposite_client_to_server(self):
        assert Direction.CLIENT_TO_SERVER.opposite() is Direction.SERVER_TO_CLIENT

    def test_opposite_server_to_client(self):
        assert Direction.SERVER_TO_CLIENT.opposite() is Direction.CLIENT_TO_SERVER


class TestFrame:
    def _make(self, **kwargs) -> Frame:
        defaults = dict(
            session_id="sess-1",
            direction=Direction.CLIENT_TO_SERVER,
            raw_bytes=b"hello",
            sequence_number=0,
        )
        defaults.update(kwargs)
        return Frame.create(**defaults)

    def test_create_sets_id(self):
        frame = self._make()
        assert frame.id
        assert len(frame.id) == 36  # UUID4 string

    def test_create_sets_timestamp(self):
        before = time.time()
        frame = self._make()
        after = time.time()
        assert before <= frame.timestamp <= after

    def test_create_preserves_fields(self):
        frame = self._make(raw_bytes=b"data", sequence_number=7)
        assert frame.raw_bytes == b"data"
        assert frame.sequence_number == 7
        assert frame.session_id == "sess-1"
        assert frame.direction is Direction.CLIENT_TO_SERVER

    def test_default_framer_name(self):
        frame = self._make()
        assert frame.framer_name == "raw"

    def test_custom_framer_name(self):
        frame = self._make(framer_name="delimiter")
        assert frame.framer_name == "delimiter"

    def test_repr_is_readable(self):
        frame = self._make()
        r = repr(frame)
        assert "Frame" in r
        assert "client_to_server" in r


class TestSessionInfo:
    def test_create_populates_all_fields(self):
        info = SessionInfo.create("127.0.0.1", 12345, "10.0.0.1", 80)
        assert info.client_host == "127.0.0.1"
        assert info.client_port == 12345
        assert info.server_host == "10.0.0.1"
        assert info.server_port == 80
        assert info.state is SessionState.CONNECTING
        assert info.id
        assert info.closed_at is None

    def test_create_sets_created_at(self):
        before = time.time()
        info = SessionInfo.create("h", 1, "h", 2)
        after = time.time()
        assert before <= info.created_at <= after


class TestInterceptedUnit:
    def _frame(self) -> Frame:
        return Frame.create("s", Direction.CLIENT_TO_SERVER, b"data", 0)

    def test_from_frame_default_forward(self):
        frame = self._frame()
        unit = InterceptedUnit.from_frame(frame)
        assert unit.frame is frame
        assert unit.action is InterceptAction.FORWARD
        assert unit.modified_data is None

    def test_effective_bytes_forward_returns_original(self):
        frame = self._frame()
        unit = InterceptedUnit.from_frame(frame)
        unit.action = InterceptAction.FORWARD
        assert unit.effective_bytes() == b"data"

    def test_effective_bytes_modified_returns_replacement(self):
        frame = self._frame()
        unit = InterceptedUnit.from_frame(frame)
        unit.action = InterceptAction.MODIFIED
        unit.modified_data = b"replaced"
        assert unit.effective_bytes() == b"replaced"

    def test_effective_bytes_modified_no_data_falls_back_to_original(self):
        # Edge case: action=MODIFIED but modified_data is None
        frame = self._frame()
        unit = InterceptedUnit.from_frame(frame)
        unit.action = InterceptAction.MODIFIED
        unit.modified_data = None
        assert unit.effective_bytes() == b"data"

    def test_effective_bytes_drop_returns_original(self):
        # effective_bytes() doesn't check for DROP — the relay checks action.
        # But it should still return the original bytes if called.
        frame = self._frame()
        unit = InterceptedUnit.from_frame(frame)
        unit.action = InterceptAction.DROP
        assert unit.effective_bytes() == b"data"


class TestParsedMessage:
    def test_from_frame_fields(self):
        frame = Frame.create("s", Direction.CLIENT_TO_SERVER, b"\x01\x02", 0)
        msg = ParsedMessage.from_frame(
            frame=frame,
            protocol_name="MyProto",
            fields={"type": 1, "length": 2},
            display_name="MyProto/Request",
        )
        assert msg.frame is frame
        assert msg.protocol_name == "MyProto"
        assert msg.fields["type"] == 1
        assert msg.display_name == "MyProto/Request"
        assert msg.id
