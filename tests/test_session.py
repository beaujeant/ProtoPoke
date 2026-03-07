"""Tests for the session registry."""

from __future__ import annotations

import pytest

from tcpproxy.models import Direction, Frame, SessionState
from tcpproxy.core.session import Session, SessionRegistry


def make_registry() -> SessionRegistry:
    return SessionRegistry()


class TestSession:
    def test_add_frame(self):
        reg = make_registry()
        sess = reg.create("127.0.0.1", 1, "10.0.0.1", 80)
        frame = Frame.create(sess.id, Direction.CLIENT_TO_SERVER, b"x", 0)
        sess.add_frame(frame)
        assert len(sess.frames) == 1
        assert sess.frames[0] is frame

    def test_frames_for_direction(self):
        reg = make_registry()
        sess = reg.create("127.0.0.1", 1, "10.0.0.1", 80)
        f1 = Frame.create(sess.id, Direction.CLIENT_TO_SERVER, b"up",   0)
        f2 = Frame.create(sess.id, Direction.SERVER_TO_CLIENT, b"down", 0)
        sess.add_frame(f1)
        sess.add_frame(f2)
        assert sess.frames_for_direction(Direction.CLIENT_TO_SERVER) == [f1]
        assert sess.frames_for_direction(Direction.SERVER_TO_CLIENT) == [f2]

    def test_is_active(self):
        reg = make_registry()
        sess = reg.create("127.0.0.1", 1, "10.0.0.1", 80)
        assert sess.is_active()  # CONNECTING is active
        reg.mark_active(sess.id)
        assert sess.is_active()
        reg.mark_closed(sess.id)
        assert not sess.is_active()

    def test_state_transitions(self):
        reg = make_registry()
        sess = reg.create("127.0.0.1", 1, "10.0.0.1", 80)
        assert sess.info.state is SessionState.CONNECTING
        reg.mark_active(sess.id)
        assert sess.info.state is SessionState.ACTIVE
        reg.mark_closed(sess.id)
        assert sess.info.state is SessionState.CLOSED
        assert sess.info.closed_at is not None


class TestSessionRegistry:
    def test_create_returns_session(self):
        reg = make_registry()
        sess = reg.create("127.0.0.1", 1234, "10.0.0.1", 80)
        assert sess.id
        assert sess.info.client_host == "127.0.0.1"
        assert sess.info.server_host == "10.0.0.1"

    def test_get_existing(self):
        reg = make_registry()
        sess = reg.create("127.0.0.1", 1, "10.0.0.1", 80)
        assert reg.get(sess.id) is sess

    def test_get_nonexistent(self):
        reg = make_registry()
        assert reg.get("nonexistent") is None

    def test_mark_active(self):
        reg = make_registry()
        sess = reg.create("127.0.0.1", 1, "10.0.0.1", 80)
        reg.mark_active(sess.id)
        assert sess.info.state is SessionState.ACTIVE

    def test_mark_closed(self):
        reg = make_registry()
        sess = reg.create("127.0.0.1", 1, "10.0.0.1", 80)
        reg.mark_active(sess.id)
        reg.mark_closed(sess.id)
        assert sess.info.state is SessionState.CLOSED

    def test_active_sessions_excludes_closed(self):
        reg = make_registry()
        s1 = reg.create("127.0.0.1", 1, "10.0.0.1", 80)
        s2 = reg.create("127.0.0.1", 2, "10.0.0.1", 80)
        reg.mark_active(s1.id)
        reg.mark_active(s2.id)
        reg.mark_closed(s1.id)

        active_ids = {s.id for s in reg.active_sessions()}
        assert s1.id not in active_ids
        assert s2.id in active_ids

    def test_all_sessions_includes_closed(self):
        reg = make_registry()
        s1 = reg.create("127.0.0.1", 1, "10.0.0.1", 80)
        reg.mark_closed(s1.id)
        assert len(reg.all_sessions()) == 1

    def test_len(self):
        reg = make_registry()
        reg.create("127.0.0.1", 1, "10.0.0.1", 80)
        reg.create("127.0.0.1", 2, "10.0.0.1", 80)
        assert len(reg) == 2

    def test_mark_active_unknown_id_does_not_raise(self):
        reg = make_registry()
        reg.mark_active("nonexistent")  # Should silently do nothing

    def test_mark_closed_unknown_id_does_not_raise(self):
        reg = make_registry()
        reg.mark_closed("nonexistent")
