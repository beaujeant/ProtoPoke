"""Tests for ForgeRequest and ForgeRecord models."""

from __future__ import annotations

import pytest

from protopoke.forge.models import ForgeRecord, ForgeRequest


class TestForgeRecord:
    def test_create(self):
        rec = ForgeRecord.create(b"\x01\x02", b"\x03\x04", "10.0.0.1", 443)
        assert rec.sent_bytes == b"\x01\x02"
        assert rec.received_bytes == b"\x03\x04"
        assert rec.host == "10.0.0.1"
        assert rec.port == 443
        assert rec.success is True
        assert rec.error is None

    def test_create_failure(self):
        rec = ForgeRecord.create(b"\x01", b"", "bad-host", 9999, success=False, error="timeout")
        assert not rec.success
        assert rec.error == "timeout"
        assert rec.received_bytes == b""

    def test_serialise_round_trip(self):
        rec = ForgeRecord.create(b"\xDE\xAD", b"\xBE\xEF", "localhost", 8080, tls=True)
        restored = ForgeRecord.from_dict(rec.to_dict())
        assert restored.sent_bytes == b"\xDE\xAD"
        assert restored.received_bytes == b"\xBE\xEF"
        assert restored.tls is True
        assert restored.id == rec.id

    def test_null_bytes_round_trip(self):
        rec = ForgeRecord.create(b"\x00\x00\x00", b"\x00", "h", 1)
        restored = ForgeRecord.from_dict(rec.to_dict())
        assert restored.sent_bytes == b"\x00\x00\x00"


class TestForgeRequest:
    def test_create(self):
        req = ForgeRequest.create("Tab 1", "10.0.0.1", 443, current_bytes=b"\x01")
        assert req.label == "Tab 1"
        assert req.host == "10.0.0.1"
        assert req.port == 443
        assert req.current_bytes == b"\x01"
        assert req.history == []

    def test_add_record(self):
        req = ForgeRequest.create("Tab", "h", 80)
        rec = ForgeRecord.create(b"\x01", b"\x02", "h", 80)
        req.add_record(rec)
        assert len(req.history) == 1
        assert req.history[0] is rec

    def test_serialise_round_trip(self):
        req = ForgeRequest.create(
            "My Tab", "example.com", 443, tls=True,
            current_bytes=b"\xFF\xFE", source_session_id="sess-1"
        )
        rec = ForgeRecord.create(b"\xFF\xFE", b"\x00\x01", "example.com", 443, tls=True)
        req.add_record(rec)

        restored = ForgeRequest.from_dict(req.to_dict())
        assert restored.label == "My Tab"
        assert restored.host == "example.com"
        assert restored.tls is True
        assert restored.current_bytes == b"\xFF\xFE"
        assert restored.source_session_id == "sess-1"
        assert len(restored.history) == 1
        assert restored.history[0].sent_bytes == b"\xFF\xFE"

    def test_empty_current_bytes(self):
        req = ForgeRequest.create("Empty", "h", 80)
        restored = ForgeRequest.from_dict(req.to_dict())
        assert restored.current_bytes == b""
