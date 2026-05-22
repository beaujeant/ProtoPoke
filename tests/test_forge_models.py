"""Tests for forge data models (PlaybookFrame, TrafficEntry, PlaybookRun, Playbook)."""

from __future__ import annotations

import json

import pytest

from protopoke.forge.models import PlaybookFrame, TrafficEntry, PlaybookRun, Playbook


class TestPlaybookFrame:
    def test_create(self):
        f = PlaybookFrame.create(label="Login", raw_hex="01 02 03", direction="client_to_server")
        assert f.label == "Login"
        assert f.raw_hex == "01 02 03"
        assert f.direction == "client_to_server"
        assert f.id  # non-empty UUID

    def test_preview(self):
        f = PlaybookFrame.create(raw_hex="01 02 03 04 05")
        assert "01" in f.preview()

    def test_byte_length(self):
        f = PlaybookFrame.create(raw_hex="01 02 03")
        assert f.byte_length() == 3

    def test_byte_length_with_placeholder(self):
        f = PlaybookFrame.create(raw_hex="01 {{VAR}} 03")
        assert f.byte_length() == 2

    def test_serialise_round_trip(self):
        f = PlaybookFrame.create(label="Test", raw_hex="DE AD", direction="server_to_client")
        restored = PlaybookFrame.from_dict(f.to_dict())
        assert restored.label == "Test"
        assert restored.raw_hex == "DE AD"
        assert restored.direction == "server_to_client"
        assert restored.id == f.id


class TestTrafficEntry:
    def test_create_sent(self):
        e = TrafficEntry.create_sent(b"\x01\x02", "Login")
        assert e.direction == "sent"
        assert e.raw_bytes == b"\x01\x02"
        assert e.frame_label == "Login"

    def test_create_received(self):
        e = TrafficEntry.create_received(b"\x03\x04", "Response")
        assert e.direction == "received"
        assert e.raw_bytes == b"\x03\x04"

    def test_serialise_round_trip(self):
        e = TrafficEntry.create_sent(b"\xDE\xAD", "Frame1")
        restored = TrafficEntry.from_dict(e.to_dict())
        assert restored.raw_bytes == b"\xDE\xAD"
        assert restored.direction == "sent"
        assert restored.id == e.id


class TestPlaybookRun:
    def test_create(self):
        run = PlaybookRun.create("My Playbook")
        assert run.playbook_label == "My Playbook"
        assert run.traffic == []

    def test_bytes_totals(self):
        run = PlaybookRun.create("Test")
        run.traffic.append(TrafficEntry.create_sent(b"\x01\x02\x03", "f1"))
        run.traffic.append(TrafficEntry.create_received(b"\x04\x05", "f1"))
        assert run.sent_bytes_total() == 3
        assert run.received_bytes_total() == 2

    def test_serialise_round_trip(self):
        run = PlaybookRun.create("Test")
        run.traffic.append(TrafficEntry.create_sent(b"\xAA", "f1"))
        restored = PlaybookRun.from_dict(run.to_dict())
        assert restored.playbook_label == "Test"
        assert len(restored.traffic) == 1
        assert restored.traffic[0].raw_bytes == b"\xAA"


class TestPlaybook:
    def test_create(self):
        p = Playbook.create("My Playbook", host="10.0.0.1", port=443, tls=True)
        assert p.label == "My Playbook"
        assert p.host == "10.0.0.1"
        assert p.port == 443
        assert p.tls is True
        assert p.frames == []
        assert p.runs == []

    def test_serialise_round_trip(self):
        p = Playbook.create("Test", host="example.com", port=443, tls=True)
        frame = PlaybookFrame.create(label="F1", raw_hex="01 02")
        p.frames.append(frame)
        run = PlaybookRun.create("Test")
        run.traffic.append(TrafficEntry.create_sent(b"\x01\x02", "F1"))
        p.runs.append(run)

        restored = Playbook.from_dict(p.to_dict())
        assert restored.label == "Test"
        assert restored.host == "example.com"
        assert restored.tls is True
        assert len(restored.frames) == 1
        assert restored.frames[0].raw_hex == "01 02"
        assert len(restored.runs) == 1
        assert restored.runs[0].traffic[0].raw_bytes == b"\x01\x02"

    def test_variables_persist(self):
        p = Playbook.create("Test")
        p.variables["SEQ"] = "00000001"
        restored = Playbook.from_dict(p.to_dict())
        assert restored.variables["SEQ"] == "00000001"

    def test_transport_defaults_to_tcp(self):
        p = Playbook.create("Test")
        assert p.transport == "tcp"

    def test_legacy_dict_without_transport_loads_as_tcp(self):
        p = Playbook.create("Test", host="h", port=1)
        d = p.to_dict()
        d.pop("transport", None)
        restored = Playbook.from_dict(d)
        assert restored.transport == "tcp"

    def test_udp_transport_round_trips(self):
        p = Playbook.create("Test", host="h", port=1, transport="udp")
        d = p.to_dict()
        assert d["transport"] == "udp"
        restored = Playbook.from_dict(d)
        assert restored.transport == "udp"


class TestPlaybookPortable:
    """Standalone export/import (the Forge Import/Export buttons)."""

    def _sample(self) -> Playbook:
        p = Playbook.create(
            "Login flow", host="example.com", port=8443, tls=True,
            transport="tcp", response_window=2.5,
        )
        p.source_session_id = "live-session-that-wont-survive"
        p.variables["TOKEN"] = "deadbeef"
        p.frames.append(PlaybookFrame.create(label="hello", raw_hex="01 02"))
        p.frames.append(
            PlaybookFrame.create(label="reply", raw_hex="ff", direction="server_to_client")
        )
        run = PlaybookRun.create("Login flow")
        run.traffic.append(TrafficEntry.create_sent(b"\x01\x02", "hello"))
        p.runs.append(run)
        return p

    def test_portable_round_trip_preserves_replay_config(self):
        restored = Playbook.from_portable_dict(self._sample().to_portable_dict())
        assert restored.label == "Login flow"
        assert restored.host == "example.com"
        assert restored.port == 8443
        assert restored.tls is True
        assert restored.transport == "tcp"
        assert restored.response_window == 2.5
        assert restored.variables == {"TOKEN": "deadbeef"}
        assert [f.raw_hex for f in restored.frames] == ["01 02", "ff"]
        assert restored.frames[1].direction == "server_to_client"

    def test_portable_drops_session_binding(self):
        d = self._sample().to_portable_dict()
        assert "source_session_id" not in d
        restored = Playbook.from_portable_dict(d)
        assert restored.source_session_id is None

    def test_portable_drops_runs_history(self):
        d = self._sample().to_portable_dict()
        assert "runs" not in d
        assert Playbook.from_portable_dict(d).runs == []

    def test_portable_generates_fresh_id(self):
        original = self._sample()
        restored = Playbook.from_portable_dict(original.to_portable_dict())
        assert restored.id != original.id

    def test_portable_is_json_serialisable(self):
        json.dumps(self._sample().to_portable_dict())

    def test_import_rejects_unmarked_file(self):
        with pytest.raises(ValueError):
            Playbook.from_portable_dict({
                "label": "no marker",
                "frames": [{"label": "f1", "raw_hex": "aa", "direction": "client_to_server"}],
            })

    def test_import_rejects_non_list_frames(self):
        with pytest.raises(ValueError):
            Playbook.from_portable_dict({"format": Playbook.PORTABLE_FORMAT, "frames": "nope"})
