"""Tests for ProjectManager."""

from __future__ import annotations

import json
import zipfile

import pytest

from protopoke.config import ForwarderConfig, ForwarderType
from protopoke.knowledge import Finding, Note
from protopoke.rules.rule import ReplaceRule, InterceptRule, RuleAction
from protopoke.forge.models import Playbook, PlaybookFrame, TrafficEntry
from protopoke.project.manager import ProjectManager, ProjectState


class TestProjectManager:
    def test_new_resets_state(self):
        pm = ProjectManager()
        pm.forwarders = [ForwarderConfig(name="Test", listen_port=9999)]
        pm.new("Fresh")
        assert pm.forwarders == []
        assert pm.name == "Fresh"
        assert pm.path is None
        assert pm.is_dirty is False

    def test_save_as_creates_zip_file(self, tmp_path):
        pm = ProjectManager()
        pm.name = "Test Project"
        out = pm.save_as(tmp_path / "my.pp")
        assert out.is_file()
        assert zipfile.is_zipfile(out)
        with zipfile.ZipFile(out) as zf:
            assert "project.json" in zf.namelist()
            assert "forwarders.json" in zf.namelist()
            assert "rules.json" in zf.namelist()
            assert "forge.json" in zf.namelist()

    def test_save_as_sets_path(self, tmp_path):
        pm = ProjectManager()
        pm.save_as(tmp_path / "proj.pp")
        assert pm.path is not None
        assert pm.is_dirty is False

    def test_save_requires_path(self):
        pm = ProjectManager()
        with pytest.raises(RuntimeError, match="No project path"):
            pm.save()

    def test_save_after_save_as(self, tmp_path):
        pm = ProjectManager()
        pm.forwarders = [ForwarderConfig(name="Default", listen_port=1234)]
        pm.save_as(tmp_path / "p.pp")
        pm.forwarders[0].listen_port = 5678
        pm.mark_dirty()
        pm.save()
        # Reload and verify
        pm2 = ProjectManager()
        pm2.open(tmp_path / "p.pp")
        assert pm2.forwarders[0].listen_port == 5678

    def test_open_loads_forwarders(self, tmp_path):
        pm = ProjectManager()
        pm.forwarders = [ForwarderConfig(name="Default", listen_port=7777)]
        pm.save_as(tmp_path / "p.pp")

        pm2 = ProjectManager()
        state = pm2.open(tmp_path / "p.pp")
        assert state.forwarders[0].listen_port == 7777

    def test_open_loads_replace_rules(self, tmp_path):
        pm = ProjectManager()
        rule = ReplaceRule.create("r1", "01 02", b"\xFF")
        pm.rules_engine.add_rule(rule)
        pm.save_as(tmp_path / "p.pp")

        pm2 = ProjectManager()
        state = pm2.open(tmp_path / "p.pp")
        assert len(state.rules_engine.rules) == 1
        assert state.rules_engine.rules[0].label == "r1"

    def test_open_loads_intercept_rules(self, tmp_path):
        pm = ProjectManager()
        rule = InterceptRule.create("catch", "FF", RuleAction.FORWARD)
        pm.intercept_filter.add_rule(rule)
        pm.save_as(tmp_path / "p.pp")

        pm2 = ProjectManager()
        state = pm2.open(tmp_path / "p.pp")
        assert len(state.intercept_filter.rules) == 1
        assert state.intercept_filter.rules[0].action == RuleAction.FORWARD

    def test_open_loads_playbooks(self, tmp_path):
        pm = ProjectManager()
        frame = PlaybookFrame.create(
            raw_hex="01 02",
            direction="client_to_server",
            label="Login",
        )
        playbook = Playbook.create(
            label="Test Playbook",
            host="10.0.0.1",
            port=443,
        )
        playbook.frames.append(frame)
        pm.playbooks.append(playbook)
        pm.save_as(tmp_path / "p.pp")

        pm2 = ProjectManager()
        state = pm2.open(tmp_path / "p.pp")
        assert len(state.playbooks) == 1
        assert state.playbooks[0].label == "Test Playbook"
        assert len(state.playbooks[0].frames) == 1
        assert state.playbooks[0].frames[0].raw_hex == "01 02"

    def test_playbook_connection_config_survives_save_load(self, tmp_path):
        pm = ProjectManager()
        playbook = Playbook.create(
            label="Cfg", host="10.0.0.1", port=8443, tls=True,
            transport="tcp", response_window=2.5,
        )
        playbook.variables["TOKEN"] = "deadbeef"
        pm.playbooks.append(playbook)
        pm.save_as(tmp_path / "p.pp")

        state = ProjectManager().open(tmp_path / "p.pp")
        pb = state.playbooks[0]
        assert (pb.host, pb.port, pb.tls) == ("10.0.0.1", 8443, True)
        assert pb.transport == "tcp"
        assert pb.response_window == 2.5
        assert pb.variables == {"TOKEN": "deadbeef"}

    def test_stale_source_session_cleared_on_load(self, tmp_path):
        # A bound session belongs to the saving process and cannot survive a
        # reload; the playbook must fall back to host/port instead of staying
        # bound to a dead session (which the UI refuses to run).
        pm = ProjectManager()
        playbook = Playbook.create(label="Bound", host="10.0.0.1", port=443)
        playbook.source_session_id = "session-from-another-life"
        pm.playbooks.append(playbook)
        pm.save_as(tmp_path / "p.pp")

        state = ProjectManager().open(tmp_path / "p.pp")
        assert state.playbooks[0].source_session_id is None
        assert state.playbooks[0].host == "10.0.0.1"

    def test_open_missing_path_raises(self):
        pm = ProjectManager()
        with pytest.raises(FileNotFoundError):
            pm.open("/tmp/does_not_exist_12345.pp")

    def test_open_returns_project_state(self, tmp_path):
        pm = ProjectManager()
        pm.name = "MyProj"
        pm.save_as(tmp_path / "p.pp")

        pm2 = ProjectManager()
        state = pm2.open(tmp_path / "p.pp")
        assert isinstance(state, ProjectState)
        assert state.name == "MyProj"

    def test_mark_dirty(self):
        pm = ProjectManager()
        assert pm.is_dirty is False
        pm.mark_dirty()
        assert pm.is_dirty is True

    def test_project_json_contains_metadata(self, tmp_path):
        pm = ProjectManager()
        pm.name = "My Test"
        out = pm.save_as(tmp_path / "p.pp")
        with zipfile.ZipFile(out) as zf:
            meta = json.loads(zf.read("project.json"))
        assert meta["name"] == "My Test"
        assert "saved_at" in meta

    def test_captured_sessions_round_trip(self, tmp_path):
        pm = ProjectManager()
        pm.name = "Sessions Test"
        pm.captured_sessions = [
            {
                "id": "sess-1",
                "client_host": "127.0.0.1",
                "client_port": 1234,
                "server_host": "10.0.0.1",
                "server_port": 9090,
                "state": "closed",
                "created_at": 1000.0,
                "closed_at": 1001.0,
                "frames": [
                    {
                        "id": "frame-1",
                        "session_id": "sess-1",
                        "direction": "client_to_server",
                        "raw_bytes": "deadbeef",
                        "timestamp": 1000.5,
                        "sequence_number": 1,
                        "framer_name": "raw",
                    }
                ],
            }
        ]
        out = pm.save_as(tmp_path / "p.pp")

        pm2 = ProjectManager()
        state = pm2.open(out)
        assert len(state.captured_sessions) == 1
        assert state.captured_sessions[0]["id"] == "sess-1"
        assert len(state.captured_sessions[0]["frames"]) == 1
        assert state.captured_sessions[0]["frames"][0]["raw_bytes"] == "deadbeef"

    def test_mixed_transport_forwarders_round_trip(self, tmp_path):
        pm = ProjectManager()
        pm.forwarders = [
            ForwarderConfig(name="tcp1", listen_port=11111),
            ForwarderConfig(
                name="udp1",
                forwarder_type=ForwarderType.UDP,
                listen_port=22222,
                upstream_host="127.0.0.1",
                upstream_port=33333,
            ),
            ForwarderConfig(
                name="socks1",
                forwarder_type=ForwarderType.SOCKS5,
                listen_port=44444,
                socks_auth_user="user",
                socks_auth_pass="pass",
            ),
        ]
        pm.save_as(tmp_path / "mixed.pp")

        pm2 = ProjectManager()
        state = pm2.open(tmp_path / "mixed.pp")
        types = {f.name: f.forwarder_type for f in state.forwarders}
        assert types == {
            "tcp1":   ForwarderType.TCP,
            "udp1":   ForwarderType.UDP,
            "socks1": ForwarderType.SOCKS5,
        }
        udp = next(f for f in state.forwarders if f.name == "udp1")
        assert udp.upstream_port == 33333
        socks = next(f for f in state.forwarders if f.name == "socks1")
        assert socks.socks_auth_user == "user"
        assert socks.socks_auth_pass == "pass"

    def test_findings_and_notes_round_trip(self, tmp_path):
        pm = ProjectManager()
        pm.knowledge.add_finding(Finding.create(
            title="CRC at bytes 4-5",
            description="probably CRC16-CCITT",
            confidence="high",
            status="confirmed",
            author="ai",
            forwarder_id="fwd-uuid-123",
            evidence_frame_ids=["f1", "f2"],
            tags=["checksum"],
        ))
        pm.knowledge.add_note(Note.create(
            title="open question",
            body_md="* why does the server echo the seq?",
            author="user",
            locked=True,
        ))
        out = pm.save_as(tmp_path / "kb.pp")

        pm2 = ProjectManager()
        state = pm2.open(out)
        assert len(state.knowledge.findings) == 1
        assert len(state.knowledge.notes) == 1
        f = state.knowledge.findings[0]
        assert f.title == "CRC at bytes 4-5"
        assert f.confidence == "high"
        assert f.status == "confirmed"
        assert f.forwarder_id == "fwd-uuid-123"
        assert f.evidence_frame_ids == ["f1", "f2"]
        n = state.knowledge.notes[0]
        assert n.title == "open question"
        assert n.locked is True

    def test_forwarder_id_survives_save_load(self, tmp_path):
        pm = ProjectManager()
        original = ForwarderConfig(name="Game", listen_port=5555)
        original_id = original.id
        pm.forwarders = [original]
        pm.save_as(tmp_path / "p.pp")

        pm2 = ProjectManager()
        state = pm2.open(tmp_path / "p.pp")
        assert state.forwarders[0].id == original_id

    def test_zip_too_many_members_rejected(self, tmp_path):
        """ZIP with more than _ZIP_MAX_MEMBERS entries raises ValueError."""
        import zipfile as zf
        from protopoke.project.manager import _ZIP_MAX_MEMBERS
        bomb = tmp_path / "bomb.pp"
        with zf.ZipFile(bomb, "w") as z:
            for i in range(_ZIP_MAX_MEMBERS + 1):
                z.writestr(f"junk_{i}.bin", b"x")
        pm = ProjectManager()
        with pytest.raises(ValueError, match="too many members"):
            pm.open(bomb)
