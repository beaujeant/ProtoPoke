"""Tests for ProjectManager."""

from __future__ import annotations

import json
import zipfile

import pytest

from protopoke.config import ForwarderConfig
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

    def test_open_missing_path_raises(self):
        pm = ProjectManager()
        with pytest.raises(FileNotFoundError):
            pm.open("/tmp/does_not_exist_12345.pp")

    def test_open_missing_project_json_raises(self, tmp_path):
        pm = ProjectManager()
        bad_dir = tmp_path / "bad.pp"
        bad_dir.mkdir()
        with pytest.raises(ValueError, match="project.json"):
            pm.open(bad_dir)

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
        assert "format_version" in meta
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

    def test_legacy_directory_format_still_opens(self, tmp_path):
        """Backward compat: old directory-based projects can still be opened."""
        import time
        old_dir = tmp_path / "old.pp"
        old_dir.mkdir()
        meta = {"format_version": 1, "name": "Old", "created_at": time.time(), "saved_at": 0.0}
        (old_dir / "project.json").write_text(json.dumps(meta))

        pm = ProjectManager()
        state = pm.open(old_dir)
        assert state.name == "Old"

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
