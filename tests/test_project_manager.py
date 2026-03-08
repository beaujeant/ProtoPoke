"""Tests for ProjectManager."""

from __future__ import annotations

import json

import pytest

from protopoke.config import ProxyConfig
from protopoke.rules.rule import ReplaceRule, InterceptRule, RuleAction
from protopoke.replay.models import RepeaterRequest, SendRecord
from protopoke.project.manager import ProjectManager, ProjectState


class TestProjectManager:
    def test_new_resets_state(self):
        pm = ProjectManager()
        pm.config.listen_port = 9999
        pm.new("Fresh")
        assert pm.config.listen_port == 8080  # default
        assert pm.name == "Fresh"
        assert pm.path is None
        assert pm.is_dirty is False

    def test_save_as_creates_directory(self, tmp_path):
        pm = ProjectManager()
        pm.name = "Test Project"
        out = pm.save_as(tmp_path / "my.protopoke")
        assert out.is_dir()
        assert (out / "project.json").exists()
        assert (out / "config.json").exists()
        assert (out / "rules.json").exists()
        assert (out / "repeater.json").exists()

    def test_save_as_sets_path(self, tmp_path):
        pm = ProjectManager()
        pm.save_as(tmp_path / "proj.protopoke")
        assert pm.path is not None
        assert pm.is_dirty is False

    def test_save_requires_path(self):
        pm = ProjectManager()
        with pytest.raises(RuntimeError, match="No project path"):
            pm.save()

    def test_save_after_save_as(self, tmp_path):
        pm = ProjectManager()
        pm.save_as(tmp_path / "p.protopoke")
        pm.config.listen_port = 1234
        pm.mark_dirty()
        pm.save()
        # Reload and verify
        pm2 = ProjectManager()
        pm2.open(tmp_path / "p.protopoke")
        assert pm2.config.listen_port == 1234

    def test_open_loads_config(self, tmp_path):
        pm = ProjectManager()
        pm.config.listen_port = 7777
        pm.save_as(tmp_path / "p.protopoke")

        pm2 = ProjectManager()
        state = pm2.open(tmp_path / "p.protopoke")
        assert state.config.listen_port == 7777
        assert pm2.config.listen_port == 7777

    def test_open_loads_replace_rules(self, tmp_path):
        pm = ProjectManager()
        rule = ReplaceRule.create("r1", "01 02", b"\xFF")
        pm.rules_engine.add_rule(rule)
        pm.save_as(tmp_path / "p.protopoke")

        pm2 = ProjectManager()
        state = pm2.open(tmp_path / "p.protopoke")
        assert len(state.rules_engine.rules) == 1
        assert state.rules_engine.rules[0].label == "r1"

    def test_open_loads_intercept_rules(self, tmp_path):
        pm = ProjectManager()
        rule = InterceptRule.create("catch", "FF", RuleAction.FORWARD)
        pm.intercept_filter.add_rule(rule)
        pm.save_as(tmp_path / "p.protopoke")

        pm2 = ProjectManager()
        state = pm2.open(tmp_path / "p.protopoke")
        assert len(state.intercept_filter.rules) == 1
        assert state.intercept_filter.rules[0].action == RuleAction.FORWARD

    def test_open_loads_repeater(self, tmp_path):
        pm = ProjectManager()
        req = RepeaterRequest.create("Tab 1", "10.0.0.1", 443, current_bytes=b"\x01\x02")
        rec = SendRecord.create(b"\x01\x02", b"\x03\x04", "10.0.0.1", 443)
        req.add_record(rec)
        pm.repeater_requests.append(req)
        pm.save_as(tmp_path / "p.protopoke")

        pm2 = ProjectManager()
        state = pm2.open(tmp_path / "p.protopoke")
        assert len(state.repeater_requests) == 1
        assert state.repeater_requests[0].label == "Tab 1"
        assert state.repeater_requests[0].current_bytes == b"\x01\x02"
        assert len(state.repeater_requests[0].history) == 1
        assert state.repeater_requests[0].history[0].sent_bytes == b"\x01\x02"

    def test_open_missing_directory_raises(self):
        pm = ProjectManager()
        with pytest.raises(FileNotFoundError):
            pm.open("/tmp/does_not_exist_12345.protopoke")

    def test_open_missing_project_json_raises(self, tmp_path):
        pm = ProjectManager()
        bad_dir = tmp_path / "bad.protopoke"
        bad_dir.mkdir()
        with pytest.raises(ValueError, match="project.json"):
            pm.open(bad_dir)

    def test_open_returns_project_state(self, tmp_path):
        pm = ProjectManager()
        pm.name = "MyProj"
        pm.save_as(tmp_path / "p.protopoke")

        pm2 = ProjectManager()
        state = pm2.open(tmp_path / "p.protopoke")
        assert isinstance(state, ProjectState)
        assert state.name == "MyProj"
        assert state.db_path is None  # sessions.db not created yet

    def test_mark_dirty(self):
        pm = ProjectManager()
        assert pm.is_dirty is False
        pm.mark_dirty()
        assert pm.is_dirty is True

    def test_db_path_none_when_unsaved(self):
        pm = ProjectManager()
        assert pm.db_path is None

    def test_db_path_set_after_save_as(self, tmp_path):
        pm = ProjectManager()
        pm.save_as(tmp_path / "p.protopoke")
        assert pm.db_path == tmp_path / "p.protopoke" / "sessions.db"

    def test_project_json_contains_metadata(self, tmp_path):
        pm = ProjectManager()
        pm.name = "My Test"
        pm.save_as(tmp_path / "p.protopoke")
        meta = json.loads((tmp_path / "p.protopoke" / "project.json").read_text())
        assert meta["name"] == "My Test"
        assert "format_version" in meta
        assert "saved_at" in meta
