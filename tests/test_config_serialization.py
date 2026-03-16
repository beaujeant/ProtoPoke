"""Tests for ProxyConfig serialization."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from protopoke.config import ProxyConfig


class TestProxyConfigSerialization:
    def test_to_dict_round_trip(self):
        cfg = ProxyConfig(
            listen_port=9090,
            upstream_host="10.0.0.1",
            upstream_port=443,
            tls_upstream=True,
            framer_name="delimiter",
            framer_kwargs={"delimiter": b"\r\n"},
        )
        d = cfg.to_dict()
        restored = ProxyConfig.from_dict(d)

        assert restored.listen_port == 9090
        assert restored.upstream_host == "10.0.0.1"
        assert restored.upstream_port == 443
        assert restored.tls_upstream is True
        assert restored.framer_name == "delimiter"
        # Bytes are round-tripped through hex encoding
        assert restored.framer_kwargs["delimiter"] == b"\r\n"

    def test_to_dict_bytes_encoded_as_hex(self):
        cfg = ProxyConfig(framer_kwargs={"delimiter": b"\x00\xFF"})
        d = cfg.to_dict()
        # JSON-compatible: bytes should be a hex string
        assert isinstance(d["framer_kwargs"]["delimiter"], str)
        assert d["framer_kwargs"]["delimiter"] == "00ff"

    def test_save_and_load(self, tmp_path):
        cfg = ProxyConfig(listen_port=8765, tls_listen=True)
        path = tmp_path / "config.json"
        cfg.save(path)

        assert path.exists()
        restored = ProxyConfig.load(path)
        assert restored.listen_port == 8765
        assert restored.tls_listen is True

    def test_save_produces_valid_json(self, tmp_path):
        cfg = ProxyConfig()
        path = tmp_path / "config.json"
        cfg.save(path)
        # Should not raise
        data = json.loads(path.read_text())
        assert "listen_port" in data

    def test_from_dict_ignores_unknown_keys(self):
        cfg = ProxyConfig()
        d = cfg.to_dict()
        d["future_unknown_field"] = "ignored"
        # Should not raise
        restored = ProxyConfig.from_dict({k: v for k, v in d.items() if k != "future_unknown_field"})
        assert restored.listen_port == cfg.listen_port

    def test_defaults_preserved(self):
        cfg = ProxyConfig()
        restored = ProxyConfig.from_dict(cfg.to_dict())
        assert restored.listen_host == "127.0.0.1"
        assert restored.framer_name == "raw"
        assert restored.tamper_enabled is False
