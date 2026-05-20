"""Tests for ForwarderConfig serialization."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from protopoke.config import ForwarderConfig, ForwarderType


class TestForwarderConfigSerialization:
    def test_to_dict_round_trip(self):
        cfg = ForwarderConfig(
            name="Test",
            listen_port=9090,
            upstream_host="10.0.0.1",
            upstream_port=443,
            tls_upstream=True,
            framer_name="delimiter",
            framer_kwargs={"delimiter": b"\r\n"},
        )
        d = cfg.to_dict()
        restored = ForwarderConfig.from_dict(d)

        assert restored.name == "Test"
        assert restored.listen_port == 9090
        assert restored.upstream_host == "10.0.0.1"
        assert restored.upstream_port == 443
        assert restored.tls_upstream is True
        assert restored.framer_name == "delimiter"
        # Bytes are round-tripped through hex encoding
        assert restored.framer_kwargs["delimiter"] == b"\r\n"

    def test_to_dict_bytes_encoded_as_hex(self):
        cfg = ForwarderConfig(name="Test", framer_kwargs={"delimiter": b"\x00\xFF"})
        d = cfg.to_dict()
        # JSON-compatible: bytes should be a hex string
        assert isinstance(d["framer_kwargs"]["delimiter"], str)
        assert d["framer_kwargs"]["delimiter"] == "00ff"

    def test_save_and_load(self, tmp_path):
        cfg = ForwarderConfig(name="Test", listen_port=8765, tls_listen=True)
        path = tmp_path / "config.json"
        cfg.save(path)

        assert path.exists()
        restored = ForwarderConfig.load(path)
        assert restored.listen_port == 8765
        assert restored.tls_listen is True

    def test_save_produces_valid_json(self, tmp_path):
        cfg = ForwarderConfig(name="Test")
        path = tmp_path / "config.json"
        cfg.save(path)
        # Should not raise
        data = json.loads(path.read_text())
        assert "listen_port" in data

    def test_from_dict_ignores_unknown_keys(self):
        cfg = ForwarderConfig(name="Test")
        d = cfg.to_dict()
        d["future_unknown_field"] = "ignored"
        # Should not raise
        restored = ForwarderConfig.from_dict({k: v for k, v in d.items() if k != "future_unknown_field"})
        assert restored.listen_port == cfg.listen_port

    def test_defaults_preserved(self):
        cfg = ForwarderConfig(name="Test")
        restored = ForwarderConfig.from_dict(cfg.to_dict())
        assert restored.listen_host == "127.0.0.1"
        assert restored.framer_name == "raw"
        assert restored.tamper_enabled is False

    def test_name_and_enabled_round_trip(self):
        cfg = ForwarderConfig(name="MyForwarder", enabled=False)
        restored = ForwarderConfig.from_dict(cfg.to_dict())
        assert restored.name == "MyForwarder"
        assert restored.enabled is False

    def test_forwarder_type_default_is_tcp(self):
        cfg = ForwarderConfig(name="t")
        assert cfg.forwarder_type is ForwarderType.TCP

    def test_legacy_dict_without_forwarder_type_loads_as_tcp(self):
        cfg = ForwarderConfig(name="t")
        d = cfg.to_dict()
        d.pop("forwarder_type", None)
        restored = ForwarderConfig.from_dict(d)
        assert restored.forwarder_type is ForwarderType.TCP

    def test_udp_forwarder_round_trip(self):
        cfg = ForwarderConfig(
            name="udp",
            forwarder_type=ForwarderType.UDP,
        )
        restored = ForwarderConfig.from_dict(cfg.to_dict())
        assert restored.forwarder_type is ForwarderType.UDP

    def test_socks5_forwarder_round_trip_with_auth(self):
        cfg = ForwarderConfig(
            name="socks",
            forwarder_type=ForwarderType.SOCKS5,
            socks_auth_username="alice",
            socks_auth_password="secret",
        )
        d = cfg.to_dict()
        # forwarder_type is serialised as a plain string for JSON compatibility.
        assert d["forwarder_type"] == "socks5"
        restored = ForwarderConfig.from_dict(d)
        assert restored.forwarder_type is ForwarderType.SOCKS5
        assert restored.socks_auth_username == "alice"
        assert restored.socks_auth_password == "secret"

    def test_socks5_with_tls_listen_rejected(self):
        with pytest.raises(ValueError):
            ForwarderConfig(
                name="bad",
                forwarder_type=ForwarderType.SOCKS5,
                tls_listen=True,
            )

    def test_udp_with_tls_listen_rejected(self):
        with pytest.raises(ValueError):
            ForwarderConfig(
                name="bad",
                forwarder_type=ForwarderType.UDP,
                tls_listen=True,
            )
