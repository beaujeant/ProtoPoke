"""Tests for the MCP server (build_mcp_server + tool functions).

We test tool logic directly by calling the tool functions through the MCP
server's internal tool registry, without running an actual MCP transport.
This keeps the tests fast and dependency-light.

Each tool is a regular Python function (or coroutine) registered on the
FastMCP instance.  We retrieve it with ``mcp._tool_manager.get_tool(name)``
and call ``tool.fn(...)`` directly.
"""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Stub out the broken TLS / cryptography native extension so that the rest
# of the import chain works in environments where _cffi_backend is missing.
# ---------------------------------------------------------------------------
def _make_tls_stubs() -> None:
    """Insert lightweight mocks for cryptography / TLS modules before import."""
    for mod_name in list(sys.modules):
        if mod_name.startswith("cryptography") or mod_name.startswith("protopoke.tls"):
            del sys.modules[mod_name]

    # Stub cryptography
    crypto_stub = ModuleType("cryptography")
    sys.modules.setdefault("cryptography", crypto_stub)
    for sub in ["x509", "hazmat", "hazmat.primitives", "hazmat.primitives.asymmetric",
                "hazmat.primitives.asymmetric.rsa", "hazmat.primitives.hashes",
                "hazmat.primitives.serialization", "hazmat.backends",
                "hazmat.backends.default", "hazmat.primitives.asymmetric.padding"]:
        sys.modules.setdefault(f"cryptography.{sub}", ModuleType(f"cryptography.{sub}"))

    # Stub protopoke.tls modules
    tls_stub = ModuleType("protopoke.tls")
    ca_stub = ModuleType("protopoke.tls.ca")
    ca_stub.CertificateAuthority = MagicMock()
    ca_stub.DEFAULT_CA_CERT_PATH = "/tmp/fake-ca.crt"
    ca_stub.DEFAULT_CA_KEY_PATH = "/tmp/fake-ca.key"
    handler_stub = ModuleType("protopoke.tls.handler")
    handler_stub.TLSHandler = MagicMock()
    sys.modules["protopoke.tls"] = tls_stub
    sys.modules["protopoke.tls.ca"] = ca_stub
    sys.modules["protopoke.tls.handler"] = handler_stub


_make_tls_stubs()

from protopoke.api import ProxyAPI  # noqa: E402
from protopoke.config import ProxyConfig  # noqa: E402
from protopoke.models import Direction  # noqa: E402
from protopoke.rules.rule import ReplaceRule, TamperRule, RuleAction  # noqa: E402
from protopoke.mcp import build_mcp_server  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def api():
    cfg = ProxyConfig(
        listen_port=19999,
        upstream_host="127.0.0.1",
        upstream_port=19998,
        tamper_enabled=True,
    )
    return ProxyAPI(cfg)


@pytest.fixture
def mcp_server(api):
    return build_mcp_server(api)


def get_tool(mcp_server, name):
    """Retrieve a registered tool function from the FastMCP instance."""
    tool = mcp_server._tool_manager.get_tool(name)
    assert tool is not None, f"Tool '{name}' not found"
    return tool.fn


# ---------------------------------------------------------------------------
# proxy_status
# ---------------------------------------------------------------------------

class TestProxyStatus:
    def test_returns_dict(self, mcp_server):
        fn = get_tool(mcp_server, "proxy_status")
        result = fn()
        assert isinstance(result, dict)

    def test_contains_expected_keys(self, mcp_server):
        fn = get_tool(mcp_server, "proxy_status")
        result = fn()
        assert "tamper_enabled" in result
        assert "pending_tamper_count" in result
        assert "total_sessions" in result
        assert "listen" in result

    def test_tamper_enabled_reflects_config(self, mcp_server, api):
        fn = get_tool(mcp_server, "proxy_status")
        api.tamper_enabled = True
        result = fn()
        assert result["tamper_enabled"] is True


# ---------------------------------------------------------------------------
# list_sessions / get_session
# ---------------------------------------------------------------------------

class TestSessionTools:
    def test_list_sessions_empty(self, mcp_server):
        fn = get_tool(mcp_server, "list_sessions")
        assert fn() == []

    def test_get_session_not_found(self, mcp_server):
        fn = get_tool(mcp_server, "get_session")
        assert fn("nonexistent") is None

    def test_get_session_after_creation(self, mcp_server, api):
        session = api.session_registry.create("127.0.0.1", 50001, "10.0.0.1", 443)
        fn = get_tool(mcp_server, "get_session")
        result = fn(session.id)
        assert result is not None
        assert result["id"] == session.id

    def test_list_sessions_reflects_registry(self, mcp_server, api):
        api.session_registry.create("127.0.0.1", 50001, "10.0.0.1", 443)
        api.session_registry.create("127.0.0.1", 50002, "10.0.0.1", 443)
        fn = get_tool(mcp_server, "list_sessions")
        assert len(fn()) == 2


# ---------------------------------------------------------------------------
# get_frames
# ---------------------------------------------------------------------------

class TestGetFrames:
    def test_no_frames_returns_empty(self, mcp_server, api):
        session = api.session_registry.create("127.0.0.1", 50001, "10.0.0.1", 443)
        fn = get_tool(mcp_server, "get_frames")
        assert fn(session.id) == []

    def test_invalid_direction_returns_error(self, mcp_server, api):
        session = api.session_registry.create("127.0.0.1", 50001, "10.0.0.1", 443)
        fn = get_tool(mcp_server, "get_frames")
        result = fn(session.id, direction="bad_direction")
        assert len(result) == 1
        assert "error" in result[0]

    def test_direction_filter_client_to_server(self, mcp_server, api):
        from protopoke.models import Frame
        session = api.session_registry.create("127.0.0.1", 50001, "10.0.0.1", 443)
        f1 = Frame.create(session.id, Direction.CLIENT_TO_SERVER, b"\x01", 0)
        f2 = Frame.create(session.id, Direction.SERVER_TO_CLIENT, b"\x02", 1)
        session.add_frame(f1)
        session.add_frame(f2)

        fn = get_tool(mcp_server, "get_frames")
        result = fn(session.id, direction="client_to_server")
        assert len(result) == 1
        assert result[0]["direction"] == "client_to_server"


# ---------------------------------------------------------------------------
# tamper tools
# ---------------------------------------------------------------------------

class TestTamperTools:
    def test_tamper_status(self, mcp_server, api):
        fn = get_tool(mcp_server, "tamper_status")
        result = fn()
        assert "tamper_enabled" in result
        assert "pending_count" in result

    def test_tamper_toggle(self, mcp_server, api):
        fn = get_tool(mcp_server, "tamper_toggle")
        result = fn(False)
        assert result["tamper_enabled"] is False
        result2 = fn(True)
        assert result2["tamper_enabled"] is True

    def test_list_tampered_empty(self, mcp_server):
        fn = get_tool(mcp_server, "list_intercepted")
        assert fn() == []

    def test_tamper_forward_unknown_id(self, mcp_server):
        fn = get_tool(mcp_server, "tamper_forward")
        result = fn("unknown-id")
        assert result["ok"] is False

    def test_tamper_drop_unknown_id(self, mcp_server):
        fn = get_tool(mcp_server, "tamper_drop")
        result = fn("unknown-id")
        assert result["ok"] is False

    def test_tamper_modify_invalid_hex(self, mcp_server):
        fn = get_tool(mcp_server, "tamper_modify_and_forward")
        result = fn("some-id", "ZZNOTVALIDHEX")
        assert result["ok"] is False
        assert "error" in result

    def test_tamper_forward_all_when_empty(self, mcp_server):
        fn = get_tool(mcp_server, "tamper_forward_all")
        result = fn()
        assert result["forwarded"] == 0

    def test_set_direction_filter(self, mcp_server, api):
        fn = get_tool(mcp_server, "tamper_set_direction_filter")
        result = fn("client_to_server")
        assert result["direction_filter"] == "client_to_server"
        result2 = fn(None)
        assert result2["direction_filter"] is None

    def test_set_direction_filter_invalid(self, mcp_server):
        fn = get_tool(mcp_server, "tamper_set_direction_filter")
        result = fn("invalid_direction")
        assert "error" in result

    def test_set_session_filter(self, mcp_server):
        fn = get_tool(mcp_server, "tamper_set_session_filter")
        result = fn(["sess-1", "sess-2"])
        assert set(result["session_filter"]) == {"sess-1", "sess-2"}
        result2 = fn(None)
        assert result2["session_filter"] is None


# ---------------------------------------------------------------------------
# Replace rules tools
# ---------------------------------------------------------------------------

class TestReplaceRuleTools:
    def test_list_replace_rules_empty(self, mcp_server):
        fn = get_tool(mcp_server, "list_replace_rules")
        assert fn() == []

    def test_add_replace_rule(self, mcp_server):
        fn_add = get_tool(mcp_server, "add_replace_rule")
        result = fn_add("test rule", "41 42", "4344")
        assert result["ok"] is True
        assert result["rule"]["label"] == "test rule"
        assert "id" in result["rule"]

    def test_add_replace_rule_invalid_hex(self, mcp_server):
        fn = get_tool(mcp_server, "add_replace_rule")
        result = fn("bad", "41", "NOTVALIDHEX")
        assert result["ok"] is False

    def test_add_replace_rule_with_direction(self, mcp_server):
        fn = get_tool(mcp_server, "add_replace_rule")
        result = fn("dir rule", "FF", "00", direction="client_to_server")
        assert result["ok"] is True
        assert result["rule"]["direction"] == "client_to_server"

    def test_add_replace_rule_invalid_direction(self, mcp_server):
        fn = get_tool(mcp_server, "add_replace_rule")
        result = fn("bad dir", "FF", "00", direction="bad")
        assert result["ok"] is False

    def test_remove_replace_rule(self, mcp_server, api):
        rule = ReplaceRule.create("r1", "41", b"\x42")
        api.add_replace_rule(rule)

        fn_list = get_tool(mcp_server, "list_replace_rules")
        assert len(fn_list()) == 1

        fn_remove = get_tool(mcp_server, "remove_replace_rule")
        result = fn_remove(rule.id)
        assert result["ok"] is True
        assert fn_list() == []

    def test_remove_nonexistent_rule(self, mcp_server):
        fn = get_tool(mcp_server, "remove_replace_rule")
        result = fn("does-not-exist")
        assert result["ok"] is False


# ---------------------------------------------------------------------------
# Tamper rules tools
# ---------------------------------------------------------------------------

class TestTamperRuleTools:
    def test_list_tamper_rules_empty(self, mcp_server):
        fn = get_tool(mcp_server, "list_tamper_rules")
        assert fn() == []

    def test_add_tamper_rule(self, mcp_server):
        fn = get_tool(mcp_server, "add_tamper_rule")
        result = fn("login", "01 02", "intercept")
        assert result["ok"] is True
        assert result["rule"]["label"] == "login"
        assert result["rule"]["action"] == "intercept"

    def test_add_tamper_rule_forward_action(self, mcp_server):
        fn = get_tool(mcp_server, "add_tamper_rule")
        result = fn("heartbeat", "FF", "forward")
        assert result["ok"] is True
        assert result["rule"]["action"] == "forward"

    def test_add_tamper_rule_invalid_action(self, mcp_server):
        fn = get_tool(mcp_server, "add_tamper_rule")
        result = fn("bad", "01", "unknown_action")
        assert result["ok"] is False

    def test_add_tamper_rule_with_session_ids(self, mcp_server):
        fn = get_tool(mcp_server, "add_tamper_rule")
        result = fn("scoped", "01", "intercept", session_ids=["s1", "s2"])
        assert result["ok"] is True
        assert set(result["rule"]["session_ids"]) == {"s1", "s2"}

    def test_remove_tamper_rule(self, mcp_server, api):
        rule = TamperRule.create("r1", "01", RuleAction.INTERCEPT)
        api.add_tamper_rule(rule)

        fn_remove = get_tool(mcp_server, "remove_tamper_rule")
        result = fn_remove(rule.id)
        assert result["ok"] is True

        fn_list = get_tool(mcp_server, "list_tamper_rules")
        assert fn_list() == []

    def test_remove_nonexistent_tamper_rule(self, mcp_server):
        fn = get_tool(mcp_server, "remove_tamper_rule")
        result = fn("nope")
        assert result["ok"] is False


# ---------------------------------------------------------------------------
# Config tools
# ---------------------------------------------------------------------------

class TestConfigTools:
    def test_get_config(self, mcp_server, api):
        fn = get_tool(mcp_server, "get_config")
        result = fn()
        assert result["listen_port"] == api.config.listen_port

    def test_set_config_listen_port(self, mcp_server, api):
        fn = get_tool(mcp_server, "set_config")
        result = fn(listen_port=7777)
        assert result["listen_port"] == 7777
        assert api.config.listen_port == 7777

    def test_set_config_upstream(self, mcp_server, api):
        fn = get_tool(mcp_server, "set_config")
        fn(upstream_host="192.168.1.1", upstream_port=9000)
        assert api.config.upstream_host == "192.168.1.1"
        assert api.config.upstream_port == 9000

    def test_set_config_partial_update(self, mcp_server, api):
        original_port = api.config.listen_port
        fn = get_tool(mcp_server, "set_config")
        fn(upstream_host="newhost")
        assert api.config.listen_port == original_port  # unchanged


# ---------------------------------------------------------------------------
# send_frame (async tool)
# ---------------------------------------------------------------------------

class TestSendFrameTool:
    @pytest.mark.asyncio
    async def test_invalid_hex_returns_error(self, mcp_server):
        fn = get_tool(mcp_server, "send_frame")
        result = await fn(data_hex="NOTVALIDHEX", host="127.0.0.1", port=9999)
        assert result["ok"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_connection_refused_returns_error(self, mcp_server):
        fn = get_tool(mcp_server, "send_frame")
        # Port 19 is discard protocol — virtually always refused in test envs
        result = await fn(data_hex="0102", host="127.0.0.1", port=1, connect_timeout=0.5)
        # Either error flag or failed success
        assert "error" in result or result.get("success") is False


# ---------------------------------------------------------------------------
# forge_session (async tool)
# ---------------------------------------------------------------------------

class TestReplaySessionTool:
    @pytest.mark.asyncio
    async def test_unknown_session_returns_error(self, mcp_server):
        fn = get_tool(mcp_server, "forge_session")
        result = await fn("nonexistent-session-id")
        # Should fail gracefully with an error in the result
        assert "error" in result or result.get("success") is False

    @pytest.mark.asyncio
    async def test_invalid_direction_returns_error(self, mcp_server):
        fn = get_tool(mcp_server, "forge_session")
        result = await fn("any-session", direction="bad_dir")
        assert "error" in result
