"""Tests for protopoke.mcp.host.MCPHost and MCPSettings.

These tests exercise the embedded MCP server lifecycle without actually
binding to a TCP port: the FastMCP server's ``run_async`` is monkey-patched
so ``MCPHost.start`` builds the server and stashes a task, but we never
serve real HTTP.  The ``_protopoke_rebind`` hook is tested against the real
``build_mcp_server`` implementation.
"""

from __future__ import annotations

import asyncio
import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Stub out the cryptography / TLS modules (same pattern as test_mcp_server.py).
# ---------------------------------------------------------------------------
def _make_tls_stubs() -> None:
    for mod_name in list(sys.modules):
        if mod_name.startswith("cryptography") or mod_name.startswith("protopoke.tls"):
            del sys.modules[mod_name]

    crypto_stub = ModuleType("cryptography")
    sys.modules.setdefault("cryptography", crypto_stub)
    for sub in ["x509", "hazmat", "hazmat.primitives", "hazmat.primitives.asymmetric",
                "hazmat.primitives.asymmetric.rsa", "hazmat.primitives.hashes",
                "hazmat.primitives.serialization", "hazmat.backends",
                "hazmat.backends.default", "hazmat.primitives.asymmetric.padding"]:
        sys.modules.setdefault(f"cryptography.{sub}", ModuleType(f"cryptography.{sub}"))

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

from protopoke.api import ProtoPokeAPI  # noqa: E402
from protopoke.config import ForwarderConfig  # noqa: E402
from protopoke.mcp.host import MCPHost, MCPSettings  # noqa: E402
from protopoke.mcp.server import build_mcp_server  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_api(port: int = 19999) -> ProtoPokeAPI:
    fwd = ForwarderConfig(
        name="Default",
        listen_port=port,
        upstream_host="127.0.0.1",
        upstream_port=port + 1,
    )
    return ProtoPokeAPI([fwd])


@pytest.fixture
def api():
    return _make_api()


@pytest.fixture
def patched_run_async(monkeypatch):
    """Replace FastMCP.run_streamable_http_async with a slow coroutine we can cancel."""

    async def fake_run(self):
        # Loop forever until cancelled; never actually bind a port.
        await asyncio.sleep(3600)

    from mcp.server.fastmcp import FastMCP
    monkeypatch.setattr(FastMCP, "run_streamable_http_async", fake_run)
    return fake_run


# ---------------------------------------------------------------------------
# MCPSettings
# ---------------------------------------------------------------------------

def test_mcp_settings_defaults_are_disabled():
    s = MCPSettings()
    assert s.enabled is False
    assert s.host == "127.0.0.1"
    assert s.port == 7878
    assert s.name == "ProtoPoke"
    assert s.url() == "http://127.0.0.1:7878/mcp"


def test_mcp_settings_round_trip():
    s = MCPSettings(enabled=True, host="0.0.0.0", port=9000, name="Test")
    assert MCPSettings.from_dict(s.to_dict()) == s


def test_mcp_settings_from_dict_fills_defaults():
    s = MCPSettings.from_dict({})
    assert s == MCPSettings()


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

async def test_start_is_noop_when_disabled(api):
    host = MCPHost(api, MCPSettings(enabled=False))
    await host.start()
    assert host.is_running is False


async def test_start_runs_server_task_when_enabled(api, patched_run_async):
    host = MCPHost(api, MCPSettings(enabled=True, port=18765))
    await host.start()
    try:
        assert host.is_running is True
        assert host._server is not None
        assert host._server.settings.host == "127.0.0.1"
        assert host._server.settings.port == 18765
    finally:
        await host.stop()
    assert host.is_running is False


async def test_stop_is_idempotent(api, patched_run_async):
    host = MCPHost(api, MCPSettings(enabled=True))
    await host.start()
    await host.stop()
    # Second stop should not raise.
    await host.stop()
    assert host.is_running is False


async def test_start_is_noop_if_already_running(api, patched_run_async):
    host = MCPHost(api, MCPSettings(enabled=True))
    await host.start()
    try:
        first_task = host._task
        await host.start()
        assert host._task is first_task
    finally:
        await host.stop()


# ---------------------------------------------------------------------------
# apply() behaviour
# ---------------------------------------------------------------------------

async def test_apply_disables_running_server(api, patched_run_async):
    host = MCPHost(api, MCPSettings(enabled=True))
    await host.start()
    assert host.is_running
    await host.apply(MCPSettings(enabled=False))
    assert host.is_running is False


async def test_apply_enables_stopped_server(api, patched_run_async):
    host = MCPHost(api, MCPSettings(enabled=False))
    await host.start()
    assert host.is_running is False
    await host.apply(MCPSettings(enabled=True, port=18766))
    try:
        assert host.is_running is True
        assert host._server.settings.port == 18766
    finally:
        await host.stop()


async def test_apply_restarts_when_port_changes(api, patched_run_async):
    host = MCPHost(api, MCPSettings(enabled=True, port=18000))
    await host.start()
    try:
        first_task = host._task
        await host.apply(MCPSettings(enabled=True, port=18001))
        assert host.is_running
        assert host._task is not first_task
        assert host._server.settings.port == 18001
    finally:
        await host.stop()


async def test_apply_noop_when_nothing_changed(api, patched_run_async):
    settings = MCPSettings(enabled=True, port=18002)
    host = MCPHost(api, settings)
    await host.start()
    try:
        first_task = host._task
        await host.apply(MCPSettings(enabled=True, port=18002))
        assert host._task is first_task  # no restart
    finally:
        await host.stop()


async def test_apply_rolls_back_settings_on_start_failure(api, monkeypatch):
    """If start() raises (e.g. ImportError when mcp pkg is missing), the
    stored settings revert so the next apply() sees the real state."""
    host = MCPHost(api, MCPSettings(enabled=False, port=18003))

    async def boom() -> None:
        raise ImportError("the 'mcp' package is required")

    monkeypatch.setattr(host, "start", boom)

    with pytest.raises(ImportError):
        await host.apply(MCPSettings(enabled=True, port=18003))

    # Settings rolled back: enabled=False, no task running.
    assert host.settings.enabled is False
    assert host.is_running is False


# ---------------------------------------------------------------------------
# Rebind — tests against the real build_mcp_server (no transport).
# ---------------------------------------------------------------------------

def test_build_mcp_server_exposes_rebind_hook(api):
    mcp = build_mcp_server(api)
    assert callable(getattr(mcp, "_protopoke_rebind", None))


def test_rebind_swaps_api_in_tool_closure(api):
    """After rebind, tools see the new ProtoPokeAPI instance."""
    mcp = build_mcp_server(api)

    # Sanity: proxy_status tool returns a dict derived from the current api.
    tool = mcp._tool_manager.get_tool("proxy_status")
    result_before = tool.fn()
    assert result_before["total_sessions"] == 0

    # Build a fresh API with different config; rebind should swap.
    new_api = _make_api(port=29000)
    mcp._protopoke_rebind(new_api)

    result_after = tool.fn()
    # The rebind made the tool see the new api: forwarders match the new instance.
    assert result_after["configured_forwarders"] == [f.name for f in new_api.forwarders]


async def test_mcphost_rebind_uses_server_hook(api, patched_run_async):
    host = MCPHost(api, MCPSettings(enabled=True))
    await host.start()
    try:
        new_api = _make_api(port=29001)
        host.rebind(new_api)
        tool = host._server._tool_manager.get_tool("proxy_status")
        assert tool.fn()["configured_forwarders"] == [f.name for f in new_api.forwarders]
    finally:
        await host.stop()


def test_rebind_when_not_running_updates_initial_provider(api):
    """If the host is not running, rebind simply stashes the new api."""
    host = MCPHost(api, MCPSettings(enabled=False))
    new_api = _make_api(port=29002)
    host.rebind(new_api)
    assert host._initial_provider is new_api


# ---------------------------------------------------------------------------
# Provider callable
# ---------------------------------------------------------------------------

async def test_provider_callable_is_resolved_on_start(patched_run_async):
    api = _make_api(port=39000)
    calls = {"count": 0}

    def provider():
        calls["count"] += 1
        return api

    host = MCPHost(provider, MCPSettings(enabled=True))
    await host.start()
    try:
        assert calls["count"] == 1
    finally:
        await host.stop()


def test_provider_callable_type_error_if_wrong_return():
    host = MCPHost(lambda: "not an api", MCPSettings(enabled=True))
    with pytest.raises(TypeError):
        host._resolve_api()
