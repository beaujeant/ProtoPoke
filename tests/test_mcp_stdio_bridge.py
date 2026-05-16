"""Tests for protopoke.mcp.stdio_bridge.

The bridge is a stdio MCP server that forwards every message to an HTTP
MCP server. We test it end-to-end:

  Test process
       │
       │  spawns
       ▼
  protopoke-mcp (the bridge, as a Python subprocess)
       │  stdio
       ▼  ─────────  HTTP  ────────►
                                       in-process FastMCP server
                                       built from build_mcp_server(api)

We connect to the bridge with the standard `mcp.client.stdio` transport
and assert that initialize / tools/list / tools/call all round-trip
correctly.
"""

from __future__ import annotations

import asyncio
import socket
import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Stub the TLS / cryptography native deps so the in-process server can be
# built in environments without a working _cffi_backend (same pattern as
# test_mcp_server.py / test_mcp_host.py).
# ---------------------------------------------------------------------------
def _make_tls_stubs() -> None:
    for mod_name in list(sys.modules):
        if mod_name.startswith("cryptography") or mod_name.startswith("protopoke.tls"):
            del sys.modules[mod_name]

    sys.modules.setdefault("cryptography", ModuleType("cryptography"))
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
from protopoke.mcp.server import build_mcp_server  # noqa: E402
from protopoke.mcp.stdio_bridge import _looks_like_connect_failure  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_api() -> ProtoPokeAPI:
    return ProtoPokeAPI([ForwarderConfig(
        name="BridgeTest",
        listen_port=23456,
        upstream_host="127.0.0.1",
        upstream_port=23457,
    )])


class _ServerHandle:
    def __init__(self, task: asyncio.Task, port: int) -> None:
        self.task = task
        self.port = port
        self.url = f"http://127.0.0.1:{port}/mcp"


async def _start_http_server(api: ProtoPokeAPI) -> _ServerHandle:
    """Start build_mcp_server(api) on a free port; return a handle."""
    port = _free_port()
    mcp = build_mcp_server(api)
    mcp.settings.host = "127.0.0.1"
    mcp.settings.port = port

    task = asyncio.create_task(mcp.run_streamable_http_async())
    # Wait for the listener to bind by polling the port.
    deadline = asyncio.get_event_loop().time() + 5.0
    while asyncio.get_event_loop().time() < deadline:
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.05)
            continue
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        break
    else:
        task.cancel()
        raise RuntimeError("MCP server did not bind in time")

    return _ServerHandle(task, port)


async def _stop_http_server(handle: _ServerHandle) -> None:
    handle.task.cancel()
    try:
        await handle.task
    except BaseException:
        pass


# ---------------------------------------------------------------------------
# Unit: connect-failure classifier
# ---------------------------------------------------------------------------

def test_classifier_recognises_connection_errors():
    assert _looks_like_connect_failure(ConnectionRefusedError())
    assert _looks_like_connect_failure(OSError("nope"))
    grp = ExceptionGroup("boom", [ConnectionRefusedError()])
    assert _looks_like_connect_failure(grp)


def test_classifier_rejects_unrelated_errors():
    assert not _looks_like_connect_failure(ValueError("bad arg"))


# ---------------------------------------------------------------------------
# End-to-end: bridge subprocess <-> in-process HTTP server
# ---------------------------------------------------------------------------

async def test_bridge_round_trips_tools_list_and_call():
    """Spawn the bridge, talk to it over stdio, verify it forwards to HTTP."""
    from mcp import StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.client.session import ClientSession

    api = _make_api()
    server = await _start_http_server(api)
    try:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "protopoke.mcp.stdio_bridge", "--url", server.url],
        )
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as session:
                await session.initialize()

                tools = await session.list_tools()
                names = {t.name for t in tools.tools}
                # Sanity: a few well-known tools must be exposed.
                assert "proxy_status" in names
                assert "list_forwarders" in names

                result = await session.call_tool("proxy_status", {})
                # Tool responses come back as structuredContent (when available)
                # plus a text block. Either way, we just need the call to succeed.
                assert result.isError is False
    finally:
        await _stop_http_server(server)


async def test_bridge_exits_when_http_server_unreachable():
    """If the HTTP server is not running, the bridge should exit nonzero
    with a friendly message on stderr (not a raw traceback)."""
    port = _free_port()
    url = f"http://127.0.0.1:{port}/mcp"

    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "protopoke.mcp.stdio_bridge", "--url", url,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    # Send a single JSON-RPC initialize so the bridge actually tries to talk
    # to the upstream HTTP server; without I/O it can sit idle forever.
    init = (
        b'{"jsonrpc":"2.0","id":1,"method":"initialize",'
        b'"params":{"protocolVersion":"2025-11-25",'
        b'"capabilities":{},"clientInfo":{"name":"test","version":"0.0"}}}\n'
    )
    try:
        proc.stdin.write(init)
        await proc.stdin.drain()
        proc.stdin.close()  # EOF tells the stdio reader to stop
    except Exception:
        pass

    try:
        rc = await asyncio.wait_for(proc.wait(), timeout=15.0)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        pytest.fail("bridge did not exit after upstream connection failure")

    stderr = (await proc.stderr.read()).decode("utf-8", errors="replace")
    assert rc != 0, f"expected nonzero exit; got {rc}, stderr={stderr!r}"
    assert "protopoke-mcp:" in stderr
    assert url in stderr
    assert "Start the TUI" in stderr
