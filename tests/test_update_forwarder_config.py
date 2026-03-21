"""
Tests for ProxyAPI.update_forwarder_config() — hot-swapping name, framing,
and protocol definition on a running forwarder.
"""

from __future__ import annotations

import asyncio
import os
import tempfile

import pytest

from protopoke.api import ProxyAPI
from protopoke.config import ForwarderConfig, ProxyConfig
from protopoke.models import Direction
from tests.conftest import echo_server_ctx, free_port


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def send_recv(host: str, port: int, data: bytes, timeout: float = 5.0) -> bytes:
    """Connect, send data, receive response, close."""
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(data)
        await writer.drain()
        writer.write_eof()
        return await asyncio.wait_for(reader.read(65536), timeout=timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def make_api(listen_port: int, upstream_host: str, upstream_port: int,
             name: str = "Test") -> ProxyAPI:
    fwd = ForwarderConfig(
        name=name,
        config=ProxyConfig(
            listen_host="127.0.0.1",
            listen_port=listen_port,
            upstream_host=upstream_host,
            upstream_port=upstream_port,
        ),
    )
    return ProxyAPI([fwd])


# ---------------------------------------------------------------------------
# Rename
# ---------------------------------------------------------------------------

class TestRenameForwarder:
    async def test_rename_updates_engine_registry(self):
        async with echo_server_ctx() as (host, port):
            api = make_api(free_port(), host, port, name="OldName")
            await api.start_forwarder("OldName")
            try:
                result = api.update_forwarder_config("OldName", new_name="NewName")
                assert result["renamed"] is True

                # Engine registry should use the new name
                assert "NewName" in api._engines
                assert "OldName" not in api._engines

                # Forwarder config list should reflect the new name
                assert api.forwarders[0].name == "NewName"

                # Running check should use new name
                assert api.is_running("NewName")
                assert not api.is_running("OldName")
            finally:
                await api.stop_forwarder("NewName")

    async def test_rename_updates_existing_sessions(self):
        async with echo_server_ctx() as (host, port):
            listen_port = free_port()
            api = make_api(listen_port, host, port, name="Before")
            await api.start_forwarder("Before")
            try:
                # Create a session by sending traffic
                await send_recv("127.0.0.1", listen_port, b"hello")
                await asyncio.sleep(0.1)

                sessions = api.list_sessions()
                assert len(sessions) >= 1
                assert sessions[0].info.forwarder_name == "Before"

                # Rename
                api.update_forwarder_config("Before", new_name="After")

                # Existing sessions should now reference the new name
                sessions = api.list_sessions()
                for s in sessions:
                    assert s.info.forwarder_name == "After"
            finally:
                await api.stop_forwarder("After")

    async def test_rename_to_duplicate_raises(self):
        fwds = [
            ForwarderConfig(name="A", config=ProxyConfig(listen_port=free_port())),
            ForwarderConfig(name="B", config=ProxyConfig(listen_port=free_port())),
        ]
        api = ProxyAPI(fwds)
        with pytest.raises(KeyError, match="already in use"):
            api.update_forwarder_config("A", new_name="B")

    async def test_rename_nonexistent_raises(self):
        api = make_api(free_port(), "127.0.0.1", 1234)
        with pytest.raises(KeyError, match="No forwarder named"):
            api.update_forwarder_config("NoSuch", new_name="X")


# ---------------------------------------------------------------------------
# Framing hot-swap
# ---------------------------------------------------------------------------

class TestFramingHotSwap:
    async def test_swap_framer_on_running_sessions(self):
        async with echo_server_ctx() as (host, port):
            listen_port = free_port()
            api = make_api(listen_port, host, port)
            await api.start_forwarder("Test")
            try:
                # Open a persistent connection
                reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
                writer.write(b"first\n")
                await writer.drain()
                await asyncio.sleep(0.1)

                # Swap to line framer
                result = api.update_forwarder_config(
                    "Test",
                    framer_name="line",
                )
                assert result["sessions_reframed"] >= 1

                # Config should be updated
                assert api.forwarders[0].config.framer_name == "line"

                writer.close()
                await writer.wait_closed()
            finally:
                await api.stop_forwarder("Test")

    async def test_swap_framer_updates_config(self):
        api = make_api(free_port(), "127.0.0.1", 1234)
        api.update_forwarder_config(
            "Test",
            framer_name="delimiter",
            framer_kwargs={"delimiter": b"\r\n"},
        )
        cfg = api.forwarders[0].config
        assert cfg.framer_name == "delimiter"
        assert cfg.framer_kwargs == {"delimiter": b"\r\n"}


# ---------------------------------------------------------------------------
# Protocol definition hot-swap
# ---------------------------------------------------------------------------

class TestProtocolHotSwap:
    async def test_set_protocol_definition(self):
        api = make_api(free_port(), "127.0.0.1", 1234)

        # Write a minimal protocol definition to a temp file
        import yaml
        defn = {
            "name": "TestProto",
            "endianness": "big",
            "messages": [
                {
                    "name": "Generic",
                    "match": {"type": "always"},
                    "fields": [
                        {"name": "data", "type": "bytes", "length": "remaining"},
                    ],
                }
            ],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(defn, f)
            path = f.name

        try:
            result = api.update_forwarder_config(
                "Test",
                protocol_definition_path=path,
            )
            assert result["protocol_set"] is True
            assert api.forwarders[0].config.protocol_definition_path == path
            assert api._decoder.protocol_name == "TestProto"
        finally:
            os.unlink(path)

    async def test_clear_protocol_definition(self):
        api = make_api(free_port(), "127.0.0.1", 1234)

        result = api.update_forwarder_config(
            "Test",
            protocol_definition_path="",
        )
        assert result["protocol_set"] is True
        # Should fall back to passthrough decoder
        assert api._decoder.protocol_name == "raw"


# ---------------------------------------------------------------------------
# Combined changes
# ---------------------------------------------------------------------------

class TestCombinedHotSwap:
    async def test_rename_and_reframe_together(self):
        async with echo_server_ctx() as (host, port):
            listen_port = free_port()
            api = make_api(listen_port, host, port, name="Old")
            await api.start_forwarder("Old")
            try:
                # Open a connection to create a session
                reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
                writer.write(b"data")
                await writer.drain()
                await asyncio.sleep(0.1)

                result = api.update_forwarder_config(
                    "Old",
                    new_name="New",
                    framer_name="line",
                )
                assert result["renamed"] is True
                assert result["sessions_reframed"] >= 1
                assert api.forwarders[0].name == "New"
                assert api.forwarders[0].config.framer_name == "line"
                assert api.is_running("New")

                writer.close()
                await writer.wait_closed()
            finally:
                await api.stop_forwarder("New")

    async def test_no_changes_is_noop(self):
        api = make_api(free_port(), "127.0.0.1", 1234)
        result = api.update_forwarder_config("Test")
        assert result["renamed"] is False
        assert result["sessions_reframed"] == 0
        assert result["protocol_set"] is False
