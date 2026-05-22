"""End-to-end UDP proxy tests."""

from __future__ import annotations

import asyncio
from typing import Optional

import pytest

from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig, ForwarderType
from protopoke.models import Direction, SessionState

from .conftest import free_port


class _EchoUdp(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)


async def _start_udp_echo(host: str = "127.0.0.1", port: Optional[int] = None) -> tuple[asyncio.DatagramTransport, int]:
    """Start a UDP echo server. Returns (transport, bound_port)."""
    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        _EchoUdp,
        local_addr=(host, port or 0),
    )
    bound = transport.get_extra_info("sockname")[1]
    return transport, bound


async def test_udp_forwarder_relays_datagram_and_creates_session():
    listen_port = free_port()
    echo_transport, echo_port = await _start_udp_echo()
    try:
        config = ForwarderConfig(
            name="udp-test",
            forwarder_type=ForwarderType.UDP,
            listen_host="127.0.0.1",
            listen_port=listen_port,
            upstream_host="127.0.0.1",
            upstream_port=echo_port,
        )
        api = ProtoPokeAPI(forwarders=[config])
        await api.start()
        try:
            await asyncio.sleep(0.05)

            loop = asyncio.get_event_loop()
            client_queue: asyncio.Queue = asyncio.Queue()

            class _ClientProto(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    client_queue.put_nowait(data)

            client_transport, _ = await loop.create_datagram_endpoint(
                _ClientProto,
                remote_addr=("127.0.0.1", listen_port),
            )
            try:
                client_transport.sendto(b"ping")
                reply = await asyncio.wait_for(client_queue.get(), timeout=2.0)
                assert reply == b"ping"
            finally:
                client_transport.close()

            await asyncio.sleep(0.05)

            sessions = api.list_sessions()
            assert len(sessions) == 1
            info = sessions[0].info
            assert info.transport == "udp"
            assert info.state is SessionState.ACTIVE

            frames = api.get_frames(info.id)
            c2s = [f for f in frames if f.direction is Direction.CLIENT_TO_SERVER]
            s2c = [f for f in frames if f.direction is Direction.SERVER_TO_CLIENT]
            assert len(c2s) == 1
            assert c2s[0].raw_bytes == b"ping"
            assert len(s2c) == 1
            assert s2c[0].raw_bytes == b"ping"
        finally:
            await api.stop()
    finally:
        echo_transport.close()


async def test_udp_flow_stays_open_when_idle():
    """A UDP flow must NOT be closed just because it's been quiet for a while.

    UDP has no FIN and this tool is meant for reverse engineering — pausing on
    an intercept or stepping away to inspect frames must not silently fragment
    the capture.  The flow lives until forwarder stop or explicit termination.
    """
    listen_port = free_port()
    echo_transport, echo_port = await _start_udp_echo()
    try:
        config = ForwarderConfig(
            name="udp-idle",
            forwarder_type=ForwarderType.UDP,
            listen_host="127.0.0.1",
            listen_port=listen_port,
            upstream_host="127.0.0.1",
            upstream_port=echo_port,
        )
        api = ProtoPokeAPI(forwarders=[config])
        await api.start()
        try:
            await asyncio.sleep(0.05)
            loop = asyncio.get_event_loop()
            replies: asyncio.Queue = asyncio.Queue()

            class _ClientProto(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    replies.put_nowait(data)

            client_transport, _ = await loop.create_datagram_endpoint(
                _ClientProto,
                remote_addr=("127.0.0.1", listen_port),
            )
            try:
                client_transport.sendto(b"hi")
                await asyncio.wait_for(replies.get(), timeout=1.0)
                await asyncio.sleep(1.5)  # sit idle past any plausible old timeout
                sessions = api.list_sessions()
                assert len(sessions) == 1
                assert sessions[0].info.state is SessionState.ACTIVE

                # Same source-port reuses the existing flow / session.
                client_transport.sendto(b"hi-again")
                await asyncio.wait_for(replies.get(), timeout=1.0)
                sessions = api.list_sessions()
                assert len(sessions) == 1
                assert sessions[0].info.state is SessionState.ACTIVE
            finally:
                client_transport.close()
        finally:
            await api.stop()
    finally:
        echo_transport.close()


async def test_udp_terminate_session_closes_flow():
    """Operator-driven termination is the only way a UDP session reaches CLOSED."""
    listen_port = free_port()
    echo_transport, echo_port = await _start_udp_echo()
    try:
        config = ForwarderConfig(
            name="udp-terminate",
            forwarder_type=ForwarderType.UDP,
            listen_host="127.0.0.1",
            listen_port=listen_port,
            upstream_host="127.0.0.1",
            upstream_port=echo_port,
        )
        api = ProtoPokeAPI(forwarders=[config])
        await api.start()
        try:
            await asyncio.sleep(0.05)
            loop = asyncio.get_event_loop()
            replies: asyncio.Queue = asyncio.Queue()

            class _ClientProto(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    replies.put_nowait(data)

            client_transport, _ = await loop.create_datagram_endpoint(
                _ClientProto,
                remote_addr=("127.0.0.1", listen_port),
            )
            try:
                client_transport.sendto(b"hi")
                await asyncio.wait_for(replies.get(), timeout=1.0)

                sessions = api.list_sessions()
                assert len(sessions) == 1
                sid = sessions[0].info.id

                await api.terminate_session(sid)
                await asyncio.sleep(0.05)
                assert api.list_sessions()[0].info.state is SessionState.CLOSED
            finally:
                client_transport.close()
        finally:
            await api.stop()
    finally:
        echo_transport.close()


async def test_udp_send_frame_one_shot():
    """Forge UDP one-shot send through ProtoPokeAPI.send_frame."""
    echo_transport, echo_port = await _start_udp_echo()
    try:
        api = ProtoPokeAPI(forwarders=[])
        result = await api.send_frame(
            data=b"hello-udp",
            host="127.0.0.1",
            port=echo_port,
            transport="udp",
            receive_timeout=1.0,
        )
        assert result.success is True
        assert result.received_bytes == b"hello-udp"
        assert result.response_packets == [b"hello-udp"]
    finally:
        echo_transport.close()


async def test_udp_open_forge_session_persistent():
    echo_transport, echo_port = await _start_udp_echo()
    try:
        api = ProtoPokeAPI(forwarders=[])
        sid = await api.open_forge_session("127.0.0.1", echo_port, transport="udp")
        try:
            r1 = await api.send_on_forge_session(sid, b"first", receive_timeout=1.0)
            assert r1.success
            assert r1.received_bytes == b"first"
            r2 = await api.send_on_forge_session(sid, b"second", receive_timeout=1.0)
            assert r2.success
            assert r2.received_bytes == b"second"
            session = api.get_session(sid)
            assert session is not None
            assert session.info.transport == "udp"
        finally:
            await api.forge_engine.close_forge_session(sid)
    finally:
        echo_transport.close()
