"""Tests for UDP session reuse via playbooks and send_frame."""

from __future__ import annotations

import asyncio

from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig, ForwarderType
from protopoke.forge.models import Playbook, PlaybookFrame
from protopoke.models import Direction

from .conftest import free_port


class _EchoUdp(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(data.upper(), addr)


async def _start_udp_echo() -> tuple[asyncio.DatagramTransport, int]:
    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        _EchoUdp,
        local_addr=("127.0.0.1", 0),
    )
    return transport, transport.get_extra_info("sockname")[1]


async def _send_udp_and_collect(
    listen_port: int, payload: bytes, wait: float = 0.2
) -> bytes:
    """Send one datagram to *listen_port* and read one reply."""
    loop = asyncio.get_event_loop()
    replies: asyncio.Queue = asyncio.Queue()

    class _Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            replies.put_nowait(data)

    transport, _ = await loop.create_datagram_endpoint(
        _Proto, remote_addr=("127.0.0.1", listen_port),
    )
    try:
        transport.sendto(payload)
        try:
            return await asyncio.wait_for(replies.get(), timeout=wait + 0.5)
        except asyncio.TimeoutError:
            return b""
    finally:
        transport.close()


# ---------------------------------------------------------------------------
# Playbook reuse — UDP forge session
# ---------------------------------------------------------------------------

async def test_playbook_reuses_existing_udp_forge_session():
    """Binding a playbook to an existing UDP forge session reuses the socket."""
    echo_transport, echo_port = await _start_udp_echo()
    try:
        api = ProtoPokeAPI(forwarders=[])
        forge_id = await api.open_forge_session(
            "127.0.0.1", echo_port, transport="udp",
        )
        try:
            pb = Playbook.create(
                label="reuse-udp",
                host="127.0.0.1",
                port=echo_port,
                response_window=0.3,
                transport="udp",
                source_session_id=forge_id,
            )
            pb.frames.append(PlaybookFrame.create(label="a", raw_hex="61"))
            run = await api.run_playbook(pb)

            # Bound session is preserved.
            assert pb.source_session_id == forge_id

            recv = [t for t in run.traffic if t.direction == "received"]
            assert [t.raw_bytes for t in recv] == [b"A"]
        finally:
            await api.forge_engine.close_forge_session(forge_id)
    finally:
        echo_transport.close()


# ---------------------------------------------------------------------------
# Playbook reuse — UDP proxy session (forwarder-captured)
# ---------------------------------------------------------------------------

async def test_playbook_injects_into_existing_udp_proxy_session():
    """A UDP playbook bound to a live proxy session injects into the flow."""
    listen_port = free_port()
    echo_transport, echo_port = await _start_udp_echo()
    try:
        config = ForwarderConfig(
            name="udp-reuse",
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
            # Bootstrap the UDP flow so the registry holds an active session.
            reply = await _send_udp_and_collect(listen_port, b"ping")
            assert reply == b"PING"

            sessions = api.list_active_sessions()
            assert len(sessions) == 1
            sess = sessions[0]
            assert sess.info.transport == "udp"

            pb = Playbook.create(
                label="inject-udp",
                host="127.0.0.1",
                port=echo_port,
                response_window=0.3,
                transport="udp",
                source_session_id=sess.id,
            )
            pb.frames.append(PlaybookFrame.create(label="x", raw_hex="78"))
            run = await api.run_playbook(pb)
            # source_session_id stays pointing at the proxy session.
            assert pb.source_session_id == sess.id

            sent = [t for t in run.traffic if t.direction == "sent"]
            recv = [t for t in run.traffic if t.direction == "received"]
            assert [t.raw_bytes for t in sent] == [b"x"]
            # Echo returns uppercased; the injected frame goes upstream and the
            # reply is captured on the flow.
            assert [t.raw_bytes for t in recv] == [b"X"]
        finally:
            await api.stop()
    finally:
        echo_transport.close()


# ---------------------------------------------------------------------------
# send_frame reuse — UDP forge session
# ---------------------------------------------------------------------------

async def test_send_frame_reuses_existing_udp_forge_session():
    echo_transport, echo_port = await _start_udp_echo()
    try:
        api = ProtoPokeAPI(forwarders=[])
        forge_id = await api.open_forge_session(
            "127.0.0.1", echo_port, transport="udp",
        )
        try:
            result = await api.send_frame(
                data=b"hello",
                transport="udp",
                source_session_id=forge_id,
                receive_timeout=0.3,
            )
            assert result.success, result.error
            assert result.sent_bytes == b"hello"
            assert result.received_bytes == b"HELLO"
            # The forge session is still alive after the send.
            assert api.forge_engine.is_forge_session(forge_id)
        finally:
            await api.forge_engine.close_forge_session(forge_id)
    finally:
        echo_transport.close()


# ---------------------------------------------------------------------------
# send_frame reuse — UDP proxy session
# ---------------------------------------------------------------------------

async def test_send_frame_injects_into_existing_udp_proxy_session():
    listen_port = free_port()
    echo_transport, echo_port = await _start_udp_echo()
    try:
        config = ForwarderConfig(
            name="udp-sendframe-reuse",
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
            await _send_udp_and_collect(listen_port, b"boot")

            sessions = api.list_active_sessions()
            assert len(sessions) == 1
            sess_id = sessions[0].id

            result = await api.send_frame(
                data=b"hi",
                transport="udp",
                source_session_id=sess_id,
                receive_timeout=0.3,
            )
            assert result.success, result.error
            assert result.sent_bytes == b"hi"
            assert result.received_bytes == b"HI"

            frames = api.get_frames(sess_id)
            c2s = [f for f in frames if f.direction is Direction.CLIENT_TO_SERVER]
            # The bootstrap "boot" plus the injected "hi".
            assert b"hi" in [f.raw_bytes for f in c2s]
        finally:
            await api.stop()
    finally:
        echo_transport.close()


# ---------------------------------------------------------------------------
# send_frame error paths
# ---------------------------------------------------------------------------

async def test_send_frame_transport_mismatch_returns_failure():
    echo_transport, echo_port = await _start_udp_echo()
    try:
        api = ProtoPokeAPI(forwarders=[])
        forge_id = await api.open_forge_session(
            "127.0.0.1", echo_port, transport="udp",
        )
        try:
            # Bound session is UDP but the caller asks for TCP.
            result = await api.send_frame(
                data=b"x",
                transport="tcp",
                source_session_id=forge_id,
                receive_timeout=0.1,
            )
            assert not result.success
            assert "transport" in (result.error or "").lower()
        finally:
            await api.forge_engine.close_forge_session(forge_id)
    finally:
        echo_transport.close()


async def test_send_frame_unknown_session_returns_failure():
    api = ProtoPokeAPI(forwarders=[])
    result = await api.send_frame(
        data=b"x",
        source_session_id="not-a-real-session",
        receive_timeout=0.1,
    )
    assert not result.success
    assert "not found" in (result.error or "").lower()
