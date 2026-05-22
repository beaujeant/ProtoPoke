"""UDP playbook execution tests."""

from __future__ import annotations

import asyncio
from typing import Optional

import pytest

from protopoke.api import ProtoPokeAPI
from protopoke.forge.models import Playbook, PlaybookFrame


class _EchoUdp(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # Reply with the bytes uppercased so we can distinguish send vs recv.
        self.transport.sendto(data.upper(), addr)


async def _start_udp_echo() -> tuple[asyncio.DatagramTransport, int]:
    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        _EchoUdp,
        local_addr=("127.0.0.1", 0),
    )
    return transport, transport.get_extra_info("sockname")[1]


async def test_udp_playbook_runs_and_records_traffic():
    transport, echo_port = await _start_udp_echo()
    try:
        api = ProtoPokeAPI(forwarders=[])
        pb = Playbook.create(
            label="udp-pb",
            host="127.0.0.1",
            port=echo_port,
            response_window=0.5,
            transport="udp",
        )
        pb.frames.append(PlaybookFrame.create(label="hello", raw_hex="68 65 6c 6c 6f"))
        pb.frames.append(PlaybookFrame.create(label="world", raw_hex="77 6f 72 6c 64"))

        run = await api.run_playbook(pb)
        assert pb.transport == "udp"

        sent = [t for t in run.traffic if t.direction == "sent"]
        recv = [t for t in run.traffic if t.direction == "received"]
        assert [t.raw_bytes for t in sent] == [b"hello", b"world"]
        assert [t.raw_bytes for t in recv] == [b"HELLO", b"WORLD"]

        # The forge session opened during the playbook should persist on the
        # playbook for reuse; close it for cleanup.
        if pb.source_session_id:
            await api.forge_engine.close_forge_session(pb.source_session_id)
    finally:
        transport.close()


async def test_udp_playbook_drops_mismatched_source_session():
    """A TCP source session should be ignored when the playbook is UDP."""
    transport, echo_port = await _start_udp_echo()
    try:
        api = ProtoPokeAPI(forwarders=[])

        # Open a TCP forge session against the echo port (the connect will
        # fail because the echo is UDP, so just create a stub session in the
        # registry instead).
        from protopoke.models import SessionInfo
        from protopoke.core.session import Session
        info = SessionInfo.create("forge", 0, "127.0.0.1", echo_port, transport="tcp")
        api.session_registry._sessions[info.id] = Session(info)
        info.state = info.state  # no-op; just to silence linter
        api.session_registry.mark_active(info.id)

        pb = Playbook.create(
            label="udp-pb-mismatch",
            host="127.0.0.1",
            port=echo_port,
            response_window=0.5,
            transport="udp",
            source_session_id=info.id,
        )
        pb.frames.append(PlaybookFrame.create(label="x", raw_hex="78"))
        run = await api.run_playbook(pb)
        # The TCP source session should have been dropped; a fresh UDP forge
        # session should have been opened.
        assert pb.source_session_id != info.id
        recv = [t for t in run.traffic if t.direction == "received"]
        assert len(recv) == 1
        assert recv[0].raw_bytes == b"X"
        if pb.source_session_id:
            await api.forge_engine.close_forge_session(pb.source_session_id)
    finally:
        transport.close()
