"""
Integration tests for the fuzzing subsystem — requires ProxyAPI + TLS + network.

These tests are separated from test_fuzzing.py so that the pure unit tests
always run even in environments where the `cryptography` package is broken.
"""

from __future__ import annotations

import asyncio
import pytest

from protopoke.config import ProxyConfig
from protopoke.api import ProxyAPI
from protopoke.fuzzing.models import CampaignStatus, FuzzResult
from protopoke.fuzzing.mutators import BitFlipMutator, KnownBadMutator
from tests.conftest import echo_server_ctx, free_port


async def _capture(api: ProxyAPI, listen_port: int, data: bytes) -> str:
    reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
    writer.write(data)
    await writer.drain()
    writer.write_eof()
    try:
        await asyncio.wait_for(reader.read(65536), timeout=3.0)
    except asyncio.TimeoutError:
        pass
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    await asyncio.sleep(0.15)
    return api.list_sessions()[-1].id


class TestFuzzSessionAPI:
    @pytest.mark.asyncio
    async def test_campaign_completes(self):
        async with echo_server_ctx() as (h, p):
            port = free_port()
            api  = ProxyAPI(ProxyConfig(
                listen_host="127.0.0.1", listen_port=port,
                upstream_host=h, upstream_port=p,
            ))
            await api.start()
            try:
                sid      = await _capture(api, port, b"hello fuzzer")
                campaign = await api.fuzz_session(
                    session_id=sid,
                    mutators=[BitFlipMutator(), KnownBadMutator()],
                    iterations=5,
                )
                assert campaign.status is CampaignStatus.DONE
                assert campaign.completed_iterations == 5
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_on_result_callback(self):
        async with echo_server_ctx() as (h, p):
            port = free_port()
            api  = ProxyAPI(ProxyConfig(
                listen_host="127.0.0.1", listen_port=port,
                upstream_host=h, upstream_port=p,
            ))
            await api.start()
            try:
                sid       = await _capture(api, port, b"callback test")
                collected: list[FuzzResult] = []
                await api.fuzz_session(
                    session_id=sid,
                    mutators=[BitFlipMutator()],
                    iterations=3,
                    on_result=collected.append,
                )
                assert len(collected) == 3
                assert all(isinstance(r, FuzzResult) for r in collected)
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_frame_selector(self):
        async with echo_server_ctx() as (h, p):
            port = free_port()
            api  = ProxyAPI(ProxyConfig(
                listen_host="127.0.0.1", listen_port=port,
                upstream_host=h, upstream_port=p,
                framer_name="delimiter",
                framer_kwargs={"delimiter": b"\n"},
            ))
            await api.start()
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                for i in range(3):
                    writer.write(f"msg{i}\n".encode())
                await writer.drain()
                writer.write_eof()
                try:
                    await asyncio.wait_for(reader.read(65536), timeout=3.0)
                except asyncio.TimeoutError:
                    pass
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                await asyncio.sleep(0.15)

                sid      = api.list_sessions()[-1].id
                campaign = await api.fuzz_session(
                    session_id=sid,
                    mutators=[BitFlipMutator()],
                    iterations=3,
                    frame_selector="1",
                )
                assert campaign.status is CampaignStatus.DONE
            finally:
                await api.stop()
