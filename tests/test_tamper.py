"""Tests for intercept controllers."""

from __future__ import annotations

import asyncio

import pytest

from protopoke.models import Direction, Frame, InterceptAction
from protopoke.tamper.controller import PassthroughController, QueuedTamperController


def make_frame(data: bytes = b"test", seq: int = 0) -> Frame:
    return Frame.create("session-1", Direction.CLIENT_TO_SERVER, data, seq)


# ---------------------------------------------------------------------------
# PassthroughController
# ---------------------------------------------------------------------------

class TestPassthroughController:
    @pytest.mark.asyncio
    async def test_always_forwards(self):
        ctrl = PassthroughController()
        unit = await ctrl.process(make_frame(b"data"))
        assert unit.action is InterceptAction.FORWARD

    @pytest.mark.asyncio
    async def test_frame_preserved(self):
        ctrl = PassthroughController()
        frame = make_frame(b"preserved")
        unit = await ctrl.process(frame)
        assert unit.frame is frame

    @pytest.mark.asyncio
    async def test_shutdown_does_nothing(self):
        ctrl = PassthroughController()
        await ctrl.shutdown()  # Should not raise


# ---------------------------------------------------------------------------
# QueuedTamperController — disabled mode
# ---------------------------------------------------------------------------

class TestQueuedControllerDisabled:
    @pytest.mark.asyncio
    async def test_disabled_forwards_immediately(self):
        ctrl = QueuedTamperController(tamper_enabled=False)
        unit = await ctrl.process(make_frame())
        assert unit.action is InterceptAction.FORWARD

    @pytest.mark.asyncio
    async def test_disabled_no_pending(self):
        ctrl = QueuedTamperController(tamper_enabled=False)
        await ctrl.process(make_frame())
        assert ctrl.pending_count() == 0


# ---------------------------------------------------------------------------
# QueuedTamperController — enabled mode
# ---------------------------------------------------------------------------

class TestQueuedControllerEnabled:
    @pytest.mark.asyncio
    async def test_intercepts_and_blocks(self):
        ctrl = QueuedTamperController(tamper_enabled=True)
        frame = make_frame(b"blocked")

        # Start processing in a task — it will block
        task = asyncio.create_task(ctrl.process(frame))
        await asyncio.sleep(0)  # Let the task run up to the await

        assert ctrl.pending_count() == 1

        # Resolve it
        pending = ctrl.list_pending()
        ctrl.forward(pending[0].id)

        unit = await task
        assert unit.action is InterceptAction.FORWARD

    @pytest.mark.asyncio
    async def test_drop_verdict(self):
        ctrl = QueuedTamperController(tamper_enabled=True)
        task = asyncio.create_task(ctrl.process(make_frame(b"drop me")))
        await asyncio.sleep(0)

        [pending] = ctrl.list_pending()
        ctrl.drop(pending.id)

        unit = await task
        assert unit.action is InterceptAction.DROP

    @pytest.mark.asyncio
    async def test_modify_verdict(self):
        ctrl = QueuedTamperController(tamper_enabled=True)
        task = asyncio.create_task(ctrl.process(make_frame(b"original")))
        await asyncio.sleep(0)

        [pending] = ctrl.list_pending()
        ctrl.modify_and_forward(pending.id, b"modified")

        unit = await task
        assert unit.action is InterceptAction.MODIFIED
        assert unit.modified_data == b"modified"
        assert unit.effective_bytes() == b"modified"

    @pytest.mark.asyncio
    async def test_multiple_pending(self):
        ctrl = QueuedTamperController(tamper_enabled=True)
        task1 = asyncio.create_task(ctrl.process(make_frame(b"a", 0)))
        task2 = asyncio.create_task(ctrl.process(make_frame(b"b", 1)))
        await asyncio.sleep(0)

        assert ctrl.pending_count() == 2

        for p in ctrl.list_pending():
            ctrl.forward(p.id)

        await asyncio.gather(task1, task2)
        assert ctrl.pending_count() == 0

    @pytest.mark.asyncio
    async def test_toggle_off_forwards_pending(self):
        ctrl = QueuedTamperController(tamper_enabled=True)
        task = asyncio.create_task(ctrl.process(make_frame()))
        await asyncio.sleep(0)

        assert ctrl.pending_count() == 1
        ctrl.tamper_enabled = False  # Should forward all pending

        unit = await task
        assert unit.action is InterceptAction.FORWARD
        assert ctrl.pending_count() == 0

    @pytest.mark.asyncio
    async def test_get_pending_returns_next_queued(self):
        ctrl = QueuedTamperController(tamper_enabled=True)
        frame = make_frame(b"queued")

        process_task = asyncio.create_task(ctrl.process(frame))
        await asyncio.sleep(0)

        queued_unit = await ctrl.get_pending()
        assert queued_unit.frame.raw_bytes == b"queued"

        ctrl.forward(queued_unit.id)
        await process_task

    @pytest.mark.asyncio
    async def test_forward_all(self):
        ctrl = QueuedTamperController(tamper_enabled=True)
        tasks = [asyncio.create_task(ctrl.process(make_frame(bytes([i])))) for i in range(5)]
        await asyncio.sleep(0)

        count = ctrl.forward_all()
        assert count == 5

        results = await asyncio.gather(*tasks)
        assert all(u.action is InterceptAction.FORWARD for u in results)

    @pytest.mark.asyncio
    async def test_set_verdict_unknown_id_returns_false(self):
        ctrl = QueuedTamperController(tamper_enabled=True)
        result = ctrl.set_verdict("nonexistent-id", InterceptAction.FORWARD)
        assert result is False

    @pytest.mark.asyncio
    async def test_shutdown_forwards_pending(self):
        ctrl = QueuedTamperController(tamper_enabled=True)
        task = asyncio.create_task(ctrl.process(make_frame()))
        await asyncio.sleep(0)

        await ctrl.shutdown()
        unit = await task
        assert unit.action is InterceptAction.FORWARD
