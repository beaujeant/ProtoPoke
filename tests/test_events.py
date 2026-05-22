"""Tests for the event bus."""

from __future__ import annotations

import asyncio

import pytest

from protopoke.events.bus import EventBus, SessionOpenedEvent, FrameCapturedEvent
from protopoke.models import SessionInfo, Frame, Direction


def make_session_info() -> SessionInfo:
    return SessionInfo.create("127.0.0.1", 1234, "10.0.0.1", 80)


def make_frame() -> Frame:
    return Frame.create("sess", Direction.CLIENT_TO_SERVER, b"data", 0)


class TestEventBus:
    @pytest.mark.asyncio
    async def test_subscribe_and_publish(self):
        bus = EventBus()
        received = []

        async def handler(event: SessionOpenedEvent):
            received.append(event)

        bus.subscribe(SessionOpenedEvent, handler)
        event = SessionOpenedEvent(session=make_session_info())
        await bus.publish(event)

        assert len(received) == 1
        assert received[0] is event

    @pytest.mark.asyncio
    async def test_multiple_handlers(self):
        bus = EventBus()
        counts = [0, 0]

        async def h1(e): counts[0] += 1
        async def h2(e): counts[1] += 1

        bus.subscribe(SessionOpenedEvent, h1)
        bus.subscribe(SessionOpenedEvent, h2)
        await bus.publish(SessionOpenedEvent(session=make_session_info()))

        assert counts == [1, 1]

    @pytest.mark.asyncio
    async def test_publish_different_event_type(self):
        bus = EventBus()
        session_events = []
        frame_events = []

        async def on_session(e): session_events.append(e)
        async def on_frame(e): frame_events.append(e)

        bus.subscribe(SessionOpenedEvent, on_session)
        bus.subscribe(FrameCapturedEvent, on_frame)

        await bus.publish(SessionOpenedEvent(session=make_session_info()))
        assert len(session_events) == 1
        assert len(frame_events) == 0

        session = make_session_info()
        frame = make_frame()
        await bus.publish(FrameCapturedEvent(frame=frame, session=session))
        assert len(frame_events) == 1

    @pytest.mark.asyncio
    async def test_unsubscribe(self):
        bus = EventBus()
        received = []

        async def handler(e): received.append(e)

        bus.subscribe(SessionOpenedEvent, handler)
        bus.unsubscribe(SessionOpenedEvent, handler)
        await bus.publish(SessionOpenedEvent(session=make_session_info()))

        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_no_subscribers_no_error(self):
        bus = EventBus()
        await bus.publish(SessionOpenedEvent(session=make_session_info()))
        # Should not raise

    @pytest.mark.asyncio
    async def test_handler_exception_does_not_propagate(self):
        bus = EventBus()
        good_received = []

        async def bad_handler(e):
            raise RuntimeError("handler exploded")

        async def good_handler(e):
            good_received.append(e)

        bus.subscribe(SessionOpenedEvent, bad_handler)
        bus.subscribe(SessionOpenedEvent, good_handler)

        # Should not raise even though bad_handler raises
        await bus.publish(SessionOpenedEvent(session=make_session_info()))

        # The good handler still ran
        assert len(good_received) == 1

    @pytest.mark.asyncio
    async def test_handlers_run_concurrently(self):
        """Verify handlers are gathered (concurrent), not sequential."""
        bus = EventBus()
        order = []

        async def slow_first(e):
            await asyncio.sleep(0.02)
            order.append("slow")

        async def fast_second(e):
            await asyncio.sleep(0.001)
            order.append("fast")

        bus.subscribe(SessionOpenedEvent, slow_first)
        bus.subscribe(SessionOpenedEvent, fast_second)

        await bus.publish(SessionOpenedEvent(session=make_session_info()))

        # Fast completes before slow even though registered second
        assert order == ["fast", "slow"]
