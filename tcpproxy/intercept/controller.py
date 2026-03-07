"""
Interception controllers.

The intercept controller is the heart of this tool's "Burp Suite"-like behavior.
It sits between the relay (which reads raw bytes) and the destination socket
(which bytes are written to). Every Frame passes through it.

Two concrete implementations:

    PassthroughController:
        Immediately returns FORWARD for every frame. Use this for passive
        capture/logging where you don't want to pause traffic.

    QueuedInterceptController:
        Holds frames in an asyncio Queue. The relay awaits a verdict.
        An external caller (ProxyAPI, CLI, UI) polls get_pending() and calls
        set_verdict() / forward() / drop() / modify_and_forward().

How interception blocks the relay (but not other sessions):
    The relay is an asyncio Task. When it calls `await controller.process(frame)`,
    if the controller is QueuedInterceptController, it creates an asyncio.Future
    for this frame and awaits it. The event loop is free to run other coroutines
    (other sessions' relays, new connections, the API server) while this one
    frame waits. Only THIS direction of THIS session is paused.

Toggling interception at runtime:
    Set `controller.intercept_enabled = False` to immediately forward all
    currently pending frames and stop intercepting new ones.

Future extensions:
    - Per-session interception rules (only intercept session X)
    - Direction-specific interception (only client->server)
    - Filter-based interception (only intercept if bytes match a pattern)
    - Auto-forward rules (forward after N seconds if no human decision)
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Optional

from ..models import Frame, InterceptedUnit, InterceptAction

logger = logging.getLogger(__name__)


class InterceptController(ABC):
    """
    Abstract interface for intercept controllers.

    The relay calls process() for each Frame. The controller decides what
    to do and returns an InterceptedUnit with a verdict.
    """

    @abstractmethod
    async def process(self, frame: Frame) -> InterceptedUnit:
        """
        Process a frame and return a verdict.

        For PassthroughController: returns immediately.
        For QueuedInterceptController: blocks until an operator decides.

        Args:
            frame: The captured frame to process.

        Returns:
            InterceptedUnit with action set to FORWARD, DROP, or MODIFIED.
        """
        ...

    async def shutdown(self) -> None:
        """
        Clean up resources when the proxy is stopping.

        Override this to flush pending items, close queues, etc.
        """
        pass


# ---------------------------------------------------------------------------
# PassthroughController
# ---------------------------------------------------------------------------

class PassthroughController(InterceptController):
    """
    Forward-everything controller. No interception.

    Use this for passive capture and logging without pausing traffic.
    This is the default when intercept_enabled=False in ProxyConfig.
    """

    async def process(self, frame: Frame) -> InterceptedUnit:
        unit = InterceptedUnit.from_frame(frame)
        unit.action = InterceptAction.FORWARD
        return unit


# ---------------------------------------------------------------------------
# QueuedInterceptController
# ---------------------------------------------------------------------------

class QueuedInterceptController(InterceptController):
    """
    Hold-and-decide controller with an operator queue.

    When enabled:
        1. Each Frame is wrapped in an InterceptedUnit and added to _pending.
        2. The unit is put in _incoming_queue for the operator to consume.
        3. The relay awaits an asyncio.Future tied to the unit.
        4. The operator calls get_pending() → sets verdict via forward()/drop()/
           modify_and_forward() → the relay's Future resolves.
        5. The relay acts on the verdict and moves to the next frame.

    When disabled:
        Acts exactly like PassthroughController (immediate FORWARD).

    Thread safety:
        Designed for use within a single asyncio event loop thread.
        All accesses to _pending and _incoming_queue happen in coroutines
        that run on the same event loop, so no locks are needed.
    """

    def __init__(self, intercept_enabled: bool = True) -> None:
        self._intercept_enabled = intercept_enabled

        # Live futures: unit_id → (unit, Future[InterceptedUnit])
        # The Future is resolved when set_verdict() is called.
        self._pending: dict[str, tuple[InterceptedUnit, asyncio.Future]] = {}

        # Queue for the operator to pull pending units from.
        # The operator calls get_pending() which does queue.get().
        self._incoming_queue: asyncio.Queue[InterceptedUnit] = asyncio.Queue()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def intercept_enabled(self) -> bool:
        return self._intercept_enabled

    @intercept_enabled.setter
    def intercept_enabled(self, value: bool) -> None:
        """
        Toggle interception.

        When disabled, all currently pending frames are immediately forwarded.
        New frames will be forwarded without queuing.
        """
        self._intercept_enabled = value
        if not value:
            self._forward_all_pending()

    # ------------------------------------------------------------------
    # InterceptController interface
    # ------------------------------------------------------------------

    async def process(self, frame: Frame) -> InterceptedUnit:
        """
        If intercept is on: hold frame and wait for operator verdict.
        If intercept is off: forward immediately.
        """
        unit = InterceptedUnit.from_frame(frame)

        if not self._intercept_enabled:
            unit.action = InterceptAction.FORWARD
            return unit

        # Create a future this coroutine will await
        loop = asyncio.get_running_loop()
        future: asyncio.Future[InterceptedUnit] = loop.create_future()

        self._pending[unit.id] = (unit, future)
        await self._incoming_queue.put(unit)

        logger.debug(
            "Frame intercepted: unit=%s frame=%s session=%s dir=%s",
            unit.id[:8], frame.id[:8], frame.session_id[:8],
            frame.direction.value,
        )

        try:
            # Block this relay direction until an operator decides
            result = await future
            return result
        finally:
            # Always clean up even if the task is cancelled
            self._pending.pop(unit.id, None)

    async def shutdown(self) -> None:
        """Forward all pending items when the proxy shuts down."""
        self._forward_all_pending()

    # ------------------------------------------------------------------
    # Operator API
    # ------------------------------------------------------------------

    async def get_pending(self) -> InterceptedUnit:
        """
        Wait for and return the next intercepted unit.

        Call this from the ProxyAPI / UI / CLI to process the intercept queue.
        Blocks until a frame is available.
        """
        return await self._incoming_queue.get()

    def pending_count(self) -> int:
        """Number of frames currently waiting for a verdict."""
        return len(self._pending)

    def list_pending(self) -> list[InterceptedUnit]:
        """All frames currently waiting for a verdict (snapshot)."""
        return [unit for unit, _ in self._pending.values()]

    def set_verdict(
        self,
        unit_id:       str,
        action:        InterceptAction,
        modified_data: Optional[bytes] = None,
    ) -> bool:
        """
        Set the verdict for a pending intercepted unit.

        Args:
            unit_id:       ID of the InterceptedUnit to resolve.
            action:        What to do: FORWARD, DROP, or MODIFIED.
            modified_data: Replacement bytes (required when action=MODIFIED).

        Returns:
            True if the unit was found and resolved.
            False if unit_id is not in the pending queue (already resolved,
            or was never intercepted).
        """
        if unit_id not in self._pending:
            logger.warning("set_verdict: unknown unit_id=%s", unit_id)
            return False

        unit, future = self._pending[unit_id]

        if future.done():
            logger.warning("set_verdict: future already done for unit_id=%s", unit_id)
            return False

        unit.action = action
        if action is InterceptAction.MODIFIED:
            unit.modified_data = modified_data

        future.set_result(unit)
        logger.debug("Verdict set: unit=%s action=%s", unit_id[:8], action.value)
        return True

    # ------------------------------------------------------------------
    # Convenience shorthands
    # ------------------------------------------------------------------

    def forward(self, unit_id: str) -> bool:
        """Forward a pending unit as-is."""
        return self.set_verdict(unit_id, InterceptAction.FORWARD)

    def drop(self, unit_id: str) -> bool:
        """Drop a pending unit without forwarding."""
        return self.set_verdict(unit_id, InterceptAction.DROP)

    def modify_and_forward(self, unit_id: str, new_data: bytes) -> bool:
        """Forward a pending unit with replacement bytes."""
        return self.set_verdict(unit_id, InterceptAction.MODIFIED, new_data)

    def forward_all(self) -> int:
        """Forward all pending units. Returns the count forwarded."""
        count = 0
        for unit_id in list(self._pending.keys()):
            if self.forward(unit_id):
                count += 1
        return count

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _forward_all_pending(self) -> None:
        """Resolve all pending futures with FORWARD. Called on disable/shutdown."""
        for unit_id in list(self._pending.keys()):
            entry = self._pending.get(unit_id)
            if entry is None:
                continue
            unit, future = entry
            if not future.done():
                unit.action = InterceptAction.FORWARD
                future.set_result(unit)
        self._pending.clear()
