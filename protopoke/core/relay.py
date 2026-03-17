"""
Bidirectional relay.

The relay is the moving part of the proxy. It reads bytes from one side,
pushes them through the framer and tamper controller, and writes the
result (possibly modified) to the other side.

Architecture:

    DirectionalRelay:
        Handles ONE direction (client→server OR server→client).
        Runs as an asyncio Task. The main loop:

            while connected:
                data = await reader.read(N)
                for frame in framer.feed(data):
                    unit = await controller.process(frame)   ← may block
                    if forward: writer.write(unit.effective_bytes())

        The `await controller.process(frame)` is where tampering pauses.
        Only THIS relay task is suspended — the event loop stays alive and
        serves other sessions, new connections, and the API.

    BidirectionalRelay:
        Wraps two DirectionalRelays (one per direction) and runs them as
        concurrent asyncio Tasks.

        IMPORTANT — TCP half-close handling:
            When one side sends EOF, the correct proxy behaviour is a
            TCP half-close: signal EOF to the destination (so the remote
            peer knows we're done writing) but keep reading from it so
            any remaining in-flight data can reach the client.

            Example:
                1. Client sends data + FIN → proxy
                2. Upstream relay receives EOF, writes_eof() to server
                3. Server echoes data + FIN → proxy  (response in flight)
                4. Downstream relay reads echo, forwards to client, reads FIN
                5. BidirectionalRelay fully closes both writers on exit

            If instead of write_eof we called writer.close() in step 2,
            the server connection would be abruptly terminated and the
            echo response in step 3 would be lost.

        BidirectionalRelay owns all four stream objects and is responsible
        for closing all writers after both relay tasks finish.

Error handling:
    - ConnectionResetError, BrokenPipeError: peer closed ungracefully.
    - asyncio.CancelledError: propagated (proxy shutdown).
    - Other exceptions: logged, relay stops.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional, TYPE_CHECKING

from ..models import Direction, Frame, InterceptAction
from ..framing.base import Framer
from ..tamper.controller import TamperController
from ..events.bus import (
    EventBus,
    FrameCapturedEvent,
    InterceptCompletedEvent,
)
from .session import Session

if TYPE_CHECKING:
    from ..rules.engine import RulesEngine

logger = logging.getLogger(__name__)


class DirectionalRelay:
    """
    One-way relay: source reader → framer → tamper controller → dest writer.

    Runs as a single asyncio Task (via BidirectionalRelay.run()).
    Does NOT own or close the dest_writer — that's BidirectionalRelay's job.
    """

    def __init__(
        self,
        session:              Session,
        direction:            Direction,
        source_reader:        asyncio.StreamReader,
        dest_writer:          asyncio.StreamWriter,
        framer:               Framer,
        tamper_controller: TamperController,
        event_bus:            EventBus,
        read_buffer_size:     int = 4096,
        rules_engine:         "Optional[RulesEngine]" = None,
    ) -> None:
        self._session              = session
        self._direction            = direction
        self._source_reader        = source_reader
        self._dest_writer          = dest_writer
        self._framer               = framer
        self._tamper_controller = tamper_controller
        self._event_bus            = event_bus
        self._read_buffer_size     = read_buffer_size
        self._rules_engine         = rules_engine
        self._running              = False

    async def run(self) -> None:
        """
        Main relay loop. Intended to run as an asyncio Task.

        On source EOF: sends a TCP half-close (write_eof) to the destination,
        then exits. BidirectionalRelay fully closes the writers after both
        directions have finished.
        """
        self._running = True
        label = f"{self._session.id[:8]}|{self._direction.value}"

        try:
            while self._running:
                try:
                    data = await self._source_reader.read(self._read_buffer_size)
                except asyncio.IncompleteReadError:
                    logger.debug("Source closed unexpectedly [%s]", label)
                    break

                if not data:
                    logger.debug("Source EOF [%s]", label)
                    break

                for frame in self._framer.feed(data):
                    await self._process_frame(frame)

        except asyncio.CancelledError:
            logger.debug("Relay cancelled [%s]", label)
            raise

        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            logger.debug("Connection error [%s]: %s", label, exc)

        except Exception as exc:
            logger.error("Relay error [%s]: %s", label, exc, exc_info=True)

        finally:
            # Flush framer buffer (best effort)
            for frame in self._framer.flush():
                try:
                    await self._process_frame(frame)
                except Exception:
                    pass

            # TCP half-close: tell the remote peer we're done writing.
            # We do NOT call writer.close() here — that would terminate the
            # TCP connection immediately, losing any in-flight response data.
            # BidirectionalRelay.run() closes the writers after both tasks end.
            self._running = False
            await self._send_eof_to_dest()

    async def _process_frame(self, frame: Frame) -> None:
        """
        Run one frame through replace rules, tampering, then write.

        Pipeline:
          1. Add *frame* (original capture) to session and emit FrameCapturedEvent.
          2. Apply replace rules to get effective bytes (may equal original).
          3. If bytes changed, create a synthetic frame carrying the modified bytes.
          4. Pass the effective frame to the tamper controller.
          5. Write to destination unless the verdict is DROP.
        """
        # Always store the raw-capture frame so the session log shows what
        # was actually on the wire.
        self._session.add_frame(frame)

        await self._event_bus.publish(
            FrameCapturedEvent(frame=frame, session=self._session.info)
        )

        # Apply replace rules (no-op when no engine is set)
        effective_frame = frame
        if self._rules_engine is not None:
            modified_bytes = self._rules_engine.apply(frame)
            if modified_bytes != frame.raw_bytes:
                # Create a new Frame for tampering/forwarding so the
                # original capture is preserved in the session unchanged.
                effective_frame = Frame.create(
                    session_id=frame.session_id,
                    direction=frame.direction,
                    raw_bytes=modified_bytes,
                    sequence_number=frame.sequence_number,
                    framer_name=frame.framer_name,
                )

        unit = await self._tamper_controller.process(effective_frame)

        await self._event_bus.publish(
            InterceptCompletedEvent(unit=unit, session=self._session.info)
        )

        if unit.action is InterceptAction.DROP:
            logger.debug(
                "Frame dropped: session=%s frame=%s",
                frame.session_id[:8], frame.id[:8],
            )
            return

        data_to_send = unit.effective_bytes()

        # If the operator modified the frame in the Tamper tab, log the
        # modified bytes as a separate frame so the Traffic tab shows what was
        # actually sent alongside the original capture.
        if unit.action is InterceptAction.MODIFIED:
            modified_frame = Frame.create(
                session_id=frame.session_id,
                direction=frame.direction,
                raw_bytes=data_to_send,
                sequence_number=len(self._session.frames),
                framer_name="tamper",
            )
            self._session.add_frame(modified_frame)
            await self._event_bus.publish(
                FrameCapturedEvent(frame=modified_frame, session=self._session.info)
            )

        try:
            self._dest_writer.write(data_to_send)
            await self._dest_writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            logger.debug("Write error [%s]: %s", self._direction.value, exc)

    async def _send_eof_to_dest(self) -> None:
        """
        Signal to the destination that we're done writing (TCP half-close).

        Uses write_eof() if the transport supports it. This sends a FIN packet
        so the remote peer knows no more data is coming, while keeping the
        connection open so the remote peer can still send back data.
        """
        try:
            if self._dest_writer.can_write_eof():
                self._dest_writer.write_eof()
                await self._dest_writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass  # Destination already closed — that's fine
        except Exception as exc:
            logger.debug("EOF send error: %s", exc)

    def swap_framer(self, new_framer: Framer) -> None:
        """
        Replace the active framer with *new_framer*.

        Safe to call at any await point (asyncio is single-threaded).
        Any data buffered in the old framer is discarded — the new framer
        starts fresh.  This is intentional: a framer change implies a
        protocol-boundary reset.
        """
        self._framer = new_framer
        logger.debug(
            "Framer swapped → %s [%s|%s]",
            type(new_framer).__name__,
            self._session.id[:8],
            self._direction.value,
        )

    def stop(self) -> None:
        """Request the relay to stop after its current read."""
        self._running = False


class BidirectionalRelay:
    """
    Two-way relay managing both directions of a proxied TCP session.

    Owns all four stream objects (two readers, two writers).
    Responsible for the final close of all writers after both tasks finish.

    After ``run()`` returns, ``first_disconnect_direction`` indicates which
    side disconnected first (CLIENT_TO_SERVER → client disconnected,
    SERVER_TO_CLIENT → server disconnected, None → cancelled / unknown).
    """

    def __init__(
        self,
        session:              Session,
        client_reader:        asyncio.StreamReader,
        client_writer:        asyncio.StreamWriter,
        server_reader:        asyncio.StreamReader,
        server_writer:        asyncio.StreamWriter,
        client_framer:        Framer,
        server_framer:        Framer,
        tamper_controller: TamperController,
        event_bus:            EventBus,
        read_buffer_size:     int = 4096,
        rules_engine:         "Optional[RulesEngine]" = None,
    ) -> None:
        self._session       = session
        self._client_writer = client_writer
        self._server_writer = server_writer

        # Set by run() to identify who disconnected first.
        # CLIENT_TO_SERVER → client closed connection first.
        # SERVER_TO_CLIENT → server closed connection first.
        # None → session was cancelled or both closed simultaneously.
        self.first_disconnect_direction: Optional[Direction] = None

        self._upstream = DirectionalRelay(
            session=session,
            direction=Direction.CLIENT_TO_SERVER,
            source_reader=client_reader,
            dest_writer=server_writer,
            framer=client_framer,
            tamper_controller=tamper_controller,
            event_bus=event_bus,
            read_buffer_size=read_buffer_size,
            rules_engine=rules_engine,
        )

        self._downstream = DirectionalRelay(
            session=session,
            direction=Direction.SERVER_TO_CLIENT,
            source_reader=server_reader,
            dest_writer=client_writer,
            framer=server_framer,
            tamper_controller=tamper_controller,
            event_bus=event_bus,
            read_buffer_size=read_buffer_size,
            rules_engine=rules_engine,
        )

    async def run(self) -> None:
        """
        Run both directions concurrently.

        Returns when both relay directions have finished.
        After both exit, closes all writers cleanly.

        Sets ``self.first_disconnect_direction`` to whichever relay task
        exited first (indicating which peer disconnected first).
        """
        session_label = self._session.id[:8]

        upstream_task = asyncio.create_task(
            self._upstream.run(),
            name=f"relay-up-{session_label}",
        )
        downstream_task = asyncio.create_task(
            self._downstream.run(),
            name=f"relay-down-{session_label}",
        )

        try:
            # Use asyncio.wait(FIRST_COMPLETED) to detect which side
            # disconnected first, then wait for the remaining task.
            done, pending = await asyncio.wait(
                {upstream_task, downstream_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            # The first task to finish tells us who disconnected first.
            if upstream_task in done and downstream_task not in done:
                self.first_disconnect_direction = Direction.CLIENT_TO_SERVER
            elif downstream_task in done and upstream_task not in done:
                self.first_disconnect_direction = Direction.SERVER_TO_CLIENT
            # If both finished simultaneously, first_disconnect_direction stays None.

            # Wait for the remaining relay to drain and finish.
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

        except asyncio.CancelledError:
            upstream_task.cancel()
            downstream_task.cancel()
            await asyncio.gather(
                upstream_task, downstream_task,
                return_exceptions=True,
            )
            raise
        finally:
            # Both relay directions have finished. Now do the final close
            # of all writers to release socket resources.
            await self._close_all_writers()

    def swap_framers(self, client_framer: Framer, server_framer: Framer) -> None:
        """
        Hot-swap the framers on both directions of this session.

        Called while the relay is running to change the framing strategy
        without interrupting the TCP connection.
        """
        self._upstream.swap_framer(client_framer)
        self._downstream.swap_framer(server_framer)

    async def _close_all_writers(self) -> None:
        """Close all writers (best effort, ignore errors)."""
        for writer in (self._client_writer, self._server_writer):
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
