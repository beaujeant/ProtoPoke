"""
FuzzerEngine — orchestrates a fuzzing campaign.

Design:
    The engine iterates over a FuzzCampaign's configuration, picks frames
    from the template session, applies mutations, replays the mutated frame
    to the target, and records a FuzzResult for each iteration.

    It reuses ForgeEngine under the hood, so it benefits from all existing
    replay infrastructure (session registry, framer, connection management).

    For each iteration:
        1. Select the target frames from the template session.
        2. Pick one frame at random to mutate (or cycle deterministically).
        3. Pick the next mutator (round-robin through the campaign's mutator list).
        4. Call mutator.mutate(frame, parsed_message).
        5. If the mutator returns None, skip and count as a no-op iteration.
        6. Replay the session with that one frame replaced by the mutated bytes.
        7. Build a FuzzResult and store it on the campaign.
        8. Call on_result callback if provided.
        9. Stop early if stop_on_crash and the result is a connection reset.

Baseline:
    Before the first iteration the engine replays the session unmodified to
    capture the baseline response size.  This size is used by FuzzResult to
    flag "interesting" results (response size differs by >20%).

Response timeout:
    Replay connections use the same connect_timeout from the replay engine.
    A separate response_timeout cuts off slow reads so a hung server does
    not block the campaign indefinitely.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable, Optional, TYPE_CHECKING

from ..models import Direction, Frame
from ..core.session import Session, SessionRegistry
from ..replay.engine import ForgeEngine, parse_frame_selector
from .models import CampaignStatus, FuzzCampaign, FuzzResult
from .mutators.base import FrameMutator

if TYPE_CHECKING:
    from ..models import ParsedMessage
    from ..protocol.base import ProtocolDecoder

logger = logging.getLogger(__name__)


class FuzzerEngine:
    """
    Runs fuzzing campaigns against a target server.

    Args:
        forge_engine:    ForgeEngine to use for sending frames and capturing responses.
        session_registry: The shared session registry (same instance as the proxy).
        decoder:          Optional protocol decoder for protocol-aware mutators.
    """

    def __init__(
        self,
        forge_engine:    ForgeEngine,
        session_registry: SessionRegistry,
        decoder:          Optional["ProtocolDecoder"] = None,
    ) -> None:
        self._forge_engine    = forge_engine
        self._session_registry = session_registry
        self._decoder          = decoder

    async def run_campaign(
        self,
        campaign:         FuzzCampaign,
        mutators:         list[FrameMutator],
        server_host:      Optional[str]      = None,
        server_port:      Optional[int]      = None,
        response_timeout: float              = 10.0,
        on_result:        Optional[Callable[[FuzzResult], None]] = None,
    ) -> FuzzCampaign:
        """
        Run the campaign to completion (or until stopped/crashed).

        Args:
            campaign:         The campaign configuration (mutated in-place with results).
            mutators:         Ordered list of mutators (round-robined).
            server_host:      Override target host (default: session's original server).
            server_port:      Override target port (default: session's original server).
            response_timeout: Seconds to wait for a server response before timing out.
            on_result:        Called after each iteration with the FuzzResult.

        Returns:
            The campaign with all results populated and status set.
        """
        campaign.status     = CampaignStatus.RUNNING
        campaign.started_at = time.time()

        if not mutators:
            logger.warning("FuzzerEngine: no mutators configured, campaign aborted")
            campaign.status       = CampaignStatus.DONE
            campaign.completed_at = time.time()
            return campaign

        session = self._session_registry.get(campaign.session_id)
        if not session:
            logger.error("FuzzerEngine: session %s not found", campaign.session_id)
            campaign.status       = CampaignStatus.DONE
            campaign.completed_at = time.time()
            return campaign

        target_host = server_host or session.info.server_host
        target_port = server_port or session.info.server_port

        # ------------------------------------------------------------------
        # Collect source frames
        # ------------------------------------------------------------------
        source_frames = sorted(
            (f for f in session.frames if f.direction is Direction.CLIENT_TO_SERVER),
            key=lambda f: f.sequence_number,
        )

        if campaign.frame_selector:
            try:
                selected_seqs = parse_frame_selector(campaign.frame_selector)
                source_frames = [f for f in source_frames if f.sequence_number in selected_seqs]
            except ValueError as exc:
                logger.error("FuzzerEngine: invalid frame_selector: %s", exc)
                campaign.status       = CampaignStatus.DONE
                campaign.completed_at = time.time()
                return campaign

        if not source_frames:
            logger.warning("FuzzerEngine: no frames to fuzz (check session and frame_selector)")
            campaign.status       = CampaignStatus.DONE
            campaign.completed_at = time.time()
            return campaign

        # ------------------------------------------------------------------
        # Baseline: replay once unmodified to get baseline response size
        # ------------------------------------------------------------------
        baseline_size = await self._measure_baseline(
            campaign.session_id, target_host, target_port, response_timeout,
        )
        campaign.baseline_response_size = baseline_size
        logger.info("FuzzerEngine: baseline response size = %d bytes", baseline_size)

        # ------------------------------------------------------------------
        # Pre-decode frames for protocol-aware mutators
        # ------------------------------------------------------------------
        parsed_by_id: dict[str, Optional["ParsedMessage"]] = {}
        if self._decoder:
            for f in source_frames:
                try:
                    parsed_by_id[f.id] = self._decoder.decode(f)
                except Exception:
                    parsed_by_id[f.id] = None
        else:
            parsed_by_id = {f.id: None for f in source_frames}

        # ------------------------------------------------------------------
        # Fuzzing loop
        # ------------------------------------------------------------------
        mutator_idx = 0
        frame_idx   = 0

        for iteration in range(campaign.iterations):
            if campaign.status is CampaignStatus.STOPPED:
                break

            # Pick frame (cycle) and mutator (round-robin)
            target_frame = source_frames[frame_idx % len(source_frames)]
            mutator      = mutators[mutator_idx % len(mutators)]
            frame_idx   += 1
            mutator_idx += 1

            parsed = parsed_by_id.get(target_frame.id)

            # Apply mutation
            try:
                mutated = await mutator.mutate(target_frame, parsed)
            except Exception as exc:
                logger.warning(
                    "FuzzerEngine: mutator %s raised: %s — skipping iteration %d",
                    mutator.name, exc, iteration,
                )
                continue

            if mutated is None:
                logger.debug(
                    "FuzzerEngine: mutator %s returned None for frame %s — skipping",
                    mutator.name, target_frame.id[:8],
                )
                continue

            # Send and measure
            result = await self._send_mutated(
                campaign=campaign,
                iteration=iteration,
                mutator=mutator,
                source_frames=source_frames,
                target_frame=target_frame,
                mutated_bytes=mutated,
                target_host=target_host,
                target_port=target_port,
                response_timeout=response_timeout,
                baseline_size=baseline_size,
            )

            campaign.results.append(result)
            if on_result:
                try:
                    on_result(result)
                except Exception:
                    pass

            if result.interesting:
                logger.info(
                    "FuzzerEngine: interesting result at iteration %d "
                    "(%s, reset=%s, timeout=%s, size_delta=%+d)",
                    iteration, mutator.name,
                    result.connection_reset, result.timed_out,
                    result.response_size_delta,
                )

            if campaign.stop_on_crash and result.connection_reset:
                logger.warning(
                    "FuzzerEngine: connection reset at iteration %d — stopping campaign",
                    iteration,
                )
                campaign.status = CampaignStatus.STOPPED
                break

        if campaign.status is not CampaignStatus.STOPPED:
            campaign.status = CampaignStatus.DONE

        campaign.completed_at = time.time()
        logger.info(
            "FuzzerEngine: campaign done — %d iterations, %d interesting, %d crashes",
            len(campaign.results),
            len(campaign.interesting_results),
            len(campaign.crash_results),
        )
        return campaign

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _measure_baseline(
        self,
        session_id:       str,
        target_host:      str,
        target_port:      int,
        response_timeout: float,
    ) -> int:
        """Replay the session once unmodified; return total response bytes."""
        try:
            result = await asyncio.wait_for(
                self._forge_engine.forge_session(
                    session_id=session_id,
                    server_host=target_host,
                    server_port=target_port,
                ),
                timeout=response_timeout + 5.0,
            )
            if result.success:
                return result.total_bytes_received()
        except (asyncio.TimeoutError, Exception) as exc:
            logger.warning("FuzzerEngine: baseline measurement failed: %s", exc)
        return 0

    async def _send_mutated(
        self,
        campaign:         FuzzCampaign,
        iteration:        int,
        mutator:          FrameMutator,
        source_frames:    list[Frame],
        target_frame:     Frame,
        mutated_bytes:    bytes,
        target_host:      str,
        target_port:      int,
        response_timeout: float,
        baseline_size:    int,
    ) -> FuzzResult:
        """Send one mutated frame as part of a full session replay."""
        t_start = time.monotonic()
        connection_reset = False
        timed_out        = False
        error:           Optional[str] = None
        response_bytes:  Optional[bytes] = None

        try:
            replay_result = await asyncio.wait_for(
                self._forge_engine.forge_session(
                    session_id=campaign.session_id,
                    server_host=target_host,
                    server_port=target_port,
                    modified_frames={target_frame.id: mutated_bytes},
                ),
                timeout=response_timeout,
            )
            if replay_result.success:
                received = replay_result.frames_received()
                response_bytes = b"".join(f.raw_bytes for f in received)
            else:
                error = replay_result.error
                # Classify the error
                if replay_result.error and (
                    "reset" in replay_result.error.lower()
                    or "connection" in replay_result.error.lower()
                ):
                    connection_reset = True

        except asyncio.TimeoutError:
            timed_out = True
        except ConnectionResetError:
            connection_reset = True
        except Exception as exc:
            error = str(exc)

        elapsed_ms = (time.monotonic() - t_start) * 1000.0

        return FuzzResult.create(
            iteration=iteration,
            mutator_name=mutator.name,
            original_frame_id=target_frame.id,
            mutated_bytes=mutated_bytes,
            response_bytes=response_bytes,
            response_time_ms=elapsed_ms,
            connection_reset=connection_reset,
            timed_out=timed_out,
            error=error,
            baseline_response_size=baseline_size,
        )
