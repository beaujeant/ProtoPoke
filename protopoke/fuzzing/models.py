"""
Fuzzing data models.

FuzzResult    — the outcome of one fuzzing iteration (one mutated frame sent).
FuzzCampaign  — a complete fuzzing run: config + accumulated results.

Design notes:
- Results are kept in memory (list on FuzzCampaign).  A future enhancement
  could persist interesting results to the project file via ProjectManager.
- FuzzResult.interesting is set heuristically by the engine:
    • connection reset (TCP RST) — server may have crashed or rejected hard
    • timeout — server hung
    • response size outside a tolerance band vs the baseline
  Operators can refine what "interesting" means; this is a starting point.
- baseline_response_size is stored on the campaign so each result can compute
  its delta without needing a back-reference to the engine.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .mutators.base import FrameMutator


def _new_id() -> str:
    return str(uuid.uuid4())


class CampaignStatus(str, Enum):
    IDLE     = "idle"
    RUNNING  = "running"
    STOPPED  = "stopped"
    DONE     = "done"


@dataclass
class FuzzResult:
    """
    The outcome of one fuzzing iteration.

    Attributes:
        id:                   Unique ID for this result.
        iteration:            0-based iteration counter within the campaign.
        mutator_name:         Name of the mutator that produced this mutation.
        original_frame_id:    ID of the source frame that was mutated.
        mutated_bytes:        The actual bytes that were sent.
        response_bytes:       Raw bytes received from the server (None = no response).
        response_time_ms:     Round-trip time in milliseconds.
        connection_reset:     True if the server reset the TCP connection.
        timed_out:            True if no response arrived before the timeout.
        error:                Any other transport-level error message.
        interesting:          Heuristic flag — True if this result is worth investigating.
        baseline_response_size: Size of the baseline response for delta computation.
        timestamp:            When this result was recorded.
    """
    id:                     str
    iteration:              int
    mutator_name:           str
    original_frame_id:      str
    mutated_bytes:          bytes
    response_bytes:         Optional[bytes]
    response_time_ms:       float
    connection_reset:       bool
    timed_out:              bool
    error:                  Optional[str]
    interesting:            bool
    baseline_response_size: int
    timestamp:              float = field(default_factory=time.time)

    @classmethod
    def create(
        cls,
        iteration:              int,
        mutator_name:           str,
        original_frame_id:      str,
        mutated_bytes:          bytes,
        response_bytes:         Optional[bytes],
        response_time_ms:       float,
        connection_reset:       bool,
        timed_out:              bool,
        error:                  Optional[str],
        baseline_response_size: int,
    ) -> "FuzzResult":
        interesting = (
            connection_reset
            or timed_out
            or (
                response_bytes is not None
                and baseline_response_size > 0
                and abs(len(response_bytes) - baseline_response_size) > baseline_response_size * 0.20
            )
        )
        return cls(
            id=_new_id(),
            iteration=iteration,
            mutator_name=mutator_name,
            original_frame_id=original_frame_id,
            mutated_bytes=mutated_bytes,
            response_bytes=response_bytes,
            response_time_ms=response_time_ms,
            connection_reset=connection_reset,
            timed_out=timed_out,
            error=error,
            interesting=interesting,
            baseline_response_size=baseline_response_size,
        )

    @property
    def response_size(self) -> int:
        return len(self.response_bytes) if self.response_bytes is not None else 0

    @property
    def response_size_delta(self) -> int:
        return self.response_size - self.baseline_response_size

    def to_dict(self) -> dict:
        return {
            "id":                     self.id,
            "iteration":              self.iteration,
            "mutator_name":           self.mutator_name,
            "original_frame_id":      self.original_frame_id,
            "mutated_bytes":          self.mutated_bytes.hex(),
            "mutated_len":            len(self.mutated_bytes),
            "response_bytes":         self.response_bytes.hex() if self.response_bytes else None,
            "response_size":          self.response_size,
            "response_size_delta":    self.response_size_delta,
            "response_time_ms":       self.response_time_ms,
            "connection_reset":       self.connection_reset,
            "timed_out":              self.timed_out,
            "error":                  self.error,
            "interesting":            self.interesting,
            "baseline_response_size": self.baseline_response_size,
            "timestamp":              self.timestamp,
        }


@dataclass
class FuzzCampaign:
    """
    A fuzzing campaign: configuration + accumulated results.

    Create with FuzzCampaign.create(), then pass to FuzzerEngine.run_campaign().

    Attributes:
        id:             Unique ID.
        session_id:     Template session to replay with mutations applied.
        frame_selector: Which frames to fuzz (same syntax as ForgeEngine).
                        None = all client-to-server frames.
        mutator_names:  Display names of the configured mutators (for serialisation).
        iterations:     Total number of mutations to attempt.
        stop_on_crash:  Stop campaign immediately on connection reset.
        results:        Accumulated FuzzResult objects (filled by engine).
        status:         Current campaign lifecycle state.
        started_at:     When the campaign started running.
        completed_at:   When it finished (or None if still running/idle).
        baseline_response_size: Size of the baseline response (0 if not yet measured).
    """
    id:                     str
    session_id:             str
    frame_selector:         Optional[str]
    mutator_names:          list[str]
    iterations:             int
    stop_on_crash:          bool
    results:                list[FuzzResult] = field(default_factory=list)
    status:                 CampaignStatus = CampaignStatus.IDLE
    started_at:             Optional[float] = None
    completed_at:           Optional[float] = None
    baseline_response_size: int = 0

    @classmethod
    def create(
        cls,
        session_id:     str,
        mutators:       list["FrameMutator"],
        iterations:     int  = 50,
        frame_selector: Optional[str] = None,
        stop_on_crash:  bool = True,
    ) -> "FuzzCampaign":
        return cls(
            id=_new_id(),
            session_id=session_id,
            frame_selector=frame_selector,
            mutator_names=[m.name for m in mutators],
            iterations=iterations,
            stop_on_crash=stop_on_crash,
        )

    # ------------------------------------------------------------------
    # Convenience views
    # ------------------------------------------------------------------

    @property
    def interesting_results(self) -> list[FuzzResult]:
        return [r for r in self.results if r.interesting]

    @property
    def crash_results(self) -> list[FuzzResult]:
        return [r for r in self.results if r.connection_reset]

    @property
    def completed_iterations(self) -> int:
        return len(self.results)

    def to_dict(self) -> dict:
        return {
            "id":                     self.id,
            "session_id":             self.session_id,
            "frame_selector":         self.frame_selector,
            "mutator_names":          self.mutator_names,
            "iterations":             self.iterations,
            "stop_on_crash":          self.stop_on_crash,
            "status":                 self.status.value,
            "started_at":             self.started_at,
            "completed_at":           self.completed_at,
            "baseline_response_size": self.baseline_response_size,
            "completed_iterations":   self.completed_iterations,
            "interesting_count":      len(self.interesting_results),
            "crash_count":            len(self.crash_results),
            "results":                [r.to_dict() for r in self.results],
        }
