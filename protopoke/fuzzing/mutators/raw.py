"""
Raw (protocol-unaware) mutators.

These mutators treat the frame as an opaque byte string and apply generic
bit/byte-level transformations.  They do not need a ParsedMessage or an
encoder, so they work even when no protocol definition has been loaded.

Mutators:
    BitFlipMutator      — flip one or more random bits
    ByteInsertMutator   — insert random bytes at a random position
    ByteDeleteMutator   — delete a random byte range
    KnownBadMutator     — replace a section with known-bad payloads
    RadamsaMutator      — pipe the frame through radamsa (if installed)
    ChainMutator        — apply a sequence of mutators in order
"""

from __future__ import annotations

import asyncio
import os
import random
from typing import Optional, TYPE_CHECKING

from .base import FrameMutator

if TYPE_CHECKING:
    from ...models import Frame, ParsedMessage


# ---------------------------------------------------------------------------
# Known-bad payloads injected by KnownBadMutator
# ---------------------------------------------------------------------------

_KNOWN_BAD: list[bytes] = [
    b"\x00" * 8,                      # null bytes
    b"\xff" * 8,                      # max bytes
    b"A" * 256,                       # long ASCII (stack overflow probe)
    b"A" * 1024,                      # longer
    b"A" * 4096,                      # even longer
    b"%s%s%s%s%n",                    # format string
    b"%x%x%x%x",                      # format string (hex)
    b"\x00" * 1,                      # single null
    b"\xff\xfe",                      # BOM-like
    b"\x7f\xff\xff\xff",              # INT32_MAX
    b"\x80\x00\x00\x00",              # INT32_MIN
    b"\xff\xff\xff\xff",              # UINT32_MAX
    b"\xff\xff\xff\xff\xff\xff\xff\xff",  # UINT64_MAX
    b"\x00" * 128,                    # null padding
    b"../../../etc/passwd\x00",       # path traversal
    b"' OR '1'='1",                   # SQL injection fragment
]


class BitFlipMutator(FrameMutator):
    """
    Flip *count* random bits in the frame.

    The flipped bits are chosen uniformly across the entire frame.  Flipping
    a single bit affects exactly one byte (alters that byte's value).
    """

    def __init__(self, count: int = 1) -> None:
        self._count = count

    @property
    def name(self) -> str:
        return f"BitFlip(n={self._count})"

    async def mutate(
        self,
        frame:  "Frame",
        parsed: Optional["ParsedMessage"],
    ) -> Optional[bytes]:
        if not frame.raw_bytes:
            return None
        data = bytearray(frame.raw_bytes)
        for _ in range(self._count):
            bit_idx = random.randrange(len(data) * 8)
            byte_idx = bit_idx // 8
            bit_pos  = bit_idx % 8
            data[byte_idx] ^= (1 << bit_pos)
        return bytes(data)


class ByteInsertMutator(FrameMutator):
    """
    Insert *count* random bytes at a random offset.

    The insertion position is chosen uniformly (including appending at end).
    """

    def __init__(self, count: int = 4) -> None:
        self._count = count

    @property
    def name(self) -> str:
        return f"ByteInsert(n={self._count})"

    async def mutate(
        self,
        frame:  "Frame",
        parsed: Optional["ParsedMessage"],
    ) -> Optional[bytes]:
        data = bytearray(frame.raw_bytes)
        pos = random.randint(0, len(data))
        data[pos:pos] = os.urandom(self._count)
        return bytes(data)


class ByteDeleteMutator(FrameMutator):
    """
    Delete up to *max_count* bytes from a random position.

    Guarantees at least one byte remains if the frame is non-empty.
    Returns None (no mutation) for empty or single-byte frames.
    """

    def __init__(self, max_count: int = 4) -> None:
        self._max_count = max_count

    @property
    def name(self) -> str:
        return f"ByteDelete(max={self._max_count})"

    async def mutate(
        self,
        frame:  "Frame",
        parsed: Optional["ParsedMessage"],
    ) -> Optional[bytes]:
        data = bytearray(frame.raw_bytes)
        if len(data) <= 1:
            return None
        count = random.randint(1, min(self._max_count, len(data) - 1))
        pos = random.randint(0, len(data) - count)
        del data[pos:pos + count]
        return bytes(data)


class KnownBadMutator(FrameMutator):
    """
    Replace a random section of the frame with a known-bad payload.

    On each call a payload is chosen at random from the internal library
    and spliced into the frame at a random offset.  The splice replaces the
    bytes *or* extends the frame if the payload is longer.

    Optionally, *payloads* can override the built-in library.
    """

    def __init__(self, payloads: Optional[list[bytes]] = None) -> None:
        self._payloads = payloads if payloads is not None else _KNOWN_BAD

    @property
    def name(self) -> str:
        return "KnownBad"

    async def mutate(
        self,
        frame:  "Frame",
        parsed: Optional["ParsedMessage"],
    ) -> Optional[bytes]:
        if not self._payloads:
            return None
        payload = random.choice(self._payloads)
        data = bytearray(frame.raw_bytes)
        pos = random.randint(0, max(0, len(data) - 1))
        data[pos:pos + len(payload)] = payload
        return bytes(data)


class RadamsaMutator(FrameMutator):
    """
    Mutate by piping the frame bytes through radamsa.

    radamsa is a general-purpose fuzzer generator that produces structurally
    interesting mutations (e.g. integer overflows in embedded lengths, Unicode
    edge cases, repetitions). It must be installed and on PATH.

    If radamsa is not installed, this mutator falls back to BitFlipMutator.

    Args:
        radamsa_path: Explicit path to the radamsa binary (default: "radamsa").
        timeout:      Seconds to wait for radamsa to respond (default: 5.0).
        seed:         Optional seed for reproducibility (passed as --seed).
    """

    def __init__(
        self,
        radamsa_path: str   = "radamsa",
        timeout:      float = 5.0,
        seed:         Optional[int] = None,
    ) -> None:
        self._radamsa_path = radamsa_path
        self._timeout      = timeout
        self._seed         = seed
        self._available:   Optional[bool] = None   # lazily checked

    @property
    def name(self) -> str:
        return "Radamsa"

    async def _check_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            proc = await asyncio.create_subprocess_exec(
                self._radamsa_path, "--help",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=3.0)
            self._available = proc.returncode == 0
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            self._available = False
        return self._available

    async def mutate(
        self,
        frame:  "Frame",
        parsed: Optional["ParsedMessage"],
    ) -> Optional[bytes]:
        if not await self._check_available():
            # Graceful fallback
            return await BitFlipMutator().mutate(frame, parsed)

        cmd = [self._radamsa_path]
        if self._seed is not None:
            cmd += ["--seed", str(self._seed)]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(frame.raw_bytes),
                timeout=self._timeout,
            )
            return stdout if stdout else None
        except (asyncio.TimeoutError, OSError):
            return await BitFlipMutator().mutate(frame, parsed)


class ChainMutator(FrameMutator):
    """
    Apply a sequence of mutators in order, each feeding into the next.

    If any mutator in the chain returns None, that step is skipped and the
    current bytes continue to the next mutator unchanged.

    Useful for combining: field edit → radamsa pass → bit flip.

    Args:
        mutators: Ordered list of mutators to apply.
    """

    def __init__(self, mutators: list[FrameMutator]) -> None:
        self._mutators = mutators

    @property
    def name(self) -> str:
        inner = " → ".join(m.name for m in self._mutators)
        return f"Chain({inner})"

    async def mutate(
        self,
        frame:  "Frame",
        parsed: Optional["ParsedMessage"],
    ) -> Optional[bytes]:
        from ...models import Frame as _Frame, Direction

        current = frame.raw_bytes
        mutated_at_least_once = False

        for mutator in self._mutators:
            # Wrap current bytes in a temporary Frame so each mutator
            # gets the already-mutated bytes, not the original.
            tmp_frame = _Frame(
                id=frame.id,
                session_id=frame.session_id,
                direction=frame.direction,
                raw_bytes=current,
                timestamp=frame.timestamp,
                sequence_number=frame.sequence_number,
                framer_name=frame.framer_name,
            )
            result = await mutator.mutate(tmp_frame, parsed)
            if result is not None:
                current = result
                mutated_at_least_once = True

        return current if mutated_at_least_once else None
