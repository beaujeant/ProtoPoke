"""
FrameMutator — abstract base class for all fuzzing mutators.

A FrameMutator takes a Frame (and optionally its ParsedMessage) and returns
mutated bytes, or None to pass through unchanged.

All mutators are async so that RadamsaMutator (subprocess) and future
network-aware mutators can await without blocking the event loop.

Protocol-aware mutators (in field.py) also receive the ParsedMessage so
they can target specific fields and re-encode with structural validity.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ...models import Frame, ParsedMessage


class FrameMutator(ABC):
    """
    Abstract base class for all fuzzing mutators.

    Subclass and implement ``mutate()``.  Optionally override ``name``.

    The ``parsed`` argument is None when:
      - No protocol definition has been loaded.
      - The frame did not match any message definition.
    Protocol-aware mutators should handle None gracefully (e.g. fall back
    to raw mutation or return None to skip this frame).
    """

    @abstractmethod
    async def mutate(
        self,
        frame:  "Frame",
        parsed: Optional["ParsedMessage"],
    ) -> Optional[bytes]:
        """
        Produce a mutated version of *frame*.

        Args:
            frame:  The frame about to be sent.
            parsed: Protocol-decoded view of the frame, or None.

        Returns:
            Mutated bytes to send instead, or None to leave the frame unchanged.
        """

    @property
    def name(self) -> str:
        """Human-readable name shown in results and the UI."""
        return self.__class__.__name__
