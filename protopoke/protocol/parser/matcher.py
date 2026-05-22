"""
Message matcher.

Determines which MessageDefinition applies to a given Frame by checking
match rules in order (first match wins).

Match strategies:

  MAGIC:
      Reads bytes at a fixed offset in the frame and compares to a
      byte sequence.  The direction filter (if set) is also checked.

  SEQUENCE:
      Matches frames by their position in the stream.  The parser engine
      maintains per-(session, direction) counters and passes the current
      sequence index to the matcher.

  ALWAYS:
      Unconditional catch-all.  The direction filter is still applied.
"""

from __future__ import annotations

from ..definition.schema import (
    DirectionFilter,
    MatchType,
    MessageDefinition,
)
from ...models import Direction, Frame


class MessageMatcher:
    """
    Try each MessageDefinition in order; return the first that matches.

    Usage:
        matcher = MessageMatcher(protocol_def.messages)
        msg_def = matcher.match(frame, sequence_index)
        # msg_def is None if no definition matched
    """

    def __init__(self, messages: list[MessageDefinition]) -> None:
        self._messages = messages

    def match(
        self,
        frame:          Frame,
        sequence_index: int,
    ) -> MessageDefinition | None:
        """
        Return the first MessageDefinition that matches `frame`.

        Args:
            frame:          The frame to classify.
            sequence_index: Current 0-based index of this frame within its
                            (session, direction) stream.  Provided by the engine.

        Returns:
            The matching MessageDefinition, or None if nothing matched.
        """
        for msg_def in self._messages:
            if self._check(msg_def, frame, sequence_index):
                return msg_def
        return None

    def _check(
        self,
        msg_def:        MessageDefinition,
        frame:          Frame,
        sequence_index: int,
    ) -> bool:
        """
        Return True if *frame* matches *msg_def*'s match rule.

        Matching order:
          1. Optional direction filter on the message definition (BOTH/C2S/S2C).
          2. The rule type:
             - MAGIC:    check that ``frame.raw_bytes[offset:offset+n] == value``
             - SEQUENCE: check that ``sequence_index == rule.index`` (and the
                         rule's own direction filter, which may differ from the
                         message-level filter)
             - ALWAYS:   unconditionally matches (useful as a catch-all/fallback)
        """
        # First check the optional direction filter on the message definition
        if not _direction_matches(msg_def.direction, frame.direction):
            return False

        rule = msg_def.match

        if rule.type is MatchType.MAGIC:
            return _magic_match(frame.raw_bytes, rule.offset, rule.value)

        if rule.type is MatchType.SEQUENCE:
            # The sequence direction filter is on the MATCH rule (not the message)
            if not _direction_matches(rule.direction, frame.direction):
                return False
            return sequence_index == rule.index

        if rule.type is MatchType.ALWAYS:
            return True

        return False


def _magic_match(data: bytes, offset: int, value: list[int]) -> bool:
    """Check if `data[offset:offset+len(value)]` equals `value`."""
    if not value:
        return True
    end = offset + len(value)
    if end > len(data):
        return False
    return list(data[offset:end]) == value


def _direction_matches(filter_: DirectionFilter, direction: Direction) -> bool:
    """Return True if `direction` is allowed by `filter_`."""
    if filter_ is DirectionFilter.BOTH:
        return True
    if filter_ is DirectionFilter.CLIENT_TO_SERVER:
        return direction is Direction.CLIENT_TO_SERVER
    if filter_ is DirectionFilter.SERVER_TO_CLIENT:
        return direction is Direction.SERVER_TO_CLIENT
    return True
