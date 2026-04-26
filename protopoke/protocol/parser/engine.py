"""
Definition-based decoder and encoder.

DefinitionBasedDecoder implements ProtocolDecoder using a loaded
ProtocolDefinition.  It is session-aware: it tracks per-(session, direction)
sequence counters needed for SEQUENCE-type match rules.

DefinitionBasedEncoder implements ProtocolEncoder.  It encodes a ParsedMessage
back to bytes, supporting field-level edits for intercept+modify and replay.

Usage:
    from protopoke.protocol.definition import load_protocol_file
    from protopoke.protocol.parser import DefinitionBasedDecoder, DefinitionBasedEncoder

    defn = load_protocol_file("myproto.yaml")
    decoder = DefinitionBasedDecoder(defn)
    encoder = DefinitionBasedEncoder(defn)

    # Decode a captured frame
    msg = decoder.decode(frame)
    print(msg.message_type)
    for f in msg.fields:
        print(f.name, f.value)

    # Re-encode with a modified field
    new_bytes = encoder.encode(msg, edits={"username": "newuser"})
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from ...models import Direction, Frame, ParsedField, ParsedMessage
from ..base import ProtocolDecoder, ProtocolEncoder
from ..definition.schema import (
    FieldDefinition,
    FieldType,
    ProtocolDefinition,
)
from .fields import ParseError, encode_field, parse_field
from .matcher import MessageMatcher

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

class DefinitionBasedDecoder(ProtocolDecoder):
    """
    Decodes frames using a ProtocolDefinition loaded from YAML/JSON/dict.

    Session-awareness:
        SEQUENCE match rules require knowing how many frames have already
        passed in a given (session_id, direction) stream.  This decoder
        maintains those counters internally.  One decoder instance can be
        shared across all sessions (the counters are keyed by session_id).

        When a session is closed, call reset_session(session_id) to free
        the counter memory.

    Thread-safety:
        Not thread-safe.  Use one instance per asyncio task / thread, or
        add your own locking if sharing across threads.
    """

    def __init__(self, definition: ProtocolDefinition) -> None:
        self._def = definition
        self._matcher = MessageMatcher(definition.messages)
        # (session_id, direction) → frame count so far
        self._seq_counters: dict[tuple[str, Direction], int] = defaultdict(int)

    @property
    def protocol_name(self) -> str:
        return self._def.name

    def can_decode(self, frame: Frame) -> bool:
        # Always attempt — return error ParsedMessage on failure
        return True

    def decode(self, frame: Frame) -> ParsedMessage:
        """
        Decode a frame into a structured ParsedMessage.

        Never raises.  On parse error, returns a ParsedMessage with
        error set and whatever fields were successfully parsed.
        """
        key = (frame.session_id, frame.direction)
        seq_index = self._seq_counters[key]

        msg_def = self._matcher.match(frame, seq_index)

        if msg_def is None:
            self._seq_counters[key] += 1
            return ParsedMessage.from_frame(
                frame=frame,
                protocol_name=self._def.name,
                message_type="<unknown>",
                fields=_raw_fallback(frame),
                display_name=f"[{len(frame.raw_bytes)}B] <unknown>",
                error=f"No message definition matched frame seq={seq_index}",
            )

        fields: list[ParsedField] = []
        context: dict[str, int] = {}
        error: str | None = None

        try:
            offset = 0
            for field_def in msg_def.fields:
                pf = parse_field(
                    data=frame.raw_bytes,
                    offset=offset,
                    field_def=field_def,
                    context=context,
                    endianness=self._def.endianness,
                )
                fields.append(pf)
                offset += pf.size
                # Add scalar values to context for expression evaluation
                if isinstance(pf.value, (int, float)):
                    context[field_def.name] = int(pf.value)
        except ParseError as exc:
            error = str(exc)
            logger.debug("Parse error in %r: %s", msg_def.name, exc)

        self._seq_counters[key] += 1

        display = f"[{len(frame.raw_bytes)}B] {msg_def.name}"
        return ParsedMessage.from_frame(
            frame=frame,
            protocol_name=self._def.name,
            message_type=msg_def.name,
            fields=fields,
            display_name=display,
            error=error,
        )

    def reset_session(self, session_id: str) -> None:
        """Free sequence counters for a closed session."""
        for direction in Direction:
            self._seq_counters.pop((session_id, direction), None)


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------

class DefinitionBasedEncoder(ProtocolEncoder):
    """
    Encodes a ParsedMessage back to raw bytes, optionally with field edits.

    Field-level editing:
        `encode(msg, edits)` accepts a dict of field_name → new_value.
        New values can be Python native types (int, str, bytes).

        When a length field references an edited variable-length field,
        the encoder automatically recomputes the length value.

    Limitations:
        - Only top-level fields are editable via `edits`.  Editing nested
          TLV/array sub-fields requires passing the fully re-constructed
          bytes in `edits[field_name]`.
        - TLV_SEQUENCE and ARRAY fields are re-encoded from their raw bytes
          unless explicitly overridden in `edits`.
    """

    def __init__(self, definition: ProtocolDefinition) -> None:
        self._def = definition

    @property
    def protocol_name(self) -> str:
        return self._def.name

    def encode(self, message: ParsedMessage) -> bytes:
        """Encode a ParsedMessage back to bytes (no edits)."""
        return self.encode_with_edits(message, {})

    def encode_with_edits(
        self,
        message: ParsedMessage,
        edits: dict[str, Any],
    ) -> bytes:
        """
        Encode a ParsedMessage back to bytes, applying field-level edits.

        Args:
            message: The parsed message to encode.
            edits:   Dict of field_name → new Python value.
                     Fields not in edits use their original parsed value.

        Returns:
            Bytes suitable for sending on the wire.

        Raises:
            ValueError: If the message type is not found in the definition,
                        or a field cannot be encoded.
        """
        # Look up the message definition
        msg_def = self._find_message_def(message.message_type)
        if msg_def is None:
            # Fallback: reassemble from raw field bytes, applying edits as bytes
            return self._raw_encode(message, edits)

        # Two-pass strategy:
        #   Pass 1: determine final values for all fields (apply edits)
        #   Pass 2: encode each field in order, auto-recomputing any length fields
        #           that reference variable-length sibling fields (so length headers
        #           stay correct even when an edited field changed size)

        # Build a value map: field_name → final value
        field_by_name = {f.name: f for f in message.fields}
        values: dict[str, Any] = {}

        for field_def in msg_def.fields:
            if field_def.name in edits:
                values[field_def.name] = edits[field_def.name]
            elif field_def.name in field_by_name:
                values[field_def.name] = field_by_name[field_def.name].value
            else:
                values[field_def.name] = self._default_value(field_def)

        # Encode fields; auto-recompute length fields
        # We need to encode variable-length fields first to know their sizes
        encoded: dict[str, bytes] = {}
        for field_def in msg_def.fields:
            val = values[field_def.name]
            context = {k: len(v) if isinstance(v, (bytes, bytearray)) else int(v)
                       for k, v in encoded.items()
                       if isinstance(v, (bytes, bytearray, int, float))}
            # Auto-recompute: if this is a length field (referenced by another
            # field's length expression), recalculate from the already-encoded target
            val = self._maybe_recompute_length(field_def, val, values, encoded, msg_def)
            encoded[field_def.name] = encode_field(
                field_def, val, context, self._def.endianness
            )

        return b"".join(encoded[fd.name] for fd in msg_def.fields)

    # ------------------------------------------------------------------

    def _find_message_def(self, message_type: str):
        for msg_def in self._def.messages:
            if msg_def.name == message_type:
                return msg_def
        return None

    def _raw_encode(self, message: ParsedMessage, edits: dict[str, Any]) -> bytes:
        """Fallback: concatenate raw field bytes, overriding with edits."""
        parts = []
        for pf in message.fields:
            if pf.name in edits:
                v = edits[pf.name]
                if isinstance(v, (bytes, bytearray)):
                    parts.append(bytes(v))
                elif isinstance(v, str):
                    parts.append(v.encode())
                elif isinstance(v, int):
                    parts.append(v.to_bytes(pf.size, "big"))
                else:
                    parts.append(pf.raw_bytes)
            else:
                parts.append(pf.raw_bytes)
        return b"".join(parts)

    def _default_value(self, field_def: FieldDefinition) -> Any:
        if field_def.type in (FieldType.BYTES, FieldType.TLV_SEQUENCE, FieldType.ARRAY):
            return b""
        if field_def.type is FieldType.STRING:
            return ""
        if field_def.type is FieldType.PADDING:
            return None
        return 0

    def _maybe_recompute_length(
        self,
        field_def: FieldDefinition,
        current_val: Any,
        values: dict[str, Any],
        encoded: dict[str, bytes],
        msg_def,
    ) -> Any:
        """
        If `field_def` is a length field that points to an edited field,
        recompute the length from the already-encoded target field bytes.

        We detect this heuristically: if another field's `length` expression
        is exactly `{this_field_name}`, this is likely a length field.
        """
        for other_def in msg_def.fields:
            if other_def.length == f"{{{field_def.name}}}":
                # This field controls the length of `other_def`
                if other_def.name in encoded:
                    return len(encoded[other_def.name])
                # The target hasn't been encoded yet — encode it now to get the size
                try:
                    target_val = values.get(other_def.name, self._default_value(other_def))
                    target_bytes = encode_field(other_def, target_val, {}, self._def.endianness)
                    return len(target_bytes)
                except Exception:
                    pass
        return current_val


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _raw_fallback(frame: Frame) -> list[ParsedField]:
    """Produce a single 'raw' field when no message definition matched."""
    raw = frame.raw_bytes
    return [ParsedField(
        name="raw",
        value=raw,
        raw_bytes=raw,
        offset=0,
        size=len(raw),
        display_hint="hex",
        display_value=raw.hex(" ").upper() if raw else "(empty)",
    )]
