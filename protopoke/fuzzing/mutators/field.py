"""
Protocol-aware (field-level) mutators.

These mutators use the ParsedMessage to target specific fields and the
DefinitionBasedEncoder to re-assemble the frame with structural validity.

Because the encoder auto-recomputes length fields, mutations like extending
a string field will produce packets that are still valid at the framing level
while triggering overflows inside the application parser — this is usually
far more effective than blind raw mutation.

Mutators:
    FieldBoundaryMutator  — set integer fields to boundary values (0, -1, MAX, etc.)
    FieldOverflowMutator  — replace string/bytes fields with long repetitions
    NullByteMutator       — inject \x00 into string fields
    LengthMangleMutator   — deliberately corrupt length-named fields

All mutators fall back to returning None (no mutation) when no ParsedMessage
is available or when no suitable fields are found.
"""

from __future__ import annotations

import random
import struct
from typing import TYPE_CHECKING, Optional

from .base import FrameMutator

if TYPE_CHECKING:
    from ...models import Frame, ParsedField, ParsedMessage
    from ...protocol.parser.engine import DefinitionBasedEncoder


# ---------------------------------------------------------------------------
# Boundary values per integer type
# ---------------------------------------------------------------------------

_INT_BOUNDARIES: dict[str, list[int]] = {
    "uint8":  [0, 1, 127, 128, 254, 255],
    "uint16": [0, 1, 255, 256, 32767, 32768, 65534, 65535],
    "uint32": [0, 1, 255, 256, 65535, 65536, 2147483647, 2147483648, 4294967294, 4294967295],
    "uint64": [0, 1, 2147483647, 2147483648, 4294967295, 4294967296,
               9223372036854775807, 9223372036854775808, 18446744073709551615],
    "int8":   [-128, -127, -1, 0, 1, 126, 127],
    "int16":  [-32768, -32767, -1, 0, 1, 32766, 32767],
    "int32":  [-2147483648, -2147483647, -1, 0, 1, 2147483646, 2147483647],
    "int64":  [-9223372036854775808, -9223372036854775807, -1, 0, 1,
               9223372036854775806, 9223372036854775807],
}

_INTEGER_TYPES = set(_INT_BOUNDARIES)

_STRING_TYPES  = {"string", "bytes"}

_LENGTH_KEYWORDS = {"len", "length", "size", "sz", "count", "cnt"}


def _is_length_field(field_name: str) -> bool:
    """Heuristic: is this field likely a length?"""
    lower = field_name.lower()
    return any(kw in lower for kw in _LENGTH_KEYWORDS)


class FieldBoundaryMutator(FrameMutator):
    """
    Set a random integer field to a boundary value, then re-encode.

    Integer fields (uint8 / int16 / etc.) are the most common source of
    overflow and sign-extension bugs.  This mutator exhaustively cycles
    through all integer fields in the message, picking a random boundary
    value for the chosen field on each call.

    Requires an encoder to be passed at construction.  Falls back to
    returning None if no encoder is set or no ParsedMessage is available.

    Args:
        encoder:         A DefinitionBasedEncoder instance.
        skip_fields:     Field names to leave untouched (e.g. magic bytes, opcodes).
        preserve_fields: Alias for skip_fields (kept for API clarity).
    """

    def __init__(
        self,
        encoder: "DefinitionBasedEncoder",
        skip_fields: Optional[list[str]] = None,
    ) -> None:
        self._encoder     = encoder
        self._skip_fields = set(skip_fields or [])

    @property
    def name(self) -> str:
        return "FieldBoundary"

    async def mutate(
        self,
        frame:  "Frame",
        parsed: Optional["ParsedMessage"],
    ) -> Optional[bytes]:
        if parsed is None or not parsed.fields:
            return None

        # Collect all integer fields (skip excluded ones)
        candidates: list["ParsedField"] = [
            f for f in parsed.fields
            if f.name not in self._skip_fields
            and isinstance(f.value, int)
            and hasattr(f, "size")
            and _size_to_type(f.size) in _INTEGER_TYPES
        ]
        if not candidates:
            return None

        target = random.choice(candidates)
        field_type = _size_to_type(target.size)
        boundary = random.choice(_INT_BOUNDARIES[field_type])

        try:
            return self._encoder.encode_with_edits(parsed, {target.name: boundary})
        except Exception:
            return None


class FieldOverflowMutator(FrameMutator):
    """
    Replace a random string or bytes field with a long repetition.

    The payload length cycles through a set of "interesting" sizes:
    256, 512, 1024, 4096 bytes.  The encoder re-encodes the frame so any
    dependent length field is updated to match.

    Requires an encoder.

    Args:
        encoder:     A DefinitionBasedEncoder instance.
        filler_byte: Byte to repeat (default b'A').
        lengths:     Overflow payload lengths to choose from.
        skip_fields: Field names to skip.
    """

    def __init__(
        self,
        encoder:     "DefinitionBasedEncoder",
        filler_byte: bytes = b"A",
        lengths:     Optional[list[int]] = None,
        skip_fields: Optional[list[str]] = None,
    ) -> None:
        self._encoder     = encoder
        self._filler      = filler_byte
        self._lengths     = lengths or [256, 512, 1024, 4096]
        self._skip_fields = set(skip_fields or [])

    @property
    def name(self) -> str:
        return "FieldOverflow"

    async def mutate(
        self,
        frame:  "Frame",
        parsed: Optional["ParsedMessage"],
    ) -> Optional[bytes]:
        if parsed is None or not parsed.fields:
            return None

        candidates: list["ParsedField"] = [
            f for f in parsed.fields
            if f.name not in self._skip_fields
            and (isinstance(f.value, (str, bytes)))
        ]
        if not candidates:
            return None

        target = random.choice(candidates)
        payload_len = random.choice(self._lengths)
        if isinstance(target.value, bytes):
            payload: bytes | str = self._filler * payload_len
        else:
            # String: use ASCII 'A'
            payload = "A" * payload_len

        try:
            return self._encoder.encode_with_edits(parsed, {target.name: payload})
        except Exception:
            return None


class NullByteMutator(FrameMutator):
    """
    Inject a null byte (\x00) at a random position within a string field.

    Many C-based parsers use null termination; injecting a null byte mid-string
    can truncate the value unexpectedly, causing logic errors or information
    disclosure.  Non-null positions are preserved.

    Requires an encoder.

    Args:
        encoder:     A DefinitionBasedEncoder instance.
        skip_fields: Field names to skip.
    """

    def __init__(
        self,
        encoder:     "DefinitionBasedEncoder",
        skip_fields: Optional[list[str]] = None,
    ) -> None:
        self._encoder     = encoder
        self._skip_fields = set(skip_fields or [])

    @property
    def name(self) -> str:
        return "NullByte"

    async def mutate(
        self,
        frame:  "Frame",
        parsed: Optional["ParsedMessage"],
    ) -> Optional[bytes]:
        if parsed is None or not parsed.fields:
            return None

        string_fields: list["ParsedField"] = [
            f for f in parsed.fields
            if f.name not in self._skip_fields
            and isinstance(f.value, (str, bytes))
            and len(f.value) >= 2
        ]
        if not string_fields:
            return None

        target = random.choice(string_fields)
        val = target.value
        pos = random.randint(0, len(val) - 1)

        if isinstance(val, bytes):
            mutated: bytes | str = val[:pos] + b"\x00" + val[pos + 1:]
        else:
            mutated = val[:pos] + "\x00" + val[pos + 1:]

        try:
            return self._encoder.encode_with_edits(parsed, {target.name: mutated})
        except Exception:
            return None


class LengthMangleMutator(FrameMutator):
    """
    Deliberately set length-named fields to wrong values.

    Targets fields whose names suggest they carry a length (contain "len",
    "size", "count", etc.).  Sets them to values that disagree with the
    actual payload: 0, UINT32_MAX, or original±random_offset.

    Unlike FieldBoundaryMutator, this mutator intentionally skips the
    encoder's auto-recompute so the length field stays wrong.  It encodes
    the rest of the frame normally, then overwrites just the length bytes
    in the output.

    Falls back to raw BitFlip if no suitable field is found.

    Args:
        encoder:     A DefinitionBasedEncoder instance.
        skip_fields: Field names to skip even if they look like lengths.
    """

    def __init__(
        self,
        encoder:     "DefinitionBasedEncoder",
        skip_fields: Optional[list[str]] = None,
    ) -> None:
        self._encoder     = encoder
        self._skip_fields = set(skip_fields or [])

    @property
    def name(self) -> str:
        return "LengthMangle"

    async def mutate(
        self,
        frame:  "Frame",
        parsed: Optional["ParsedMessage"],
    ) -> Optional[bytes]:
        if parsed is None or not parsed.fields:
            return None

        length_fields: list["ParsedField"] = [
            f for f in parsed.fields
            if f.name not in self._skip_fields
            and _is_length_field(f.name)
            and isinstance(f.value, int)
        ]
        if not length_fields:
            return None

        target = random.choice(length_fields)
        field_type = _size_to_type(target.size)
        boundaries = _INT_BOUNDARIES.get(field_type, [0, 0xFFFF])

        # Include a ±offset variation around the real value
        real_val = target.value
        mangled_val = random.choice([
            random.choice(boundaries),
            max(0, real_val + random.randint(1, 256)),
            max(0, real_val - random.randint(1, min(real_val, 256)) if real_val > 0 else 0),
        ])

        try:
            # First encode normally (encoder auto-recomputes lengths correctly)
            normal_bytes = bytearray(self._encoder.encode_with_edits(parsed, {}))
            # Then overwrite just the target field's bytes with the mangled value
            if target.size <= 8 and field_type.startswith("uint"):
                mangled_bytes = mangled_val.to_bytes(target.size, "big", signed=False)
                normal_bytes[target.offset:target.offset + target.size] = mangled_bytes
            elif target.size <= 8 and field_type.startswith("int"):
                mangled_bytes = mangled_val.to_bytes(target.size, "big", signed=True)
                normal_bytes[target.offset:target.offset + target.size] = mangled_bytes
            return bytes(normal_bytes)
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _size_to_type(size_bytes: int) -> str:
    """Map a field's byte size to an assumed unsigned integer type name."""
    return {1: "uint8", 2: "uint16", 4: "uint32", 8: "uint64"}.get(size_bytes, "uint32")
