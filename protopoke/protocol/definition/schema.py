"""
Protocol definition schema.

Python dataclasses that represent a loaded protocol definition.
These are produced by the loader (from YAML/JSON/dict) and consumed by
the parser engine.

The schema mirrors the YAML DSL one-to-one.  Every YAML key has a
corresponding field here.  The loader does all validation so the parser
can trust the objects it receives.

Hierarchy:
    ProtocolDefinition
     └─ MessageDefinition  (one per packet type)
         ├─ MatchRule       (how to recognise this packet type)
         └─ FieldDefinition (one per field, possibly nested)
             ├─ TLVConfig   (when type == TLV_SEQUENCE)
             ├─ ArrayConfig (when type == ARRAY)
             └─ BitfieldConfig (when type == BITFIELD)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class FieldType(str, Enum):
    """Scalar and composite field types understood by the parser."""
    # Unsigned integers
    UINT8   = "uint8"
    UINT16  = "uint16"
    UINT32  = "uint32"
    UINT64  = "uint64"
    # Signed integers
    INT8    = "int8"
    INT16   = "int16"
    INT32   = "int32"
    INT64   = "int64"
    # Floating point
    FLOAT32 = "float32"
    FLOAT64 = "float64"
    # Raw bytes / strings
    BYTES   = "bytes"
    STRING  = "string"
    # Composite
    BITFIELD     = "bitfield"      # Single int decoded as named bits
    ARRAY        = "array"         # Repeated sub-structure
    TLV_SEQUENCE = "tlv_sequence"  # Sequence of T-L-V triples
    PADDING      = "padding"       # Skip N bytes (alignment / reserved)


class DisplayHint(str, Enum):
    """How to render the field value in the UI."""
    AUTO    = "auto"     # Choose based on type (default)
    HEX     = "hex"      # Hex bytes: "DE AD BE EF"
    ASCII   = "ascii"    # Printable ASCII, dot for non-printable
    UNICODE = "unicode"  # UTF-8 decode attempt
    DECIMAL = "decimal"  # Plain integer
    ENUM    = "enum"     # Map value to a label via the enum dict


class MatchType(str, Enum):
    """How a MessageDefinition identifies itself in a stream."""
    MAGIC    = "magic"    # Match bytes at a fixed offset
    SEQUENCE = "sequence" # Match by position in the session stream
    ALWAYS   = "always"   # Wildcard — matches any frame (use as catch-all)


class DirectionFilter(str, Enum):
    """Optional direction filter on a MessageDefinition."""
    BOTH             = "both"
    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"


# ---------------------------------------------------------------------------
# Sub-configs for composite field types
# ---------------------------------------------------------------------------

@dataclass
class TLVTagDefinition:
    """Definition for one tag value inside a TLV sequence."""
    name:       str
    value_type: FieldType      = FieldType.BYTES
    encoding:   str            = "utf8"    # for STRING value_type
    display:    DisplayHint    = DisplayHint.AUTO


@dataclass
class TLVConfig:
    """
    Configuration for a TLV_SEQUENCE field.

    Describes how to parse a stream of Type-Length-Value triples.

    Attributes:
        type_size:    Bytes for the T (type) field. 1, 2, or 4.
        length_size:  Bytes for the L (length) field. 1, 2, or 4.
        endianness:   Byte order for T and L fields ("big" or "little").
        tags:         Map of tag integer value → TLVTagDefinition.
                      Unknown tags are captured as raw bytes.
    """
    type_size:  int                          = 1
    length_size: int                         = 2
    endianness: str                          = "big"
    tags:       dict[int, TLVTagDefinition]  = field(default_factory=dict)


@dataclass
class ArrayConfig:
    """
    Configuration for an ARRAY field.

    Describes a repeated sub-structure.

    Attributes:
        count:  Expression string giving the number of repetitions.
                May reference earlier field names: "{user_count}" or "4".
        item:   Ordered list of FieldDefinitions for one array element.
    """
    count: str                         # e.g. "{user_count}" or "4"
    item:  list[FieldDefinition]       = field(default_factory=list)


@dataclass
class BitfieldConfig:
    """
    Bit-level breakdown of a uint8/16/32/64 field.

    Attributes:
        bits:  Map of bit-index (0 = LSB) → bit name.
               The parser sets each bit name as a child ParsedField with
               value 0 or 1.
    """
    bits: dict[int, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Field definition
# ---------------------------------------------------------------------------

@dataclass
class FieldDefinition:
    """
    Definition for one field in a message.

    The parser walks these definitions in order to extract bytes from the
    frame.  All length/offset expressions may reference any *previously
    parsed* field by name using the `{expr}` syntax.

    Attributes:
        name:           Field name. Must be unique within its parent message
                        or array item (used as a key in expression evaluation).
        type:           Field type (see FieldType enum).
        length:         Length source. Can be:
                          - An integer literal: 4
                          - A field reference: "{username_len}"
                          - An expression:      "{total_len - header_size}"
                          - -1: consume the rest of the frame
                        Required for BYTES, STRING, TLV_SEQUENCE.
                        For integer types (uint8 etc.) the size is implied.
        null_terminated: For STRING fields — consume until a NUL byte instead
                         of using `length`. `length` acts as a max if both set.
        encoding:       String encoding for STRING fields ("utf8", "ascii", "utf16").
        display:        How to display this field in the UI.
        enum:           Map of integer value → label string. When set, the
                        display_value is the label; unknown values shown as raw.
        tlv:            Config for TLV_SEQUENCE fields.
        array:          Config for ARRAY fields.
        bitfield:       Config for BITFIELD fields.
    """
    name:           str
    type:           FieldType      = FieldType.BYTES
    length:         Optional[str]  = None       # str so it can hold expressions
    null_terminated: bool          = False
    encoding:       str            = "utf8"
    display:        DisplayHint    = DisplayHint.AUTO
    enum:           dict[int, str] = field(default_factory=dict)
    tlv:            Optional[TLVConfig]      = None
    array:          Optional[ArrayConfig]    = None
    bitfield:       Optional[BitfieldConfig] = None


# ---------------------------------------------------------------------------
# Match rule
# ---------------------------------------------------------------------------

@dataclass
class MatchRule:
    """
    How a MessageDefinition is recognised.

    type == MAGIC:
        Compare bytes at `offset` against `value`.
        `value` is a list of byte values (ints 0-255).
        All bytes must match.  Typically one or two bytes.

    type == SEQUENCE:
        Match by position in the session stream.
        `direction` filters which stream to count in (default: both).
        `index` is 0-based: 0 = first frame, 1 = second, etc.
        Frames are counted per (session, direction) pair.

    type == ALWAYS:
        Wildcard.  Always matches.  Use as a catch-all at the end of
        the message list.
    """
    type:      MatchType          = MatchType.ALWAYS
    # MAGIC
    offset:    int                = 0
    value:     list[int]          = field(default_factory=list)
    # SEQUENCE
    direction: DirectionFilter    = DirectionFilter.BOTH
    index:     int                = 0


# ---------------------------------------------------------------------------
# Message definition
# ---------------------------------------------------------------------------

@dataclass
class MessageDefinition:
    """
    Definition for one logical message / packet type.

    Attributes:
        name:        Human-readable packet type name shown in the UI.
        description: Optional longer description.
        direction:   Optional filter — only match frames going in this
                     direction. Useful for protocols where the same magic
                     byte means different things C→S vs S→C.
        match:       Rule used to recognise this packet type.
        fields:      Ordered list of field definitions.
    """
    name:        str
    description: str              = ""
    direction:   DirectionFilter  = DirectionFilter.BOTH
    match:       MatchRule        = field(default_factory=MatchRule)
    fields:      list[FieldDefinition] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Top-level protocol definition
# ---------------------------------------------------------------------------

@dataclass
class ProtocolDefinition:
    """
    Top-level container for a protocol definition.

    Attributes:
        name:       Protocol name shown in the UI.
        version:    Optional version string.
        endianness: Default byte order for all integer fields ("big" or "little").
                    Individual fields can override this (future extension).
        messages:   Ordered list of message definitions.  The parser tries
                    each in order and uses the first match — put specific
                    matches before catch-alls.
    """
    name:       str
    version:    str                   = "1.0"
    endianness: str                   = "big"   # "big" or "little"
    messages:   list[MessageDefinition] = field(default_factory=list)
