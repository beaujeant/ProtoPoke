"""
Core data models for ProtoPoke.

These are the fundamental data structures used throughout the entire system.
Everything from the transport layer to the UI passes these objects around.

Design decisions:
- dataclasses throughout: explicit, readable, easy to serialize to dict/JSON
- Enums for state: prevents typos and enables exhaustive matching
- Immutable IDs: set at creation, never changed
- Optional fields have defaults so creation is ergonomic
- ParsedMessage keeps a reference to its source Frame (raw bytes always accessible)
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Direction(Enum):
    """Which direction traffic is flowing in a proxied session."""
    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"

    def opposite(self) -> "Direction":
        if self is Direction.CLIENT_TO_SERVER:
            return Direction.SERVER_TO_CLIENT
        return Direction.CLIENT_TO_SERVER


class SessionState(Enum):
    """Lifecycle states of a proxied TCP session."""
    CONNECTING  = "connecting"    # Client accepted; connecting to server
    ACTIVE      = "active"        # Both sides up; data flowing
    ONLY_SERVER = "only server"   # Client disconnected; server side still up
    ONLY_CLIENT = "only client"   # Server disconnected; client side still up
    CLOSED      = "closed"        # Both sides fully closed


class InterceptAction(Enum):
    """Verdict for an intercepted unit of traffic."""
    FORWARD  = "forward"    # Send as-is
    DROP     = "drop"       # Discard; don't forward
    MODIFIED = "modified"   # Send with replacement bytes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def new_id() -> str:
    """Generate a new unique ID (UUID4 string)."""
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _serialise_field_value(value: Any) -> Any:
    """
    Coerce a ParsedField value to a JSON-serialisable type.

    - ``bytes``       → lowercase hex string
    - ``list``        → each element recursed (handles nested ParsedField lists)
    - ``int / str / float / bool / None`` → returned as-is
    - anything else   → ``str(value)`` as a fallback
    """
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, list):
        return [_serialise_field_value(item) for item in value]
    if isinstance(value, (int, str, float, bool)) or value is None:
        return value
    # Fallback: ParsedField children or unknown types
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return str(value)


# ---------------------------------------------------------------------------
# Core data models
# ---------------------------------------------------------------------------

@dataclass
class Frame:
    """
    A logical unit of captured TCP traffic.

    A Frame represents a chunk of bytes flowing in one direction within one
    session. At the raw transport level this is whatever the framer decides
    is a logical boundary — for the RawFramer that's a single read() chunk;
    for a length-prefix framer it's one complete message.

    Attributes:
        id:              Unique ID — used to reference this frame in the UI,
                         the intercept queue, and replay.
        session_id:      Which session this frame belongs to.
        direction:       Which way the bytes are flowing.
        raw_bytes:       The actual bytes captured from the network.
        timestamp:       When this frame was captured (seconds since epoch).
        sequence_number: Ordering within the same session+direction stream.
        framer_name:     Name of the Framer that produced this frame.
    """
    id:              str
    session_id:      str
    direction:       Direction
    raw_bytes:       bytes
    timestamp:       float
    sequence_number: int
    framer_name:     str = "raw"

    @classmethod
    def create(
        cls,
        session_id:      str,
        direction:       Direction,
        raw_bytes:       bytes,
        sequence_number: int,
        framer_name:     str = "raw",
    ) -> "Frame":
        """Factory — sets id and timestamp automatically."""
        return cls(
            id=new_id(),
            session_id=session_id,
            direction=direction,
            raw_bytes=raw_bytes,
            timestamp=time.time(),
            sequence_number=sequence_number,
            framer_name=framer_name,
        )

    def to_dict(self) -> dict:
        """
        Serialise to a JSON-compatible dict.

        ``raw_bytes`` is encoded as a hex string so it survives JSON
        serialisation.  MCP tool handlers and project save/load use this.
        """
        return {
            "id":              self.id,
            "session_id":      self.session_id,
            "direction":       self.direction.value,
            "raw_bytes":       self.raw_bytes.hex(),
            "raw_bytes_len":   len(self.raw_bytes),
            "timestamp":       self.timestamp,
            "sequence_number": self.sequence_number,
            "framer_name":     self.framer_name,
        }

    def __repr__(self) -> str:
        return (
            f"Frame(id={self.id[:8]}... "
            f"dir={self.direction.value} "
            f"len={len(self.raw_bytes)} "
            f"seq={self.sequence_number})"
        )


@dataclass
class SessionInfo:
    """
    Metadata about one proxied TCP session.

    Intentionally separated from the live connection objects (asyncio streams)
    so that session info can be stored, queried, and passed around without
    holding live references. The SessionRegistry owns the live Session objects;
    this is the serializable view.
    """
    id:             str
    client_host:    str
    client_port:    int
    server_host:    str
    server_port:    int
    state:          SessionState
    created_at:     float
    closed_at:      Optional[float] = None
    forwarder_name: str             = ""
    transport:      str             = "tcp"   # "tcp" | "udp" | "socks5"

    @classmethod
    def create(
        cls,
        client_host:    str,
        client_port:    int,
        server_host:    str,
        server_port:    int,
        forwarder_name: str = "",
        transport:      str = "tcp",
    ) -> "SessionInfo":
        return cls(
            id=new_id(),
            client_host=client_host,
            client_port=client_port,
            server_host=server_host,
            server_port=server_port,
            state=SessionState.CONNECTING,
            created_at=time.time(),
            forwarder_name=forwarder_name,
            transport=transport,
        )

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dict."""
        return {
            "id":             self.id,
            "client_host":    self.client_host,
            "client_port":    self.client_port,
            "server_host":    self.server_host,
            "server_port":    self.server_port,
            "state":          self.state.value,
            "created_at":     self.created_at,
            "closed_at":      self.closed_at,
            "forwarder_name": self.forwarder_name,
            "transport":      self.transport,
        }

    def __repr__(self) -> str:
        return (
            f"SessionInfo(id={self.id[:8]}... "
            f"{self.client_host}:{self.client_port} -> "
            f"{self.server_host}:{self.server_port} "
            f"state={self.state.value})"
        )


@dataclass
class TamperedUnit:
    """
    A Frame that is being held by the intercept controller for inspection.

    When interception is enabled, frames are wrapped in an TamperedUnit
    and placed in the intercept queue. The relay waits (asyncio await) for
    a verdict. An external caller (API, UI) calls set_verdict() to resolve it.

    The verdict and modified_data fields are filled in by the controller
    when a decision is made.

    Attributes:
        id:            Unique ID for this interception event.
        frame:         The captured frame being held.
        action:        The verdict (set by the operator).
        modified_data: Replacement bytes when action is MODIFIED.
    """
    id:            str
    frame:         Frame
    action:        InterceptAction = InterceptAction.FORWARD
    modified_data: Optional[bytes] = None

    @classmethod
    def from_frame(cls, frame: Frame) -> "TamperedUnit":
        return cls(id=new_id(), frame=frame)

    def effective_bytes(self) -> bytes:
        """
        The bytes that should actually go on the wire.

        Returns modified_data if the verdict is MODIFIED, otherwise
        returns the original frame bytes.
        """
        if self.action is InterceptAction.MODIFIED and self.modified_data is not None:
            return self.modified_data
        return self.frame.raw_bytes

    def to_dict(self) -> dict:
        """
        Serialise to a JSON-compatible dict.

        Embeds the full ``frame.to_dict()`` so the caller gets all frame
        metadata in one call.  ``effective_bytes`` is included as a hex
        string so the MCP tool can show what will actually be forwarded.
        """
        return {
            "id":             self.id,
            "frame":          self.frame.to_dict(),
            "action":         self.action.value,
            "effective_bytes": self.effective_bytes().hex(),
        }

    def __repr__(self) -> str:
        return (
            f"TamperedUnit(id={self.id[:8]}... "
            f"action={self.action.value} "
            f"frame={self.frame.id[:8]}...)"
        )


@dataclass
class ParsedField:
    """
    One parsed field within a protocol message.

    Carries both the decoded Python value AND the byte-level metadata
    (offset, size, raw_bytes) so that:
      - The hex-dump renderer can highlight exactly which bytes belong to this field.
      - The encoder can re-assemble bytes field-by-field for intercept+modify / replay.
      - Nested structures (TLV children, array items) are expressed as children.

    Attributes:
        name:          Field name from the protocol definition.
        value:         Decoded Python value: int, str, bytes, list[ParsedField], etc.
        raw_bytes:     Exact bytes consumed by this field in the original frame.
        offset:        Byte offset within the frame where this field starts.
        size:          Number of bytes consumed (== len(raw_bytes)).
        display_hint:  How to format the value: "hex", "ascii", "decimal", "enum", "auto".
        display_value: Pre-rendered string shown in the UI (enum label, decoded str, …).
        children:      Nested ParsedField list for TLV sequences, arrays, bitfields.
    """
    name:          str
    value:         Any
    raw_bytes:     bytes
    offset:        int
    size:          int
    display_hint:  str                = "auto"
    display_value: str                = ""
    children:      list[ParsedField]  = field(default_factory=list)

    def to_dict(self) -> dict:
        """
        Serialise to a JSON-compatible dict, recursing into ``children``.

        ``raw_bytes`` is hex-encoded.  ``value`` is coerced:
          - ``bytes``  → hex string
          - ``list``   → recursed if elements are ParsedField, else left as-is
          - everything else → as-is (int, str, float are already JSON-safe)
        """
        return {
            "name":          self.name,
            "value":         _serialise_field_value(self.value),
            "raw_bytes":     self.raw_bytes.hex(),
            "offset":        self.offset,
            "size":          self.size,
            "display_hint":  self.display_hint,
            "display_value": self.display_value,
            "children":      [c.to_dict() for c in self.children],
        }

    def __repr__(self) -> str:
        return (
            f"ParsedField(name={self.name!r} offset={self.offset} "
            f"size={self.size} value={self.value!r})"
        )


@dataclass
class ParsedMessage:
    """
    A protocol-decoded view of a Frame.

    Produced by a ProtocolDecoder when it interprets a Frame's raw bytes
    as structured application-protocol fields. The raw Frame is always
    kept so you can get back to the original bytes from any parsed view.

    Attributes:
        id:            Unique ID for this parsed view.
        frame:         The source frame (raw bytes always available via frame.raw_bytes).
        protocol_name: Human-readable protocol identifier (e.g. 'HTTP/1.1', 'Redis').
        message_type:  The matched message type name (e.g. "LoginRequest"), or "" if
                       no definition matched / passthrough decoding.
        fields:        Ordered list of parsed fields. Each entry carries offset, size,
                       and raw bytes for hex-dump highlighting and re-encoding.
        display_name:  Short human-readable summary for UI lists.
        error:         Non-empty if parsing failed or was partial; explains why.
    """
    id:            str
    frame:         Frame
    protocol_name: str
    message_type:  str               = ""
    fields:        list[ParsedField] = field(default_factory=list)
    display_name:  str               = ""
    error:         Optional[str]     = None

    @classmethod
    def from_frame(
        cls,
        frame:         Frame,
        protocol_name: str,
        message_type:  str               = "",
        fields:        list[ParsedField] = None,
        display_name:  str               = "",
        error:         Optional[str]     = None,
    ) -> "ParsedMessage":
        return cls(
            id=new_id(),
            frame=frame,
            protocol_name=protocol_name,
            message_type=message_type,
            fields=fields or [],
            display_name=display_name,
            error=error,
        )

    def field_by_name(self, name: str) -> Optional[ParsedField]:
        """Return the first top-level field with the given name, or None."""
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def to_dict(self) -> dict:
        """
        Serialise to a JSON-compatible dict.

        Embeds ``frame_id`` (not the full frame — callers can fetch that
        separately) and the full recursive field tree.
        """
        return {
            "id":            self.id,
            "frame_id":      self.frame.id,
            "protocol_name": self.protocol_name,
            "message_type":  self.message_type,
            "fields":        [f.to_dict() for f in self.fields],
            "display_name":  self.display_name,
            "error":         self.error,
        }

    def as_dict(self) -> dict:
        """Flat dict of field name → value (top-level only). Useful for quick access."""
        return {f.name: f.value for f in self.fields}

    def __repr__(self) -> str:
        return (
            f"ParsedMessage(protocol={self.protocol_name!r} "
            f"type={self.message_type!r} "
            f"fields={[f.name for f in self.fields]})"
        )
