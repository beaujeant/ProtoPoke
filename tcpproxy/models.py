"""
Core data models for tcpproxy.

These are the fundamental data structures used throughout the entire system.
Everything from the transport layer to the UI passes these objects around.

Design decisions:
- dataclasses throughout: explicit, readable, easy to serialize to dict/JSON/SQLite
- Enums for state: prevents typos and enables exhaustive matching
- Immutable IDs: set at creation, never changed
- Optional fields have defaults so creation is ergonomic
- ParsedMessage keeps a reference to its source Frame (raw bytes always accessible)

Persistence note:
    All fields here are primitive types (str, int, float, bytes, Enum).
    Converting to SQLite rows or JSON is straightforward. A future
    SqliteStorageBackend can persist/restore these without schema changes.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


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
    CONNECTING = "connecting"   # Client accepted; connecting to server
    ACTIVE     = "active"       # Both sides up; data flowing
    CLOSING    = "closing"      # One side has started to close
    CLOSED     = "closed"       # Fully closed


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
                         the intercept queue, replay, and storage.
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
    id:          str
    client_host: str
    client_port: int
    server_host: str
    server_port: int
    state:       SessionState
    created_at:  float
    closed_at:   Optional[float] = None

    @classmethod
    def create(
        cls,
        client_host: str,
        client_port: int,
        server_host: str,
        server_port: int,
    ) -> "SessionInfo":
        return cls(
            id=new_id(),
            client_host=client_host,
            client_port=client_port,
            server_host=server_host,
            server_port=server_port,
            state=SessionState.CONNECTING,
            created_at=time.time(),
        )

    def __repr__(self) -> str:
        return (
            f"SessionInfo(id={self.id[:8]}... "
            f"{self.client_host}:{self.client_port} -> "
            f"{self.server_host}:{self.server_port} "
            f"state={self.state.value})"
        )


@dataclass
class InterceptedUnit:
    """
    A Frame that is being held by the intercept controller for inspection.

    When interception is enabled, frames are wrapped in an InterceptedUnit
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
    def from_frame(cls, frame: Frame) -> "InterceptedUnit":
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

    def __repr__(self) -> str:
        return (
            f"InterceptedUnit(id={self.id[:8]}... "
            f"action={self.action.value} "
            f"frame={self.frame.id[:8]}...)"
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
        fields:        Protocol-specific parsed data — shape is protocol-defined.
        display_name:  Short human-readable summary for UI lists.
    """
    id:            str
    frame:         Frame
    protocol_name: str
    fields:        dict
    display_name:  str = ""

    @classmethod
    def from_frame(
        cls,
        frame:         Frame,
        protocol_name: str,
        fields:        dict,
        display_name:  str = "",
    ) -> "ParsedMessage":
        return cls(
            id=new_id(),
            frame=frame,
            protocol_name=protocol_name,
            fields=fields,
            display_name=display_name,
        )

    def __repr__(self) -> str:
        return (
            f"ParsedMessage(protocol={self.protocol_name} "
            f"display={self.display_name!r} "
            f"fields={list(self.fields.keys())})"
        )
