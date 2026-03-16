"""
Data models for the Sequence feature.

SequenceFrame
-------------
One packet slot in a sequence. Stores the hex content (with optional {{VAR}}
placeholders) and a human label.

SequenceSession
----------------
A named sequence tab: ordered list of frames, a runtime variable store, the
target connection parameters, and the flat send/receive history log.

HistoryEntry
------------
A single sent or received packet recorded during a sequence run. The history
is a flat chronological append-only log across all runs.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# SequenceFrame
# ---------------------------------------------------------------------------

@dataclass
class SequenceFrame:
    """
    One packet slot in a sequence.

    Attributes:
        id:        Unique ID (UUID4).
        label:     Human-readable name shown in the frame list.
        raw_hex:   Space-separated hex pairs, may contain {{VAR}} placeholders.
                   Example: ``"01 02 {{SESS_ID}} 0a 0b"``
        direction: Traffic direction for this frame.
                   ``"client_to_server"`` — send bytes toward the upstream server
                   (normal client request).
                   ``"server_to_client"`` — inject bytes toward the client
                   (simulate a server push / response).
                   A single sequence should only contain frames of one direction.
    """

    id:        str
    label:     str
    raw_hex:   str
    direction: str = "client_to_server"   # "client_to_server" | "server_to_client"

    @classmethod
    def create(
        cls,
        label:     str = "",
        raw_hex:   str = "",
        direction: str = "client_to_server",
    ) -> "SequenceFrame":
        return cls(id=str(uuid.uuid4()), label=label, raw_hex=raw_hex, direction=direction)

    # ------------------------------------------------------------------
    # Derived properties for UI display
    # ------------------------------------------------------------------

    def preview(self, max_bytes: int = 12) -> str:
        """Hex preview of the first *max_bytes* bytes (placeholders shown as-is)."""
        tokens = self.raw_hex.split()
        shown: list[str] = []
        byte_count = 0
        for tok in tokens:
            if tok.startswith("{{") and tok.endswith("}}"):
                shown.append(tok)
                # Treat placeholder as 1 display token, not adding to byte count
            elif len(tok) == 2:
                if byte_count >= max_bytes:
                    shown.append("…")
                    break
                shown.append(tok)
                byte_count += 1
        return " ".join(shown)

    def byte_length(self) -> int:
        """Approximate byte count (placeholders contribute 0)."""
        cleaned = re.sub(r"\{\{[^{}]+\}\}", "", self.raw_hex)
        hex_only = cleaned.replace(" ", "").replace("\n", "")
        return len(hex_only) // 2

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "id":        self.id,
            "label":     self.label,
            "raw_hex":   self.raw_hex,
            "direction": self.direction,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SequenceFrame":
        return cls(
            id=d["id"],
            label=d.get("label", ""),
            raw_hex=d.get("raw_hex", ""),
            direction=d.get("direction", "client_to_server"),
        )


# ---------------------------------------------------------------------------
# HistoryEntry
# ---------------------------------------------------------------------------

@dataclass
class HistoryEntry:
    """
    A single packet in the flat send/receive history log.

    Attributes:
        id:          Unique ID (UUID4).
        timestamp:   When this packet was sent or received (Unix seconds).
        direction:   ``"sent"`` or ``"received"``.
        raw_bytes:   The actual bytes on the wire.
        frame_label: Label of the sequence frame that triggered this entry.
    """

    id:          str
    timestamp:   float
    direction:   str    # "sent" | "received"
    raw_bytes:   bytes
    frame_label: str

    @classmethod
    def create_sent(cls, raw_bytes: bytes, frame_label: str) -> "HistoryEntry":
        return cls(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            direction="sent",
            raw_bytes=raw_bytes,
            frame_label=frame_label,
        )

    @classmethod
    def create_received(cls, raw_bytes: bytes, frame_label: str = "") -> "HistoryEntry":
        return cls(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            direction="received",
            raw_bytes=raw_bytes,
            frame_label=frame_label,
        )

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "timestamp":   self.timestamp,
            "direction":   self.direction,
            "raw_bytes":   self.raw_bytes.hex(),
            "frame_label": self.frame_label,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "HistoryEntry":
        return cls(
            id=d["id"],
            timestamp=d["timestamp"],
            direction=d["direction"],
            raw_bytes=bytes.fromhex(d["raw_bytes"]),
            frame_label=d.get("frame_label", ""),
        )


# ---------------------------------------------------------------------------
# SequenceSession
# ---------------------------------------------------------------------------

@dataclass
class SequenceSession:
    """
    A named sequence of packets (one "tab" in the Sequence feature).

    Attributes:
        id:                Unique ID (UUID4).
        label:             User-visible name shown in the tab strip.
        host:              Target host for new connections.
        port:              Target port for new connections.
        tls:               Whether to use TLS for new connections.
        frames:            Ordered list of packet frames.
        variables:         Runtime variable store: name → hex-encoded bytes.
                           Persisted across saves so captured state survives restarts.
        history:           Flat chronological log of all sent/received packets.
        response_window:   Seconds to wait for server response after each send.
        source_session_id: If set, inject into this existing proxy session instead
                           of opening a new TCP connection.
    """

    id:                str
    label:             str
    host:              str
    port:              int
    tls:               bool                = False
    frames:            list[SequenceFrame] = field(default_factory=list)
    variables:         dict[str, str]      = field(default_factory=dict)
    history:           list[HistoryEntry]  = field(default_factory=list)
    response_window:   float               = 1.0
    source_session_id: Optional[str]       = None

    @classmethod
    def create(
        cls,
        label:             str,
        host:              str  = "",
        port:              int  = 0,
        tls:               bool = False,
        source_session_id: Optional[str] = None,
    ) -> "SequenceSession":
        return cls(
            id=str(uuid.uuid4()),
            label=label,
            host=host,
            port=port,
            tls=tls,
            source_session_id=source_session_id,
        )

    def to_dict(self) -> dict:
        return {
            "id":                self.id,
            "label":             self.label,
            "host":              self.host,
            "port":              self.port,
            "tls":               self.tls,
            "frames":            [f.to_dict() for f in self.frames],
            "variables":         self.variables,
            "history":           [h.to_dict() for h in self.history],
            "response_window":   self.response_window,
            "source_session_id": self.source_session_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SequenceSession":
        raw_frames = d.get("frames", [])
        return cls(
            id=d["id"],
            label=d["label"],
            host=d.get("host", ""),
            port=d.get("port", 0),
            tls=d.get("tls", False),
            frames=[SequenceFrame.from_dict(f) for f in raw_frames],
            variables=d.get("variables", {}),
            history=[HistoryEntry.from_dict(h) for h in d.get("history", [])],
            response_window=d.get("response_window", 1.0),
            source_session_id=d.get("source_session_id"),
        )
