"""
Data models for the Forge feature.

PlaybookFrame
-------------
One packet slot in a playbook. Stores the hex content (with optional
{{VAR}} placeholders), a human label, and the traffic direction.

TrafficEntry
------------
A single sent or received packet recorded during a playbook run.

PlaybookRun
-----------
One execution of a Playbook: a timestamp and the flat ordered log of all
sent/received packets from that run.

Playbook
--------
A named playbook: ordered list of frames, connection parameters, variable
store, and the history of all runs.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# PlaybookFrame
# ---------------------------------------------------------------------------

@dataclass
class PlaybookFrame:
    """
    One packet slot in a playbook.

    Attributes:
        id:        Unique ID (UUID4).
        label:     Human-readable name shown in the frame list.
        raw_hex:   Space-separated hex pairs, may contain {{VAR}} placeholders.
                   Example: ``"01 02 {{SESS_ID}} 0a 0b"``
        direction: Traffic direction for this frame.
                   ``"client_to_server"`` — send bytes toward the upstream server.
                   ``"server_to_client"`` — inject bytes toward the client.
    """

    id:        str
    label:     str
    raw_hex:   str
    direction: str = "client_to_server"

    @classmethod
    def create(
        cls,
        label:     str = "",
        raw_hex:   str = "",
        direction: str = "client_to_server",
    ) -> "PlaybookFrame":
        return cls(id=str(uuid.uuid4()), label=label, raw_hex=raw_hex, direction=direction)

    def preview(self, max_bytes: int = 12) -> str:
        """Hex preview of the first *max_bytes* bytes (placeholders shown as-is)."""
        tokens = self.raw_hex.split()
        shown: list[str] = []
        byte_count = 0
        for tok in tokens:
            if tok.startswith("{{") and tok.endswith("}}"):
                shown.append(tok)
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

    def to_dict(self) -> dict:
        return {
            "id":        self.id,
            "label":     self.label,
            "raw_hex":   self.raw_hex,
            "direction": self.direction,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PlaybookFrame":
        return cls(
            id=d["id"],
            label=d.get("label", ""),
            raw_hex=d.get("raw_hex", ""),
            direction=d.get("direction", "client_to_server"),
        )


# ---------------------------------------------------------------------------
# TrafficEntry
# ---------------------------------------------------------------------------

@dataclass
class TrafficEntry:
    """
    A single packet in the flat send/receive traffic log for one run.

    Attributes:
        id:          Unique ID (UUID4).
        timestamp:   When this packet was sent or received (Unix seconds).
        direction:   ``"sent"`` or ``"received"``.
        raw_bytes:   The actual bytes on the wire.
        frame_label: Label of the playbook frame that triggered this entry.
    """

    id:          str
    timestamp:   float
    direction:   str    # "sent" | "received"
    raw_bytes:   bytes
    frame_label: str

    @classmethod
    def create_sent(cls, raw_bytes: bytes, frame_label: str) -> "TrafficEntry":
        return cls(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            direction="sent",
            raw_bytes=raw_bytes,
            frame_label=frame_label,
        )

    @classmethod
    def create_received(cls, raw_bytes: bytes, frame_label: str = "") -> "TrafficEntry":
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
    def from_dict(cls, d: dict) -> "TrafficEntry":
        return cls(
            id=d["id"],
            timestamp=d["timestamp"],
            direction=d["direction"],
            raw_bytes=bytes.fromhex(d["raw_bytes"]),
            frame_label=d.get("frame_label", ""),
        )


# ---------------------------------------------------------------------------
# PlaybookRun
# ---------------------------------------------------------------------------

@dataclass
class PlaybookRun:
    """
    A single execution of a Playbook.

    Attributes:
        id:             Unique ID (UUID4).
        timestamp:      When the run started (Unix seconds).
        playbook_label: Name of the playbook at the time of the run.
        traffic:        Ordered log of all sent/received packets.
    """

    id:             str
    timestamp:      float
    playbook_label: str
    traffic:        list[TrafficEntry] = field(default_factory=list)

    @classmethod
    def create(cls, playbook_label: str) -> "PlaybookRun":
        return cls(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            playbook_label=playbook_label,
        )

    def sent_bytes_total(self) -> int:
        return sum(len(e.raw_bytes) for e in self.traffic if e.direction == "sent")

    def received_bytes_total(self) -> int:
        return sum(len(e.raw_bytes) for e in self.traffic if e.direction == "received")

    def to_dict(self) -> dict:
        return {
            "id":             self.id,
            "timestamp":      self.timestamp,
            "playbook_label": self.playbook_label,
            "traffic":        [t.to_dict() for t in self.traffic],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PlaybookRun":
        return cls(
            id=d["id"],
            timestamp=d["timestamp"],
            playbook_label=d.get("playbook_label", ""),
            traffic=[TrafficEntry.from_dict(t) for t in d.get("traffic", [])],
        )


# ---------------------------------------------------------------------------
# Playbook
# ---------------------------------------------------------------------------

@dataclass
class Playbook:
    """
    A named playbook: an ordered sequence of frames to send in one shot.

    Attributes:
        id:                Unique ID (UUID4).
        label:             User-visible name shown in the playbook list.
        host:              Target host for new connections.
        port:              Target port for new connections.
        tls:               Whether to use TLS for new connections (TCP only).
        transport:         ``"tcp"`` (default) or ``"udp"``. UDP playbooks
                           cannot use TLS and do not support half-close;
                           each frame is sent as a single datagram.
        source_session_id: If set, inject into this existing proxy session
                           instead of opening a new TCP connection.
        response_window:   Seconds to wait for server response after each frame send.
        variables:         Runtime variable store: name → hex-encoded bytes.
                           Persisted across saves.
        frames:            Ordered list of packet frames.
        runs:              History of all executions (newest last).
    """

    id:                str
    label:             str
    host:              str
    port:              int
    tls:               bool               = False
    transport:         str                = "tcp"   # "tcp" | "udp"
    source_session_id: Optional[str]      = None
    response_window:   float              = 1.0
    variables:         dict[str, str]     = field(default_factory=dict)
    frames:            list[PlaybookFrame] = field(default_factory=list)
    runs:              list[PlaybookRun]  = field(default_factory=list)

    @classmethod
    def create(
        cls,
        label:             str,
        host:              str  = "",
        port:              int  = 0,
        tls:               bool = False,
        source_session_id: Optional[str] = None,
        response_window:   float = 1.0,
        transport:         str   = "tcp",
    ) -> "Playbook":
        return cls(
            id=str(uuid.uuid4()),
            label=label,
            host=host,
            port=port,
            tls=tls,
            transport=transport,
            source_session_id=source_session_id,
            response_window=response_window,
        )

    def to_dict(self) -> dict:
        return {
            "id":                self.id,
            "label":             self.label,
            "host":              self.host,
            "port":              self.port,
            "tls":               self.tls,
            "transport":         self.transport,
            "source_session_id": self.source_session_id,
            "response_window":   self.response_window,
            "variables":         self.variables,
            "frames":            [f.to_dict() for f in self.frames],
            "runs":              [r.to_dict() for r in self.runs],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Playbook":
        return cls(
            id=d["id"],
            label=d["label"],
            host=d.get("host", ""),
            port=d.get("port", 0),
            tls=d.get("tls", False),
            transport=d.get("transport", "tcp"),
            source_session_id=d.get("source_session_id"),
            response_window=d.get("response_window", 1.0),
            variables=d.get("variables", {}),
            frames=[PlaybookFrame.from_dict(f) for f in d.get("frames", [])],
            runs=[PlaybookRun.from_dict(r) for r in d.get("runs", [])],
        )

    # -- Standalone export / import (Forge "Import / Export" buttons) -------
    #
    # to_dict()/from_dict() above is the full in-process / project (.pp)
    # round-trip and intentionally carries the live source_session_id.  The
    # portable form below is for sharing a single playbook as a standalone
    # file: it keeps everything needed to *replay* the playbook (connection
    # config, variables, frames) but drops runtime-only state — the playbook
    # id, the bound source_session_id, and the runs history.

    PORTABLE_FORMAT  = "protopoke-playbook"
    PORTABLE_VERSION = 1

    def to_portable_dict(self) -> dict:
        """Serialise for standalone export (the Forge Import/Export buttons).

        Includes the connection config (host/port/tls/transport/
        response_window), the variable store, and all frames — everything an
        operator needs to replay this playbook against the target later or on
        another machine.

        Deliberately omits runtime-only state: the playbook ``id`` (a fresh
        one is generated on import so re-importing never collides with an
        existing playbook), ``source_session_id`` (the bound session will not
        exist when the file is imported), and the ``runs`` history (past
        traffic logs are not needed to replay).  On import the playbook
        reconnects fresh to ``host``/``port``.
        """
        return {
            "format":          self.PORTABLE_FORMAT,
            "version":         self.PORTABLE_VERSION,
            "label":           self.label,
            "host":            self.host,
            "port":            self.port,
            "tls":             self.tls,
            "transport":       self.transport,
            "response_window": self.response_window,
            "variables":       dict(self.variables),
            "frames": [
                {"label": f.label, "raw_hex": f.raw_hex, "direction": f.direction}
                for f in self.frames
            ],
        }

    @classmethod
    def from_portable_dict(cls, d: dict) -> "Playbook":
        """Reconstruct a playbook from a standalone export dict.

        Generates a fresh ``id`` and leaves ``source_session_id`` unset, so an
        imported playbook always opens a new connection to its saved
        host/port rather than binding to a session that no longer exists.

        Accepts the legacy export format that contained only ``label`` and
        ``frames``; any missing connection fields fall back to the same
        defaults as a hand-created playbook.
        """
        pb = cls.create(
            label=d.get("label", "Imported Playbook"),
            host=d.get("host", "") or "",
            port=int(d.get("port") or 0),
            tls=bool(d.get("tls", False)),
            transport=d.get("transport") or "tcp",
            response_window=float(d.get("response_window") or 1.0),
        )
        variables = d.get("variables")
        if isinstance(variables, dict):
            pb.variables = {str(k): str(v) for k, v in variables.items()}
        frames = d.get("frames", [])
        if not isinstance(frames, list):
            raise ValueError("'frames' must be a list")
        for fd in frames:
            pb.frames.append(PlaybookFrame.create(
                label=fd.get("label", ""),
                raw_hex=fd.get("raw_hex", ""),
                direction=fd.get("direction", "client_to_server"),
            ))
        return pb
