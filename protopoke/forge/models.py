"""
Data models for the Repeater feature.

These are separate from the core models (protopoke.models) because they are
UI-level constructs, not transport-level ones.

ForgeRecord
----------
An immutable record of one send+receive cycle in the Repeater.

ForgeRequest
---------------
A named "tab" in the Repeater, holding the current editable bytes, the
target destination, and the history of all sends made from this tab.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ForgeRecord:
    """
    A single send+response pair recorded in the Repeater history.

    Attributes:
        id:               Unique ID (UUID4).
        timestamp:        When the send was initiated (Unix seconds).
        sent_bytes:       Bytes that were sent to the target.
        received_bytes:   Raw bytes received back (concatenated; empty on error).
        response_packets: Individual network chunks received from the server,
                          in order.  Each entry is one read() chunk — finer
                          grained than received_bytes (which is their join).
        host:             Target host.
        port:             Target port.
        tls:              Whether TLS was used for the connection.
        success:          ``False`` if a connection/timeout error occurred.
        error:            Error message when ``success`` is ``False``.
    """

    id:               str
    timestamp:        float
    sent_bytes:       bytes
    received_bytes:   bytes
    host:             str
    port:             int
    tls:              bool        = False
    success:          bool        = True
    error:            Optional[str]  = None
    response_packets: list[bytes] = field(default_factory=list)
    session_id:       Optional[str]  = None

    @classmethod
    def create(
        cls,
        sent_bytes:       bytes,
        received_bytes:   bytes,
        host:             str,
        port:             int,
        tls:              bool        = False,
        success:          bool        = True,
        error:            Optional[str]  = None,
        response_packets: list[bytes] = None,
        session_id:       Optional[str]  = None,
    ) -> "ForgeRecord":
        return cls(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            sent_bytes=sent_bytes,
            received_bytes=received_bytes,
            host=host,
            port=port,
            tls=tls,
            success=success,
            error=error,
            response_packets=response_packets or [],
            session_id=session_id,
        )

    def to_dict(self) -> dict:
        return {
            "id":               self.id,
            "timestamp":        self.timestamp,
            "sent_bytes":       self.sent_bytes.hex(),
            "received_bytes":   self.received_bytes.hex(),
            "response_packets": [p.hex() for p in self.response_packets],
            "host":             self.host,
            "port":             self.port,
            "tls":              self.tls,
            "success":          self.success,
            "error":            self.error,
            "session_id":       self.session_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ForgeRecord":
        return cls(
            id=d["id"],
            timestamp=d["timestamp"],
            sent_bytes=bytes.fromhex(d["sent_bytes"]),
            received_bytes=bytes.fromhex(d["received_bytes"]),
            response_packets=[bytes.fromhex(p) for p in d.get("response_packets", [])],
            host=d["host"],
            port=d["port"],
            tls=d.get("tls", False),
            success=d.get("success", True),
            error=d.get("error"),
            session_id=d.get("session_id"),
        )


@dataclass
class ForgeRequest:
    """
    One named "tab" in the Repeater.

    Holds the current editable bytes (``current_bytes``), the target
    destination (``host``, ``port``, ``tls``), and the full send history.

    Attributes:
        id:            Unique ID (UUID4).
        label:         User-visible name shown in the tab list.
        host:          Target host.
        port:          Target port.
        tls:           Whether to use TLS.
        current_bytes: Bytes currently in the editor (editable).
        history:       All ``ForgeRecord`` instances for this tab, newest last.
        source_session_id: Session ID this request was sent from (optional).
    """

    id:                  str
    label:               str
    host:                str
    port:                int
    tls:                 bool              = False
    current_bytes:       bytes             = b""
    history:             list[ForgeRecord]  = field(default_factory=list)
    source_session_id:   Optional[str]     = None
    # Seconds to wait for server packets after a send (configurable per-tab).
    response_window:     float             = 1.0
    # "to_server" (inject/send toward the server) or "to_client" (inject toward
    # the client side of an existing proxy session).
    direction:           str               = "to_server"
    # ID of the persistent TCP session created for custom host:port sends.
    # Not persisted to disk — connections don't survive restarts.
    repeater_session_id: Optional[str]     = field(default=None, compare=False)

    @classmethod
    def create(
        cls,
        host:              str,
        port:              int,
        label:             str  = "",
        tls:               bool  = False,
        current_bytes:     bytes = b"",
        source_session_id: Optional[str] = None,
        direction:         str  = "to_server",
    ) -> "ForgeRequest":
        return cls(
            id=str(uuid.uuid4()),
            label=label,
            host=host,
            port=port,
            tls=tls,
            current_bytes=current_bytes,
            source_session_id=source_session_id,
            direction=direction,
        )

    def add_record(self, record: ForgeRecord) -> None:
        """Append a send record to the history."""
        self.history.append(record)

    def to_dict(self) -> dict:
        return {
            "id":                self.id,
            "label":             self.label,
            "host":              self.host,
            "port":              self.port,
            "tls":               self.tls,
            "current_bytes":     self.current_bytes.hex(),
            "history":           [r.to_dict() for r in self.history],
            "source_session_id": self.source_session_id,
            "response_window":   self.response_window,
            "direction":         self.direction,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ForgeRequest":
        return cls(
            id=d["id"],
            label=d["label"],
            host=d["host"],
            port=d["port"],
            tls=d.get("tls", False),
            current_bytes=bytes.fromhex(d.get("current_bytes", "")),
            history=[ForgeRecord.from_dict(r) for r in d.get("history", [])],
            source_session_id=d.get("source_session_id"),
            response_window=d.get("response_window", 1.0),
            direction=d.get("direction", "to_server"),
        )
