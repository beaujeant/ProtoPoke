"""Dataclasses for cross-session findings and notes."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from ..models import Direction, new_id


# ---------------------------------------------------------------------------
# Allowed enum-ish string values (validated at construction / load time)
# ---------------------------------------------------------------------------

FINDING_STATUSES   = ("hypothesis", "confirmed", "ruled_out", "needs_review")
FINDING_CONFIDENCE = ("low", "medium", "high")


def _coerce_direction(value: Any) -> Optional[Direction]:
    if value is None or value == "":
        return None
    if isinstance(value, Direction):
        return value
    return Direction(value)


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    A structured claim about the protocol under investigation.

    Findings capture what an AI (or a human operator) has reasoned about
    while reverse-engineering a protocol.  They are intentionally
    decoupled from the active :class:`ProtocolDefinition` so they can
    target byte offsets in messages that do not yet have a formal name.

    Attributes:
        id:           Stable UUID — used by the MCP layer to update or
                      remove the finding without ambiguity.
        created_at:   Unix timestamp when the finding was first created.
        updated_at:   Unix timestamp of the last mutation.
        author:       Free-form string; the MCP layer always sets ``"ai"``
                      when creating findings and the TUI sets ``"user"``.
        locked:       True once a user has mutated the finding via the
                      UI.  When True, the MCP layer refuses to update or
                      remove it regardless of the author.

        protocol_name:  Optional — scope to one protocol when multiple
                        are juggled in the same project.
        message_name:   Optional — message type the finding belongs to
                        (may not yet exist in the active definition).
        field_name:     Optional — field within the message.
        byte_offset:    Optional — raw offset within the frame when no
                        field has been formalised yet.
        byte_length:    Optional — span at ``byte_offset``.
        direction:      Optional — restrict to one traffic direction.
        forwarder_id:   Optional — pin to a specific forwarder.  Stored
                        as a UUID so renaming the forwarder keeps the
                        link.  The current display name is resolved by
                        the MCP / UI layer at response time.

        title:        One-line summary shown in lists.
        description:  Markdown body — supporting reasoning, references,
                      whatever helps the next session pick up.

        status:       hypothesis | confirmed | ruled_out | needs_review.
        confidence:   low | medium | high.

        evidence_frame_ids:         Frame IDs that support the finding.
        counter_evidence_frame_ids: Frame IDs that would refute it if
                                    the hypothesis were true.
        tags:         Free-form tags for filtering.
    """

    id:          str
    created_at:  float
    updated_at:  float
    author:      str
    locked:      bool

    # Scope
    protocol_name: Optional[str]       = None
    message_name:  Optional[str]       = None
    field_name:    Optional[str]       = None
    byte_offset:   Optional[int]       = None
    byte_length:   Optional[int]       = None
    direction:     Optional[Direction] = None
    forwarder_id:  Optional[str]       = None

    # Claim
    title:       str = ""
    description: str = ""

    # Lifecycle
    status:     str = "hypothesis"
    confidence: str = "medium"

    # Evidence
    evidence_frame_ids:         list[str] = field(default_factory=list)
    counter_evidence_frame_ids: list[str] = field(default_factory=list)
    tags:                       list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.status not in FINDING_STATUSES:
            raise ValueError(
                f"Invalid finding status {self.status!r}; "
                f"expected one of {FINDING_STATUSES}"
            )
        if self.confidence not in FINDING_CONFIDENCE:
            raise ValueError(
                f"Invalid finding confidence {self.confidence!r}; "
                f"expected one of {FINDING_CONFIDENCE}"
            )
        if isinstance(self.direction, str):
            self.direction = _coerce_direction(self.direction)

    @classmethod
    def create(
        cls,
        title:        str,
        author:       str = "ai",
        description:  str = "",
        status:       str = "hypothesis",
        confidence:   str = "medium",
        protocol_name: Optional[str]       = None,
        message_name:  Optional[str]       = None,
        field_name:    Optional[str]       = None,
        byte_offset:   Optional[int]       = None,
        byte_length:   Optional[int]       = None,
        direction:     Optional[Any]       = None,
        forwarder_id:  Optional[str]       = None,
        evidence_frame_ids:         Optional[list[str]] = None,
        counter_evidence_frame_ids: Optional[list[str]] = None,
        tags:                       Optional[list[str]] = None,
        locked:       bool = False,
    ) -> "Finding":
        """Factory — sets id, created_at, and updated_at automatically."""
        now = time.time()
        return cls(
            id=new_id(),
            created_at=now,
            updated_at=now,
            author=author,
            locked=locked,
            protocol_name=protocol_name,
            message_name=message_name,
            field_name=field_name,
            byte_offset=byte_offset,
            byte_length=byte_length,
            direction=_coerce_direction(direction),
            forwarder_id=forwarder_id,
            title=title,
            description=description,
            status=status,
            confidence=confidence,
            evidence_frame_ids=list(evidence_frame_ids or []),
            counter_evidence_frame_ids=list(counter_evidence_frame_ids or []),
            tags=list(tags or []),
        )

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "created_at":  self.created_at,
            "updated_at":  self.updated_at,
            "author":      self.author,
            "locked":      self.locked,
            "protocol_name": self.protocol_name,
            "message_name":  self.message_name,
            "field_name":    self.field_name,
            "byte_offset":   self.byte_offset,
            "byte_length":   self.byte_length,
            "direction":     self.direction.value if self.direction else None,
            "forwarder_id":  self.forwarder_id,
            "title":         self.title,
            "description":   self.description,
            "status":        self.status,
            "confidence":    self.confidence,
            "evidence_frame_ids":         list(self.evidence_frame_ids),
            "counter_evidence_frame_ids": list(self.counter_evidence_frame_ids),
            "tags":                       list(self.tags),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            id=d["id"],
            created_at=d.get("created_at", 0.0),
            updated_at=d.get("updated_at", d.get("created_at", 0.0)),
            author=d.get("author", "user"),
            locked=bool(d.get("locked", False)),
            protocol_name=d.get("protocol_name"),
            message_name=d.get("message_name"),
            field_name=d.get("field_name"),
            byte_offset=d.get("byte_offset"),
            byte_length=d.get("byte_length"),
            direction=_coerce_direction(d.get("direction")),
            forwarder_id=d.get("forwarder_id"),
            title=d.get("title", ""),
            description=d.get("description", ""),
            status=d.get("status", "hypothesis"),
            confidence=d.get("confidence", "medium"),
            evidence_frame_ids=list(d.get("evidence_frame_ids", [])),
            counter_evidence_frame_ids=list(d.get("counter_evidence_frame_ids", [])),
            tags=list(d.get("tags", [])),
        )


# ---------------------------------------------------------------------------
# Note
# ---------------------------------------------------------------------------

@dataclass
class Note:
    """
    A free-form markdown note attached to the project.

    Use for context that does not fit the structured :class:`Finding`
    shape: open questions, design hypotheses about the whole protocol,
    notes on test setup, etc.

    Attributes:
        id, created_at, updated_at, author, locked: same semantics as
            :class:`Finding`.
        title:   One-line label shown in the notes list.
        body_md: Markdown body.
        tags:    Free-form tags for filtering.
    """

    id:         str
    created_at: float
    updated_at: float
    author:     str
    locked:     bool
    title:      str = ""
    body_md:    str = ""
    tags:       list[str] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        title:   str,
        body_md: str = "",
        author:  str = "ai",
        tags:    Optional[list[str]] = None,
        locked:  bool = False,
    ) -> "Note":
        now = time.time()
        return cls(
            id=new_id(),
            created_at=now,
            updated_at=now,
            author=author,
            locked=locked,
            title=title,
            body_md=body_md,
            tags=list(tags or []),
        )

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "author":     self.author,
            "locked":     self.locked,
            "title":      self.title,
            "body_md":    self.body_md,
            "tags":       list(self.tags),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Note":
        return cls(
            id=d["id"],
            created_at=d.get("created_at", 0.0),
            updated_at=d.get("updated_at", d.get("created_at", 0.0)),
            author=d.get("author", "user"),
            locked=bool(d.get("locked", False)),
            title=d.get("title", ""),
            body_md=d.get("body_md", ""),
            tags=list(d.get("tags", [])),
        )
