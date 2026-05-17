"""KnowledgeBase — in-memory store for findings and notes."""

from __future__ import annotations

import time
from typing import Any, Iterable, Optional

from ..models import Direction
from .models import Finding, Note


class KnowledgeBase:
    """
    Container for :class:`Finding` and :class:`Note` instances.

    The store is plain in-memory.  Persistence is handled by
    :class:`~protopoke.project.manager.ProjectManager`, which serialises
    each list to its own JSON member in the ``.pp`` archive.

    The store itself does not enforce author-based restrictions — that
    policy lives in the MCP layer so the UI and Python callers can edit
    or delete any entry freely.
    """

    def __init__(
        self,
        findings: Optional[Iterable[Finding]] = None,
        notes:    Optional[Iterable[Note]]    = None,
    ) -> None:
        self.findings: list[Finding] = list(findings or [])
        self.notes:    list[Note]    = list(notes    or [])

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def add_finding(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        for f in self.findings:
            if f.id == finding_id:
                return f
        return None

    def remove_finding(self, finding_id: str) -> bool:
        for i, f in enumerate(self.findings):
            if f.id == finding_id:
                del self.findings[i]
                return True
        return False

    def update_finding(self, finding_id: str, **changes: Any) -> Optional[Finding]:
        """Apply ``changes`` to the named finding and bump ``updated_at``.

        Unknown keys are ignored.  Returns the updated finding, or None
        if ``finding_id`` is not in the store.
        """
        finding = self.get_finding(finding_id)
        if finding is None:
            return None
        for key, value in changes.items():
            if not hasattr(finding, key):
                continue
            if key == "direction" and value is not None and not isinstance(value, Direction):
                value = Direction(value)
            if key in ("evidence_frame_ids", "counter_evidence_frame_ids", "tags") and value is not None:
                value = list(value)
            setattr(finding, key, value)
        finding.updated_at = time.time()
        return finding

    def list_findings(
        self,
        query:         Optional[str]       = None,
        status:        Optional[str]       = None,
        author:        Optional[str]       = None,
        protocol_name: Optional[str]       = None,
        message_name:  Optional[str]       = None,
        field_name:    Optional[str]       = None,
        forwarder_id:  Optional[str]       = None,
        tags:          Optional[Iterable[str]] = None,
    ) -> list[Finding]:
        """Return findings matching every filter that is set.

        ``query`` is a case-insensitive substring match against ``title``,
        ``description``, and ``tags``.  ``tags`` (the kwarg) is an AND
        match — all named tags must be present.
        """
        results = self.findings
        if status is not None:
            results = [f for f in results if f.status == status]
        if author is not None:
            results = [f for f in results if f.author == author]
        if protocol_name is not None:
            results = [f for f in results if f.protocol_name == protocol_name]
        if message_name is not None:
            results = [f for f in results if f.message_name == message_name]
        if field_name is not None:
            results = [f for f in results if f.field_name == field_name]
        if forwarder_id is not None:
            results = [f for f in results if f.forwarder_id == forwarder_id]
        if tags:
            required = set(tags)
            results = [f for f in results if required.issubset(set(f.tags))]
        if query:
            q = query.lower()
            results = [
                f for f in results
                if q in f.title.lower()
                or q in f.description.lower()
                or any(q in t.lower() for t in f.tags)
            ]
        return list(results)

    # ------------------------------------------------------------------
    # Notes
    # ------------------------------------------------------------------

    def add_note(self, note: Note) -> Note:
        self.notes.append(note)
        return note

    def get_note(self, note_id: str) -> Optional[Note]:
        for n in self.notes:
            if n.id == note_id:
                return n
        return None

    def remove_note(self, note_id: str) -> bool:
        for i, n in enumerate(self.notes):
            if n.id == note_id:
                del self.notes[i]
                return True
        return False

    def update_note(self, note_id: str, **changes: Any) -> Optional[Note]:
        note = self.get_note(note_id)
        if note is None:
            return None
        for key, value in changes.items():
            if not hasattr(note, key):
                continue
            if key == "tags" and value is not None:
                value = list(value)
            setattr(note, key, value)
        note.updated_at = time.time()
        return note

    def list_notes(
        self,
        query:  Optional[str]           = None,
        author: Optional[str]           = None,
        tags:   Optional[Iterable[str]] = None,
    ) -> list[Note]:
        """Same filter shape as :meth:`list_findings` (subset)."""
        results = self.notes
        if author is not None:
            results = [n for n in results if n.author == author]
        if tags:
            required = set(tags)
            results = [n for n in results if required.issubset(set(n.tags))]
        if query:
            q = query.lower()
            results = [
                n for n in results
                if q in n.title.lower()
                or q in n.body_md.lower()
                or any(q in t.lower() for t in n.tags)
            ]
        return list(results)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "notes":    [n.to_dict() for n in self.notes],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KnowledgeBase":
        return cls(
            findings=[Finding.from_dict(fd) for fd in d.get("findings", [])],
            notes=[Note.from_dict(nd) for nd in d.get("notes", [])],
        )
