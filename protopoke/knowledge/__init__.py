"""
Knowledge base for cross-session AI memory.

This module stores reverse-engineering findings and free-form notes that
persist across AI sessions via the ``.pp`` project file.  The aim is to
let an AI client (over MCP) record hypotheses, ruled-out theories, and
scratchpad reasoning so the next session does not start from scratch.

Public surface:

    :class:`Finding` — a structured claim about the protocol (e.g.
    "bytes 4-5 of LoginRequest look like a CRC16"), with confidence,
    status, scope (protocol/message/field/offset/forwarder), and
    evidence frame IDs.

    :class:`Note` — a free-form markdown entry for anything that does
    not fit the structured Finding shape.

    :class:`KnowledgeBase` — in-memory container with CRUD + search,
    serialised to JSON by the project manager.

Attribution:
    Both Finding and Note carry ``author`` (creator, immutable) and
    ``locked`` (True once a user has mutated the entry through the UI).
    The MCP layer uses these to enforce that the AI may only edit/remove
    entries it authored AND that have not been locked by the user.
"""

from .models import Finding, Note
from .store import KnowledgeBase

__all__ = ["Finding", "Note", "KnowledgeBase"]
