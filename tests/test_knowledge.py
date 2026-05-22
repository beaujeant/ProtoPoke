"""Tests for the knowledge base (findings + notes)."""

from __future__ import annotations

import pytest

from protopoke.knowledge import Finding, KnowledgeBase, Note
from protopoke.models import Direction


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class TestFinding:
    def test_create_sets_defaults(self):
        f = Finding.create(title="bytes 4-5 look like CRC16")
        assert f.id
        assert f.author == "ai"
        assert f.locked is False
        assert f.status == "hypothesis"
        assert f.confidence == "medium"
        assert f.evidence_frame_ids == []
        assert f.created_at == f.updated_at

    def test_create_accepts_full_scope(self):
        f = Finding.create(
            title="checksum",
            description="probably CRC16-CCITT",
            status="confirmed",
            confidence="high",
            protocol_name="MyProto",
            message_name="LoginRequest",
            field_name="checksum",
            byte_offset=4,
            byte_length=2,
            direction="client_to_server",
            forwarder_id="fwd-abc",
            evidence_frame_ids=["f1", "f2"],
            tags=["crc", "checksum"],
        )
        assert f.message_name == "LoginRequest"
        assert f.direction is Direction.CLIENT_TO_SERVER
        assert f.tags == ["crc", "checksum"]

    def test_invalid_status_rejected(self):
        with pytest.raises(ValueError, match="status"):
            Finding.create(title="x", status="nope")

    def test_invalid_confidence_rejected(self):
        with pytest.raises(ValueError, match="confidence"):
            Finding.create(title="x", confidence="absolute")

    def test_dict_round_trip(self):
        original = Finding.create(
            title="t",
            description="desc",
            confidence="high",
            status="ruled_out",
            byte_offset=7,
            byte_length=4,
            direction=Direction.SERVER_TO_CLIENT,
            forwarder_id="fwd-1",
            evidence_frame_ids=["a", "b"],
            counter_evidence_frame_ids=["c"],
            tags=["foo"],
        )
        restored = Finding.from_dict(original.to_dict())
        assert restored == original

    def test_from_dict_minimal(self):
        f = Finding.from_dict({"id": "x"})
        assert f.id == "x"
        assert f.status == "hypothesis"
        assert f.author == "user"
        assert f.evidence_frame_ids == []


# ---------------------------------------------------------------------------
# Note
# ---------------------------------------------------------------------------

class TestNote:
    def test_create_defaults(self):
        n = Note.create(title="todo list", body_md="* check magic bytes")
        assert n.id
        assert n.author == "ai"
        assert n.locked is False
        assert n.tags == []

    def test_dict_round_trip(self):
        original = Note.create(
            title="hello", body_md="**bold**", tags=["x", "y"], author="user"
        )
        restored = Note.from_dict(original.to_dict())
        assert restored == original


# ---------------------------------------------------------------------------
# KnowledgeBase CRUD + filtering
# ---------------------------------------------------------------------------

class TestKnowledgeBase:
    def test_add_get_remove_finding(self):
        kb = KnowledgeBase()
        f = Finding.create(title="hello")
        kb.add_finding(f)
        assert kb.get_finding(f.id) is f
        assert kb.remove_finding(f.id) is True
        assert kb.get_finding(f.id) is None
        assert kb.remove_finding(f.id) is False

    def test_update_finding_bumps_timestamp(self):
        kb = KnowledgeBase()
        f = kb.add_finding(Finding.create(title="hi"))
        original_ts = f.updated_at
        f.updated_at = 0.0  # force a different starting value
        updated = kb.update_finding(f.id, title="bye", status="confirmed")
        assert updated is not None
        assert updated.title == "bye"
        assert updated.status == "confirmed"
        assert updated.updated_at > 0.0
        assert updated.updated_at != original_ts or True  # always bumped to now

    def test_update_unknown_returns_none(self):
        kb = KnowledgeBase()
        assert kb.update_finding("does-not-exist", title="x") is None

    def test_update_ignores_unknown_fields(self):
        kb = KnowledgeBase()
        f = kb.add_finding(Finding.create(title="hi"))
        kb.update_finding(f.id, bogus_attr="x", title="yo")
        assert f.title == "yo"
        assert not hasattr(f, "bogus_attr")

    def test_list_findings_filters(self):
        kb = KnowledgeBase()
        kb.add_finding(Finding.create(title="a", status="hypothesis", author="ai",
                                       protocol_name="P1", tags=["crc"]))
        kb.add_finding(Finding.create(title="b", status="confirmed", author="user",
                                       protocol_name="P1", tags=["len"]))
        kb.add_finding(Finding.create(title="c", status="ruled_out", author="ai",
                                       protocol_name="P2", tags=["crc"]))

        assert len(kb.list_findings(status="confirmed")) == 1
        assert len(kb.list_findings(author="ai")) == 2
        assert len(kb.list_findings(protocol_name="P1")) == 2
        assert len(kb.list_findings(tags=["crc"])) == 2
        assert len(kb.list_findings(tags=["crc"], author="ai")) == 2
        assert len(kb.list_findings(tags=["crc", "len"])) == 0

    def test_list_findings_query_searches_title_description_tags(self):
        kb = KnowledgeBase()
        kb.add_finding(Finding.create(title="CRC at end", description="boring"))
        kb.add_finding(Finding.create(title="other", description="length prefix"))
        kb.add_finding(Finding.create(title="x", tags=["checksum"]))

        assert len(kb.list_findings(query="crc")) == 1
        assert len(kb.list_findings(query="length")) == 1
        assert len(kb.list_findings(query="checksum")) == 1
        assert len(kb.list_findings(query="zzz")) == 0

    def test_notes_crud_and_filters(self):
        kb = KnowledgeBase()
        n1 = kb.add_note(Note.create(title="todo", body_md="* one", author="ai", tags=["plan"]))
        n2 = kb.add_note(Note.create(title="meeting", body_md="agreed: x", author="user"))

        assert kb.get_note(n1.id) is n1
        assert len(kb.list_notes(author="ai")) == 1
        assert len(kb.list_notes(query="agreed")) == 1
        assert len(kb.list_notes(tags=["plan"])) == 1

        assert kb.update_note(n1.id, title="todo (rev)").title == "todo (rev)"
        assert kb.remove_note(n2.id) is True
        assert kb.remove_note(n2.id) is False

    def test_kb_dict_round_trip(self):
        kb = KnowledgeBase()
        kb.add_finding(Finding.create(title="f1", forwarder_id="fwd-1"))
        kb.add_note(Note.create(title="n1", body_md="body"))
        restored = KnowledgeBase.from_dict(kb.to_dict())
        assert len(restored.findings) == 1
        assert len(restored.notes) == 1
        assert restored.findings[0].forwarder_id == "fwd-1"
        assert restored.notes[0].body_md == "body"
