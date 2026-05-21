"""
Tests for the MCP findings + notes tools (``protopoke/mcp/server.py``).

Covers the CRUD surface plus the author / locked enforcement that
restricts the AI to mutating only the entries it authored AND that the
user has not locked from the TUI.
"""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# TLS / cryptography stubs (same pattern as test_mcp_analysis_tools.py)
# ---------------------------------------------------------------------------
def _make_tls_stubs() -> None:
    for mod_name in list(sys.modules):
        if mod_name.startswith("cryptography") or mod_name.startswith("protopoke.tls"):
            del sys.modules[mod_name]
    crypto_stub = ModuleType("cryptography")
    sys.modules.setdefault("cryptography", crypto_stub)
    for sub in [
        "x509", "hazmat", "hazmat.primitives", "hazmat.primitives.asymmetric",
        "hazmat.primitives.asymmetric.rsa", "hazmat.primitives.hashes",
        "hazmat.primitives.serialization", "hazmat.backends",
        "hazmat.backends.default", "hazmat.primitives.asymmetric.padding",
    ]:
        sys.modules.setdefault(f"cryptography.{sub}", ModuleType(f"cryptography.{sub}"))
    tls_stub = ModuleType("protopoke.tls")
    ca_stub = ModuleType("protopoke.tls.ca")
    ca_stub.CertificateAuthority = MagicMock()
    ca_stub.DEFAULT_CA_CERT_PATH = "/tmp/fake-ca.crt"
    ca_stub.DEFAULT_CA_KEY_PATH = "/tmp/fake-ca.key"
    handler_stub = ModuleType("protopoke.tls.handler")
    handler_stub.TLSHandler = MagicMock()
    sys.modules["protopoke.tls"] = tls_stub
    sys.modules["protopoke.tls.ca"] = ca_stub
    sys.modules["protopoke.tls.handler"] = handler_stub


_make_tls_stubs()

from protopoke.api import ProtoPokeAPI  # noqa: E402
from protopoke.config import ForwarderConfig  # noqa: E402
from protopoke.knowledge import Finding, Note  # noqa: E402
from protopoke.mcp import build_mcp_server  # noqa: E402


@pytest.fixture
def api():
    fwd = ForwarderConfig(name="Default", listen_port=19999,
                          upstream_host="127.0.0.1", upstream_port=19998)
    return ProtoPokeAPI([fwd])


@pytest.fixture
def mcp_server(api):
    return build_mcp_server(api)


def tool(srv, name):
    t = srv._tool_manager.get_tool(name)
    assert t is not None, f"missing tool {name}"
    return t.fn


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

class TestFindingsCRUD:
    def test_add_then_list(self, mcp_server, api):
        add = tool(mcp_server, "add_finding")
        out = add(title="CRC at end", description="probably CRC16",
                  status="hypothesis", confidence="medium",
                  message_name="LoginRequest", tags=["crc"])
        assert out["ok"] is True
        finding_id = out["finding"]["id"]
        assert out["finding"]["author"] == "ai"
        assert out["finding"]["locked"] is False

        listed = tool(mcp_server, "list_findings")()
        assert len(listed) == 1
        assert listed[0]["id"] == finding_id

    def test_add_invalid_status(self, mcp_server):
        add = tool(mcp_server, "add_finding")
        out = add(title="x", status="bogus")
        assert out["ok"] is False
        assert "status" in out["error"]

    def test_get_finding(self, mcp_server):
        add = tool(mcp_server, "add_finding")
        fid = add(title="hi")["finding"]["id"]
        got = tool(mcp_server, "get_finding")(fid)
        assert got["id"] == fid

    def test_get_missing(self, mcp_server):
        out = tool(mcp_server, "get_finding")("nope")
        assert "error" in out

    def test_update_ai_owned(self, mcp_server):
        add = tool(mcp_server, "add_finding")
        fid = add(title="hi", status="hypothesis")["finding"]["id"]
        out = tool(mcp_server, "update_finding")(fid, status="confirmed",
                                                  confidence="high")
        assert out["ok"] is True
        assert out["finding"]["status"] == "confirmed"
        assert out["finding"]["confidence"] == "high"

    def test_update_validates_enums(self, mcp_server):
        add = tool(mcp_server, "add_finding")
        fid = add(title="hi")["finding"]["id"]
        out = tool(mcp_server, "update_finding")(fid, status="weird")
        assert out["ok"] is False
        assert "status" in out["error"]

    def test_remove_ai_owned(self, mcp_server):
        add = tool(mcp_server, "add_finding")
        fid = add(title="hi")["finding"]["id"]
        out = tool(mcp_server, "remove_finding")(fid)
        assert out["ok"] is True
        assert tool(mcp_server, "get_finding")(fid).get("error")


class TestFindingsAuthorEnforcement:
    """AI may only mutate entries with author=='ai' AND locked=False."""

    def test_cannot_update_user_authored(self, mcp_server, api):
        # The user (via the TUI) adds a finding directly to the KB.
        f = api.knowledge.add_finding(
            Finding.create(title="user finding", author="user")
        )
        out = tool(mcp_server, "update_finding")(f.id, title="new")
        assert out["ok"] is False
        assert "user" in out["error"]

    def test_cannot_remove_user_authored(self, mcp_server, api):
        f = api.knowledge.add_finding(
            Finding.create(title="user finding", author="user")
        )
        out = tool(mcp_server, "remove_finding")(f.id)
        assert out["ok"] is False
        assert api.knowledge.get_finding(f.id) is f  # still there

    def test_cannot_update_locked_ai_entry(self, mcp_server, api):
        f = api.knowledge.add_finding(
            Finding.create(title="ai entry", author="ai", locked=True)
        )
        out = tool(mcp_server, "update_finding")(f.id, title="new")
        assert out["ok"] is False
        assert "locked" in out["error"]

    def test_cannot_remove_locked_ai_entry(self, mcp_server, api):
        f = api.knowledge.add_finding(
            Finding.create(title="ai entry", author="ai", locked=True)
        )
        out = tool(mcp_server, "remove_finding")(f.id)
        assert out["ok"] is False
        assert api.knowledge.get_finding(f.id) is f


class TestFindingsFilters:
    def test_list_filters_and_query(self, mcp_server, api):
        add = tool(mcp_server, "add_finding")
        add(title="CRC field", description="x", protocol_name="P1",
            tags=["crc"])
        add(title="length", description="length prefix", protocol_name="P1",
            tags=["len"])
        add(title="other", description="z", protocol_name="P2")

        assert len(tool(mcp_server, "list_findings")(protocol_name="P1")) == 2
        assert len(tool(mcp_server, "list_findings")(query="length")) == 1
        assert len(tool(mcp_server, "list_findings")(tags=["crc"])) == 1
        assert len(tool(mcp_server, "list_findings")(protocol_name="P2",
                                                     query="other")) == 1

    def test_forwarder_name_resolved_in_response(self, mcp_server, api):
        fwd = api.forwarders[0]
        api.knowledge.add_finding(
            Finding.create(title="x", forwarder_id=fwd.id, author="ai"),
        )
        listed = tool(mcp_server, "list_findings")()
        assert listed[0]["forwarder_id"] == fwd.id
        assert listed[0]["forwarder_name"] == fwd.name

    def test_forwarder_name_none_when_forwarder_gone(self, mcp_server, api):
        api.knowledge.add_finding(
            Finding.create(title="x", forwarder_id="never-existed", author="ai"),
        )
        listed = tool(mcp_server, "list_findings")()
        assert listed[0]["forwarder_id"] == "never-existed"
        assert listed[0]["forwarder_name"] is None


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------

class TestNotesCRUD:
    def test_add_get_list_update_remove(self, mcp_server, api):
        add = tool(mcp_server, "add_note")
        out = add(title="todo", body_md="* one", tags=["plan"])
        nid = out["note"]["id"]
        assert out["note"]["author"] == "ai"

        got = tool(mcp_server, "get_note")(nid)
        assert got["title"] == "todo"

        listed = tool(mcp_server, "list_notes")(tags=["plan"])
        assert len(listed) == 1

        upd = tool(mcp_server, "update_note")(nid, body_md="* one\n* two")
        assert upd["ok"] is True
        assert "two" in upd["note"]["body_md"]

        rm = tool(mcp_server, "remove_note")(nid)
        assert rm["ok"] is True

    def test_user_authored_note_refused(self, mcp_server, api):
        n = api.knowledge.add_note(Note.create(title="x", author="user"))
        out = tool(mcp_server, "update_note")(n.id, title="y")
        assert out["ok"] is False
        out2 = tool(mcp_server, "remove_note")(n.id)
        assert out2["ok"] is False

    def test_locked_note_refused(self, mcp_server, api):
        n = api.knowledge.add_note(
            Note.create(title="x", author="ai", locked=True),
        )
        out = tool(mcp_server, "update_note")(n.id, title="y")
        assert out["ok"] is False
        assert "locked" in out["error"]


# ---------------------------------------------------------------------------
# List-view compaction (token cost) — full record stays available via get_*
# ---------------------------------------------------------------------------

class TestListCompaction:
    def test_findings_long_description_previewed_full_via_get(self, mcp_server):
        add = tool(mcp_server, "add_finding")
        long_desc = "word " * 200  # ~1000 chars
        fid = add(title="t", description=long_desc,
                  status="hypothesis", confidence="low")["finding"]["id"]
        row = tool(mcp_server, "list_findings")()[0]
        assert row["description_truncated"] is True
        assert len(row["description"]) < len(long_desc)
        # full text recoverable, and not flagged as truncated
        full = tool(mcp_server, "get_finding")(fid)
        assert full["description"] == long_desc
        assert "description_truncated" not in full

    def test_findings_short_description_kept_intact(self, mcp_server):
        add = tool(mcp_server, "add_finding")
        add(title="t", description="short claim", status="hypothesis")
        row = tool(mcp_server, "list_findings")()[0]
        assert row["description"] == "short claim"
        assert "description_truncated" not in row

    def test_findings_evidence_ids_become_count_full_via_get(self, mcp_server):
        add = tool(mcp_server, "add_finding")
        out = add(title="t", evidence_frame_ids=["a", "b", "c"])
        fid = out["finding"]["id"]
        row = tool(mcp_server, "list_findings")()[0]
        assert row["evidence_frame_count"] == 3
        assert "evidence_frame_ids" not in row
        full = tool(mcp_server, "get_finding")(fid)
        assert full["evidence_frame_ids"] == ["a", "b", "c"]

    def test_findings_null_scope_fields_omitted_but_forwarder_kept(self, mcp_server):
        add = tool(mcp_server, "add_finding")
        add(title="t", message_name="LoginRequest")  # other scope fields null
        row = tool(mcp_server, "list_findings")()[0]
        assert row["message_name"] == "LoginRequest"
        assert "protocol_name" not in row
        assert "field_name" not in row
        # forwarder_id / forwarder_name are always present (callers rely on it)
        assert "forwarder_id" in row
        assert "forwarder_name" in row

    def test_notes_long_body_previewed_full_via_get(self, mcp_server):
        add = tool(mcp_server, "add_note")
        long_body = "a line of notes\n" * 60  # ~960 chars
        nid = add(title="n", body_md=long_body)["note"]["id"]
        row = tool(mcp_server, "list_notes")()[0]
        assert row["body_truncated"] is True
        assert len(row["body_md"]) < len(long_body)
        assert tool(mcp_server, "get_note")(nid)["body_md"] == long_body

    def test_notes_short_body_kept_intact(self, mcp_server):
        add = tool(mcp_server, "add_note")
        add(title="n", body_md="* just one line")
        row = tool(mcp_server, "list_notes")()[0]
        assert row["body_md"] == "* just one line"
        assert "body_truncated" not in row


# ---------------------------------------------------------------------------
# Schema tool
# ---------------------------------------------------------------------------

class TestSchemaTool:
    def test_get_protocol_definition_schema(self, mcp_server):
        out = tool(mcp_server, "get_protocol_definition_schema")()
        assert "content" in out
        assert "uri" in out
        assert "workflow" in out
        # The guide content includes the YAML example header.
        assert "Protocol Definition" in out["content"]
