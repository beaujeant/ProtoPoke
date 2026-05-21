"""
Tests for the MCP analytical / protocol-definition-editing tools added in
``protopoke/mcp/server.py``.

Mirrors the pattern used in ``test_mcp_server.py``: stubs the TLS native
extension, builds a real ``ProtoPokeAPI``, retrieves tools through the
FastMCP tool manager, and calls them as plain functions.
"""

from __future__ import annotations

import struct
import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# TLS / cryptography stubs (same as test_mcp_server.py)
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
from protopoke.models import Direction, Frame  # noqa: E402
from protopoke.mcp import build_mcp_server  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def api():
    fwd = ForwarderConfig(
        name="Default",
        listen_port=19999,
        upstream_host="127.0.0.1",
        upstream_port=19998,
    )
    return ProtoPokeAPI([fwd])


@pytest.fixture
def mcp_server(api):
    return build_mcp_server(api)


def get_tool(mcp_server, name):
    tool = mcp_server._tool_manager.get_tool(name)
    assert tool is not None, f"Tool '{name}' not found"
    return tool.fn


def populate_position_session(api):
    """Create a session and add fixed-size 'position' frames with two-byte
    prefix + three little-endian float32s."""
    session = api.session_registry.create("127.0.0.1", 50001, "10.0.0.1", 443)
    for i, x in enumerate([0.1, 0.2, 0.3, 0.4, 0.5]):
        raw = b"mv" + struct.pack("<fff", x, 10.0, 20.0)
        frame = Frame.create(session.id, Direction.CLIENT_TO_SERVER, raw, i)
        session.add_frame(frame)
    # One reply packet so direction filtering has something to drop
    reply = Frame.create(session.id, Direction.SERVER_TO_CLIENT, b"ok", 0)
    session.add_frame(reply)
    return session


def populate_length_prefix_session(api):
    """Variable-size frames where byte 0 = total frame length."""
    session = api.session_registry.create("127.0.0.1", 50002, "10.0.0.1", 443)
    for i, body in enumerate([b"\xaa", b"\xaa\xbb", b"\xaa\xbb\xcc"]):
        raw = bytes([1 + len(body)]) + body
        session.add_frame(Frame.create(session.id, Direction.CLIENT_TO_SERVER, raw, i))
    return session


# ---------------------------------------------------------------------------
# list_field_types
# ---------------------------------------------------------------------------

class TestListFieldTypes:
    def test_returns_known_types(self, mcp_server):
        fn = get_tool(mcp_server, "list_field_types")
        types = fn()
        assert "uint16_le" in types
        assert "float32_be" in types
        assert "ascii" in types
        assert "cstring" in types


# ---------------------------------------------------------------------------
# get_frame_stats
# ---------------------------------------------------------------------------

class TestGetFrameStats:
    def test_returns_buckets(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "get_frame_stats")
        out = fn(session.id)
        assert out["frame_count"] == 6
        # One bucket per (prefix, size) pair → 2 expected
        prefixes = {(b["prefix_hex"], b["size_bytes"]) for b in out["buckets"]}
        assert ("6d76", 14) in prefixes  # "mv" + 12 bytes of floats

    def test_invalid_direction(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "get_frame_stats")
        out = fn(session.id, direction="wrong")
        assert "error" in out

    def test_session_not_found_returns_empty(self, mcp_server):
        fn = get_tool(mcp_server, "get_frame_stats")
        out = fn("nope")
        assert out["frame_count"] == 0


# ---------------------------------------------------------------------------
# entropy_map / cluster_frames
# ---------------------------------------------------------------------------

class TestEntropyMap:
    def test_constant_bytes_have_zero_entropy(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "entropy_map")
        out = fn(session.id, direction="client_to_server", size_bytes=14)
        # First two bytes are always "mv" → entropy 0
        assert out["entropies"][0] == 0.0
        assert out["entropies"][1] == 0.0


class TestClusterFrames:
    def test_clusters_match_packet_types(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "cluster_frames")
        out = fn(session.id, prefix_len=2)
        sizes = {c["size_bytes"] for c in out["clusters"]}
        assert 14 in sizes
        assert 2 in sizes  # the "ok" reply


# ---------------------------------------------------------------------------
# filter_frames
# ---------------------------------------------------------------------------

class TestFilterFrames:
    def test_size_filter(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "filter_frames")
        out = fn(session.id, size_bytes=14)
        assert out["total_matching"] == 5
        assert all(len(bytes.fromhex(f["raw_bytes"])) == 14 for f in out["frames"])

    def test_byte_pattern_filter(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "filter_frames")
        out = fn(session.id, byte_patterns=[{"offset": 0, "hex": "6d76"}])
        assert out["total_matching"] == 5

    def test_pagination(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "filter_frames")
        out = fn(session.id, limit=2, offset_cursor=0)
        assert out["returned"] == 2
        assert out["next_cursor"] == 2

    def test_invalid_hex_returns_error(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "filter_frames")
        out = fn(session.id, byte_patterns=[{"offset": 0, "hex": "ZZ"}])
        assert "error" in out


# ---------------------------------------------------------------------------
# decode_field
# ---------------------------------------------------------------------------

class TestDecodeField:
    def test_decodes_floats(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "decode_field")
        out = fn(
            session.id,
            offset=2, size=4, type="float32_le",
            direction="client_to_server", size_bytes=14,
        )
        values = [r["value"] for r in out["rows"]]
        assert values == pytest.approx([0.1, 0.2, 0.3, 0.4, 0.5], rel=1e-6)

    def test_dedupe(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "decode_field")
        # y is constant 10.0 → dedupe to a single row
        out = fn(
            session.id,
            offset=6, size=4, type="float32_le",
            direction="client_to_server", size_bytes=14,
            deduplicate=True,
        )
        assert out["total_returned"] == 1

    def test_truncation_flag(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "decode_field")
        out = fn(
            session.id, offset=2, size=4, type="float32_le",
            direction="client_to_server", size_bytes=14, limit=2,
        )
        assert out["truncated"] is True
        assert out["total_returned"] == 2

    def test_bad_type(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "decode_field")
        out = fn(session.id, offset=0, size=1, type="not_a_type")
        assert "error" in out


# ---------------------------------------------------------------------------
# compare_frames / diff_frames_in_bucket
# ---------------------------------------------------------------------------

class TestCompareFrames:
    def test_diff_between_two(self, mcp_server, api):
        session = populate_position_session(api)
        frames = [f for f in session.frames if len(f.raw_bytes) == 14][:2]
        fn = get_tool(mcp_server, "compare_frames")
        out = fn(session.id, frames[0].id, frames[1].id)
        # Only the x-float region (offsets 2..5) should differ
        assert all(d["offset"] >= 2 and d["offset"] + d["length"] <= 6
                   for d in out["differences"])

    def test_unknown_frame_id(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "compare_frames")
        out = fn(session.id, "nope", "also-nope")
        assert "error" in out


class TestDiffBucket:
    def test_column_offsets(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "diff_frames_in_bucket")
        out = fn(session.id, direction="client_to_server", size_bytes=14)
        offsets = {c["offset"] for c in out["columns"]}
        # Varying offsets are only inside the x-float (2..5)
        assert offsets.issubset({2, 3, 4, 5})


# ---------------------------------------------------------------------------
# analyze_byte_ranges
# ---------------------------------------------------------------------------

class TestAnalyzeByteRanges:
    def test_groups_and_constants(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "analyze_byte_ranges")
        out = fn(session.id, direction="client_to_server", size_bytes=14)
        # First two bytes are constant
        assert out["offsets"][0]["always_same_value"] is True
        # Group should contain the float32_le x-coordinate
        assert any(
            g["offset_start"] == 2 and any(
                c.get("type") == "float32_le" and c.get("plausible")
                for c in g["candidate_types"]
            )
            for g in out["groups"]
        )


# ---------------------------------------------------------------------------
# find_length_fields
# ---------------------------------------------------------------------------

class TestFindLengthFields:
    def test_detects_length_prefix(self, mcp_server, api):
        session = populate_length_prefix_session(api)
        fn = get_tool(mcp_server, "find_length_fields")
        out = fn(session.id, direction="client_to_server")
        first_byte_hit = next(
            (c for c in out["candidates"] if c["offset"] == 0 and c["width"] == 1),
            None,
        )
        assert first_byte_hit is not None
        assert first_byte_hit["constant"] == 0


# ---------------------------------------------------------------------------
# offset_correlations
# ---------------------------------------------------------------------------

class TestOffsetCorrelations:
    def test_basic(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "offset_correlations")
        # Compare two bytes inside the varying x-float region
        out = fn(
            session.id, offset_a=4, offset_b=5,
            type_a="uint8", type_b="uint8",
            direction="client_to_server", size_bytes=14,
        )
        assert out["n_used"] == 5
        # pearson_r may or may not be meaningful here, but the schema is fixed
        assert "pearson_r" in out
        assert "change_pairing" in out


# ---------------------------------------------------------------------------
# Protocol-definition editing tools
# ---------------------------------------------------------------------------

class TestProtocolDefinitionReadOnly:
    """The MCP server intentionally exposes only read-only access to the
    active protocol definition; mutation tools were removed so the AI
    cannot silently change how frames are decoded."""

    def test_get_without_definition_returns_error(self, mcp_server):
        fn = get_tool(mcp_server, "get_protocol_definition")
        out = fn()
        assert "error" in out

    def test_get_with_definition_round_trips(self, mcp_server, api):
        # Load a definition from a dict via the Python API (NOT the MCP)
        api.set_protocol_dict({
            "name": "MyProto",
            "endianness": "little",
            "messages": [
                {"name": "M",
                 "match": {"type": "always"},
                 "fields": [{"name": "a", "type": "uint8"}]},
            ],
        })
        d = get_tool(mcp_server, "get_protocol_definition")()
        assert d["name"] == "MyProto"
        assert d["endianness"] == "little"
        assert d["messages"][0]["name"] == "M"

    def test_get_schema_returns_guide_content(self, mcp_server):
        fn = get_tool(mcp_server, "get_protocol_definition_schema")
        out = fn()
        assert "content" in out
        assert "uri" in out
        assert out["uri"] == "protopoke://guides/protocol-definitions"
        assert "Protocol Definition" in out["content"]

    def test_mutation_tools_are_not_registered(self, mcp_server):
        """All write paths for protocol definitions are gone from MCP."""
        removed = [
            "set_protocol_file", "set_protocol_dict",
            "create_protocol_definition",
            "add_message_definition", "update_message_definition",
            "remove_message_definition", "reorder_message_definition",
            "add_field_to_message", "update_field_in_message",
            "remove_field_from_message",
            "save_protocol_to_file",
        ]
        for name in removed:
            assert mcp_server._tool_manager.get_tool(name) is None, (
                f"Expected tool {name!r} to be removed from MCP"
            )


# ---------------------------------------------------------------------------
# Structure discovery / semantic detection tools
# ---------------------------------------------------------------------------

class TestFindConstantByteSequences:
    def test_finds_recurring_magic(self, mcp_server, api):
        session = api.session_registry.create("127.0.0.1", 80, "10.0.0.1", 443)
        for i in range(5):
            session.add_frame(Frame.create(
                session.id, Direction.CLIENT_TO_SERVER,
                b"PROTO" + bytes([i]) + b"data", i,
            ))
        fn = get_tool(mcp_server, "find_constant_byte_sequences")
        out = fn(session.id, min_length=3, max_length=5)
        assert out["frame_count"] == 5
        hexes = {s["hex"] for s in out["sequences"]}
        assert "50524f544f" in hexes  # "PROTO"


class TestAlignFrames:
    def test_aligns_variable_length(self, mcp_server, api):
        session = api.session_registry.create("127.0.0.1", 80, "10.0.0.1", 443)
        # Mixed sizes: HEAD<n>TAIL where n is 1, 2, or 3 bytes
        bodies = [b"\x01", b"\x02\x02", b"\x03\x03\x03"]
        for i, body in enumerate(bodies):
            session.add_frame(Frame.create(
                session.id, Direction.CLIENT_TO_SERVER,
                b"HEAD" + body + b"TAIL", i,
            ))
        fn = get_tool(mcp_server, "align_frames")
        out = fn(session.id)
        assert out["frame_count"] == 3
        assert any(r["kind"] in ("differ", "gap") for r in out["variable_regions"])


class TestExtractStrings:
    def test_finds_ascii(self, mcp_server, api):
        session = api.session_registry.create("127.0.0.1", 80, "10.0.0.1", 443)
        session.add_frame(Frame.create(
            session.id, Direction.CLIENT_TO_SERVER,
            b"\x00\x01hello world\x00bye\x00", 0,
        ))
        fn = get_tool(mcp_server, "extract_strings")
        out = fn(session.id, min_length=3)
        values = {s["value"] for s in out["strings"]}
        assert "hello world" in values
        assert "bye" in values


class TestDetectTlv:
    def test_detects_chain(self, mcp_server, api):
        session = api.session_registry.create("127.0.0.1", 80, "10.0.0.1", 443)
        chain = b"\x01\x02ab\x02\x03xyz"
        for i in range(3):
            session.add_frame(Frame.create(
                session.id, Direction.CLIENT_TO_SERVER, chain, i,
            ))
        fn = get_tool(mcp_server, "detect_tlv")
        out = fn(session.id)
        assert out["candidates"]
        top = out["candidates"][0]
        assert top["type_width"] == 1
        assert top["length_width"] == 1
        assert top["coverage"] == 1.0


class TestDetectChecksumsCrcs:
    def test_sum8_detected(self, mcp_server, api):
        import struct
        session = api.session_registry.create("127.0.0.1", 80, "10.0.0.1", 443)
        for i in range(8):
            payload = bytes([i, i + 1, i + 2, i + 3])
            session.add_frame(Frame.create(
                session.id, Direction.CLIENT_TO_SERVER,
                payload + bytes([sum(payload) & 0xFF]), i,
            ))
        fn = get_tool(mcp_server, "detect_checksums_crcs")
        out = fn(session.id)
        assert any(
            c["algorithm"] == "sum8" and c["offset"] == 4
            for c in out["candidates"]
        )


class TestDetectTimestamps:
    def test_unix_seconds(self, mcp_server, api):
        import struct
        session = api.session_registry.create("127.0.0.1", 80, "10.0.0.1", 443)
        base = 1_700_000_000
        for i in range(10):
            f = Frame.create(
                session.id, Direction.CLIENT_TO_SERVER,
                struct.pack("<I", base + i) + b"data", i,
            )
            session.add_frame(f)
        fn = get_tool(mcp_server, "detect_timestamps")
        out = fn(session.id)
        assert any(
            c["offset"] == 0 and c["byteorder"] == "little"
            and c["epoch"] == "unix_seconds"
            for c in out["candidates"]
        )


class TestDetectCompressionEncryption:
    def test_known_magic(self, mcp_server, api):
        session = api.session_registry.create("127.0.0.1", 80, "10.0.0.1", 443)
        session.add_frame(Frame.create(
            session.id, Direction.CLIENT_TO_SERVER,
            b"prefix\x1f\x8bgzip_body_here" + bytes(range(50)), 0,
        ))
        fn = get_tool(mcp_server, "detect_compression_encryption")
        out = fn(session.id)
        names = {s["name"] for f in out["findings"] for s in f["signatures"]}
        assert "gzip" in names


class TestEchoDetection:
    def test_transaction_id_echo(self, mcp_server, api):
        import struct
        session = api.session_registry.create("127.0.0.1", 80, "10.0.0.1", 443)
        seq = 0
        for i in range(8):
            txn = struct.pack("<I", 0xDEADBEEF + i)
            session.add_frame(Frame.create(
                session.id, Direction.CLIENT_TO_SERVER,
                b"\x01" + txn + b"req", seq,
            ))
            seq += 1
            session.add_frame(Frame.create(
                session.id, Direction.SERVER_TO_CLIENT,
                b"\x81" + txn + b"reply", seq,
            ))
            seq += 1
        fn = get_tool(mcp_server, "echo_detection")
        out = fn(session.id)
        # Echo at offset 1 width 4 (the txn ID) should be in the candidates
        good = [
            c for c in out["candidates"]
            if c["src_offset"] == 1 and c["dst_offset"] == 1
            and c["width"] == 4
            and c["src_direction"] == "client_to_server"
        ]
        assert good
        assert good[0]["coverage"] >= 0.9


# ---------------------------------------------------------------------------
# Field-type bruteforce / time series tools
# ---------------------------------------------------------------------------

import asyncio  # noqa: E402
import socket  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _echo_server(host: str, port: int):
    async def handler(reader, writer):
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass
    return await asyncio.start_server(handler, host, port)


class TestAnalyzeFieldCorrelation:
    def test_decodes_time_series(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "analyze_field_correlation")
        out = fn(session.id, byte_offset=2, byte_length=4, encoding="f32_le",
                 direction="client_to_server")
        vals = [round(r["value"], 4) for r in out["rows"]]
        assert vals == [0.1, 0.2, 0.3, 0.4, 0.5]
        assert "suggestion" in out
        assert "frame_id" in out["rows"][0]

    def test_byte_length_mismatch_errors(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "analyze_field_correlation")
        out = fn(session.id, byte_offset=2, byte_length=2, encoding="f32_le")
        assert "error" in out

    def test_bad_encoding_errors(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "analyze_field_correlation")
        out = fn(session.id, byte_offset=0, byte_length=1, encoding="uint8")
        assert "error" in out


class TestBruteforceNumericLayout:
    def test_returns_candidates(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "bruteforce_numeric_layout")
        out = fn(session.id, direction="client_to_server", top_n=50)
        assert out["size_bytes"] == 14
        offenc = {(c["offset"], c["encoding"]) for c in out["candidates"]}
        assert (2, "f32_le") in offenc
        assert "suggestion" in out

    def test_no_frames(self, mcp_server, api):
        session = api.session_registry.create("127.0.0.1", 1, "10.0.0.1", 2)
        fn = get_tool(mcp_server, "bruteforce_numeric_layout")
        out = fn(session.id)
        assert out["candidates"] == []


class TestGroupByFieldValue:
    def test_buckets(self, mcp_server, api):
        session = api.session_registry.create("127.0.0.1", 1, "10.0.0.1", 2)
        for i, b in enumerate([b"\x01\xaa", b"\x01\xbb", b"\x02\xcc"]):
            session.add_frame(Frame.create(session.id, Direction.CLIENT_TO_SERVER, b, i))
        fn = get_tool(mcp_server, "group_by_field_value")
        out = fn(session.id, ranges=[{"offset": 0, "length": 1}])
        assert out["counts"] == {"01": 2, "02": 1}
        assert "suggestion" in out

    def test_invalid_range(self, mcp_server, api):
        session = api.session_registry.create("127.0.0.1", 1, "10.0.0.1", 2)
        fn = get_tool(mcp_server, "group_by_field_value")
        out = fn(session.id, ranges=[{"offset": 0}])
        assert "error" in out


class TestDiffFrames:
    def test_diff_with_field_delta(self, mcp_server, api):
        session = api.session_registry.create("127.0.0.1", 1, "10.0.0.1", 2)
        f0 = Frame.create(session.id, Direction.CLIENT_TO_SERVER, struct.pack("<I", 100), 0)
        f1 = Frame.create(session.id, Direction.CLIENT_TO_SERVER, struct.pack("<I", 175), 1)
        session.add_frame(f0)
        session.add_frame(f1)
        fn = get_tool(mcp_server, "diff_frames")
        out = fn(session.id, frame_id_a=f0.id, frame_id_b=f1.id,
                 field_decls=[{"offset": 0, "length": 4, "encoding": "u32_le"}])
        assert out["field_deltas"][0]["delta"] == 75
        assert "suggestion" in out

    def test_unknown_frame(self, mcp_server, api):
        session = api.session_registry.create("127.0.0.1", 1, "10.0.0.1", 2)
        fn = get_tool(mcp_server, "diff_frames")
        out = fn(session.id, frame_id_a="nope", frame_id_b="nope2")
        assert "error" in out


class TestExportSessionCsv:
    def test_csv_output(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "export_session_csv")
        out = fn(session.id, direction="client_to_server", fields=[
            {"name": "x", "byte_offset": 2, "byte_length": 4, "encoding": "f32_le"},
        ])
        header = out["csv"].splitlines()[0]
        assert header == "frame_id,timestamp,sequence_number,direction,size,x"
        assert out["rows"] == 5

    def test_bad_field(self, mcp_server, api):
        session = populate_position_session(api)
        fn = get_tool(mcp_server, "export_session_csv")
        out = fn(session.id, fields=[
            {"name": "x", "byte_offset": 0, "byte_length": 1, "encoding": "u16_le"},
        ])
        assert "error" in out


class TestDetectPeriodicStreams:
    def test_periodic(self, mcp_server, api):
        session = api.session_registry.create("127.0.0.1", 1, "10.0.0.1", 2)
        for i in range(15):
            f = Frame.create(session.id, Direction.SERVER_TO_CLIENT, b"\xaa\xbbping", i)
            f.timestamp = 1000.0 + i  # 1s apart
            session.add_frame(f)
        fn = get_tool(mcp_server, "detect_periodic_streams")
        out = fn(session.id)
        assert out["periodic_count"] == 1
        assert out["buckets"][0]["is_periodic"] is True
        assert "suggestion" in out


class TestBisectFieldMeaning:
    async def test_sweeps_candidates_over_forge(self, mcp_server, api):
        port = _free_port()
        server = await _echo_server("127.0.0.1", port)
        async with server:
            sid = await api.open_forge_session("127.0.0.1", port)
            fn = get_tool(mcp_server, "bisect_field_meaning")
            base = b"\x01\x00\x00"  # u16_le field at offset 1
            out = await fn(
                forge_session_id=sid,
                base_frame_hex=base.hex(),
                byte_offset=1, byte_length=2, encoding="u16_le",
                candidate_values=[1, 2, 300],
                receive_timeout=1.0,
            )
        assert out["ok"] is True
        # Echo server returns the mutated frame, so each response carries the
        # candidate value at offset 1.
        assert out["results"]["1"] == (b"\x01" + (1).to_bytes(2, "little")).hex()
        assert out["results"]["2"] == (b"\x01" + (2).to_bytes(2, "little")).hex()
        assert out["results"]["300"] == (b"\x01" + (300).to_bytes(2, "little")).hex()
        assert "suggestion" in out

    async def test_value_range(self, mcp_server, api):
        port = _free_port()
        server = await _echo_server("127.0.0.1", port)
        async with server:
            sid = await api.open_forge_session("127.0.0.1", port)
            fn = get_tool(mcp_server, "bisect_field_meaning")
            out = await fn(
                forge_session_id=sid,
                base_frame_hex="00",
                byte_offset=0, byte_length=1, encoding="u8",
                value_range={"start": 0, "stop": 3, "step": 1},
                receive_timeout=1.0,
            )
        assert out["ok"] is True
        assert set(out["results"]) == {"0", "1", "2"}

    async def test_width_mismatch(self, mcp_server, api):
        fn = get_tool(mcp_server, "bisect_field_meaning")
        out = await fn(
            forge_session_id="x", base_frame_hex="0000",
            byte_offset=0, byte_length=1, encoding="u16_le",
            candidate_values=[1],
        )
        assert out["ok"] is False

    async def test_no_candidates(self, mcp_server, api):
        fn = get_tool(mcp_server, "bisect_field_meaning")
        out = await fn(
            forge_session_id="x", base_frame_hex="0000",
            byte_offset=0, byte_length=2, encoding="u16_le",
        )
        assert out["ok"] is False

    async def test_field_out_of_range(self, mcp_server, api):
        fn = get_tool(mcp_server, "bisect_field_meaning")
        out = await fn(
            forge_session_id="x", base_frame_hex="00",
            byte_offset=4, byte_length=1, encoding="u8",
            candidate_values=[1],
        )
        assert out["ok"] is False
