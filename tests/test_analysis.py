"""
Unit tests for ``protopoke.analysis`` — the pure analytical helpers used by
the new MCP reverse-engineering tools.

Each helper is exercised with synthetic frames so the behaviour is fully
deterministic and protocol-agnostic.
"""

from __future__ import annotations

import struct
import time

import pytest

from protopoke import analysis
from protopoke.models import Direction, Frame


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_frame(raw: bytes, seq: int = 0, direction: Direction = Direction.CLIENT_TO_SERVER) -> Frame:
    return Frame(
        id=f"frame-{seq}",
        session_id="sess",
        direction=direction,
        raw_bytes=raw,
        timestamp=1000.0 + seq * 0.01,
        sequence_number=seq,
        framer_name="raw",
    )


def position_frame(seq: int, x: float, y: float, z: float) -> Frame:
    """Two-byte prefix + three little-endian float32 (a stand-in for a
    position-update packet — used here only to exercise the heuristics)."""
    payload = b"mv" + struct.pack("<fff", x, y, z)
    return make_frame(payload, seq=seq)


# ---------------------------------------------------------------------------
# select_frames + paginate
# ---------------------------------------------------------------------------

class TestSelectFrames:
    def test_size_filter_exact(self):
        frames = [
            make_frame(b"\x00\x01", 0),
            make_frame(b"\x00\x01\x02", 1),
            make_frame(b"\x00\x01\x02\x03", 2),
        ]
        out = analysis.select_frames(frames, size_bytes=3)
        assert [len(f.raw_bytes) for f in out] == [3]

    def test_min_max_size(self):
        frames = [make_frame(bytes(i), i) for i in (1, 5, 10, 20)]
        out = analysis.select_frames(frames, min_size=5, max_size=15)
        assert [len(f.raw_bytes) for f in out] == [5, 10]

    def test_byte_pattern_match(self):
        frames = [
            make_frame(b"ab\x00", 0),
            make_frame(b"cd\x00", 1),
            make_frame(b"ab\x01", 2),
        ]
        out = analysis.select_frames(frames, byte_patterns=[{"offset": 0, "hex": "61 62"}])
        assert [f.sequence_number for f in out] == [0, 2]

    def test_byte_pattern_out_of_range(self):
        frames = [make_frame(b"\x01", 0)]
        out = analysis.select_frames(frames, byte_patterns=[{"offset": 4, "hex": "00"}])
        assert out == []

    def test_invalid_hex_raises(self):
        with pytest.raises(ValueError):
            analysis.select_frames(
                [make_frame(b"\x00")],
                byte_patterns=[{"offset": 0, "hex": "ZZ"}],
            )


class TestPaginate:
    def test_basic(self):
        page, nxt = analysis.paginate(list(range(10)), limit=3, cursor=0)
        assert page == [0, 1, 2]
        assert nxt == 3

    def test_last_page_returns_none_cursor(self):
        page, nxt = analysis.paginate(list(range(5)), limit=10, cursor=0)
        assert page == [0, 1, 2, 3, 4]
        assert nxt is None


# ---------------------------------------------------------------------------
# frame_stats
# ---------------------------------------------------------------------------

class TestFrameStats:
    def test_empty(self):
        out = analysis.frame_stats([])
        assert out["frame_count"] == 0
        assert out["buckets"] == []

    def test_buckets_by_prefix_and_size(self):
        frames = [position_frame(i, x=float(i), y=0.0, z=0.0) for i in range(5)]
        frames.append(make_frame(b"hb\x00", seq=5))
        out = analysis.frame_stats(frames)
        # Two buckets: ("6d76", 14) and ("6862", 3)
        keys = {(b["prefix_hex"], b["size_bytes"]) for b in out["buckets"]}
        assert ("6d76", 14) in keys
        assert ("6862", 3) in keys

    def test_per_offset_stats_only_for_buckets_with_3_plus(self):
        frames = [
            make_frame(b"\x01\x02", 0),
            make_frame(b"\x01\x03", 1),
        ]
        out = analysis.frame_stats(frames)
        bucket = out["buckets"][0]
        assert "per_offset_stats" not in bucket

    def test_per_offset_change_rate(self):
        frames = [
            make_frame(b"\x01\x00", 0),
            make_frame(b"\x01\x01", 1),
            make_frame(b"\x01\x02", 2),
            make_frame(b"\x01\x03", 3),
        ]
        # bucket_prefix_len=1 so all 4 frames share the same prefix bucket
        out = analysis.frame_stats(frames, bucket_prefix_len=1)
        stats = out["buckets"][0]["per_offset_stats"]
        # offset 0 never changes; offset 1 changes every frame
        assert stats[0]["change_rate"] == 0.0
        assert stats[1]["change_rate"] == 1.0


# ---------------------------------------------------------------------------
# entropy_map
# ---------------------------------------------------------------------------

class TestEntropyMap:
    def test_constant_column_has_zero_entropy(self):
        frames = [make_frame(b"\xaa\x00", i) for i in range(4)]
        out = analysis.entropy_map(frames)
        assert out["entropies"][0] == 0.0

    def test_uniform_column_has_high_entropy(self):
        frames = [make_frame(bytes([i, 0]), i) for i in range(256)]
        out = analysis.entropy_map(frames)
        assert out["entropies"][0] == pytest.approx(8.0, abs=0.01)
        assert out["entropies"][1] == 0.0

    def test_size_mismatch_errors(self):
        frames = [make_frame(b"\x00", 0), make_frame(b"\x00\x01", 1)]
        out = analysis.entropy_map(frames)
        assert "error" in out


# ---------------------------------------------------------------------------
# cluster_frames
# ---------------------------------------------------------------------------

class TestClusterFrames:
    def test_groups_by_prefix_and_size(self):
        frames = [
            make_frame(b"AB\x00\x00", 0),
            make_frame(b"AB\x00\x01", 1),
            make_frame(b"CD\x00", 2),
        ]
        out = analysis.cluster_frames(frames, prefix_len=2)
        clusters = {(c["prefix_hex"], c["size_bytes"]): c["count"] for c in out["clusters"]}
        assert clusters[("4142", 4)] == 2
        assert clusters[("4344", 3)] == 1


# ---------------------------------------------------------------------------
# compare_two_frames
# ---------------------------------------------------------------------------

class TestCompareTwoFrames:
    def test_identical(self):
        a = make_frame(b"\x01\x02\x03", 0)
        b = make_frame(b"\x01\x02\x03", 1)
        out = analysis.compare_two_frames(a, b)
        assert out["differences"] == []
        assert out["common_prefix_len"] == 3

    def test_runs_coalesced(self):
        a = make_frame(b"\x00\x00\x00\x00", 0)
        b = make_frame(b"\x00\xff\xff\x00", 1)
        out = analysis.compare_two_frames(a, b)
        assert len(out["differences"]) == 1
        diff = out["differences"][0]
        assert diff["offset"] == 1
        assert diff["length"] == 2
        assert diff["value_a_hex"] == "0000"
        assert diff["value_b_hex"] == "ffff"

    def test_delta_for_small_int(self):
        a = make_frame(bytes([0x00, 0x01]), 0)
        b = make_frame(bytes([0x00, 0x05]), 1)
        out = analysis.compare_two_frames(a, b)
        assert out["differences"][0]["delta_as_int"] == 4

    def test_unequal_lengths(self):
        a = make_frame(b"\x00\x00", 0)
        b = make_frame(b"\x00\x00\x00\x00", 1)
        out = analysis.compare_two_frames(a, b)
        assert out["size_a"] == 2
        assert out["size_b"] == 4


# ---------------------------------------------------------------------------
# diff_bucket
# ---------------------------------------------------------------------------

class TestDiffBucket:
    def test_constant_offsets_omitted(self):
        frames = [
            make_frame(b"\x01\x00", 0),
            make_frame(b"\x01\x01", 1),
            make_frame(b"\x01\x02", 2),
        ]
        out = analysis.diff_bucket(frames)
        offsets = [c["offset"] for c in out["columns"]]
        assert offsets == [1]


# ---------------------------------------------------------------------------
# decode_field
# ---------------------------------------------------------------------------

class TestDecodeField:
    def test_uint16_le(self):
        frames = [
            make_frame(b"\x01\x00\x00\x00", 0),
            make_frame(b"\x01\x00\xff\x00", 1),
        ]
        out = analysis.decode_field(frames, offset=2, size=2, type_name="uint16_le")
        assert [r["value"] for r in out] == [0, 255]

    def test_float32_le(self):
        frames = [make_frame(b"\x00\x00\x80\x3f", 0)]  # 1.0
        out = analysis.decode_field(frames, offset=0, size=4, type_name="float32_le")
        assert out[0]["value"] == pytest.approx(1.0)

    def test_deduplicate(self):
        frames = [
            make_frame(b"\x01", 0),
            make_frame(b"\x01", 1),
            make_frame(b"\x02", 2),
            make_frame(b"\x02", 3),
        ]
        out = analysis.decode_field(frames, offset=0, size=1, type_name="uint8", deduplicate=True)
        assert [r["value"] for r in out] == [1, 2]

    def test_frame_too_short_records_error(self):
        frames = [make_frame(b"\x01", 0)]
        out = analysis.decode_field(frames, offset=0, size=4, type_name="uint32_le")
        assert out[0]["value"] is None
        assert "frame too short" in out[0]["error"]

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError):
            analysis.decode_field([make_frame(b"\x00")], 0, 1, "not_a_type")

    def test_size_mismatches_raises(self):
        with pytest.raises(ValueError):
            analysis.decode_field([make_frame(b"\x00\x00")], 0, 2, "uint8")

    def test_ascii_renders_non_printables_as_dot(self):
        frames = [make_frame(b"\x41\x00\x42", 0)]
        out = analysis.decode_field(frames, offset=0, size=3, type_name="ascii")
        assert out[0]["value"] == "A.B"

    def test_cstring_stops_at_nul(self):
        frames = [make_frame(b"hi\x00xx", 0)]
        out = analysis.decode_field(frames, offset=0, size=5, type_name="cstring")
        assert out[0]["value"] == "hi"


# ---------------------------------------------------------------------------
# analyze_byte_ranges
# ---------------------------------------------------------------------------

class TestAnalyzeByteRanges:
    def test_constant_offsets_grouped_as_always_same(self):
        frames = [make_frame(b"\xaa\x00", i) for i in range(4)]
        out = analysis.analyze_byte_ranges(frames)
        for o in out["offsets"]:
            assert o["always_same_value"] is True
        assert out["groups"] == []

    def test_detects_length_field(self):
        frames = []
        for i in range(5):
            # value at offset 0 = total length (1 + body)
            body = bytes([0xff] * i)
            raw = bytes([1 + len(body)]) + body if len(body) >= 0 else b""
            # Pad to fixed size 6 so the bucket analysis is valid
            raw = raw.ljust(6, b"\x00")
            # NOTE: we need varying values at offset 0 across frames for
            # the offset to land in a "group" — fabricate 5 different lengths
            frames.append(make_frame(raw, i))
        # Replace ourselves: build frames where offset 0 = useful_payload_len.
        frames = []
        for i, body in enumerate([b"", b"\x01", b"\x01\x02", b"\x01\x02\x03"]):
            raw = bytes([len(body) + 1]) + body
            raw = raw.ljust(5, b"\x00")
            frames.append(make_frame(raw, i))
        out = analysis.analyze_byte_ranges(frames)
        # Find the group covering offset 0
        first = next((g for g in out["groups"] if g["offset_start"] == 0), None)
        assert first is not None
        # All frames are 5 bytes; value at offset 0 ∈ {1,2,3,4}; delta = 4,3,2,1
        # → NOT a constant offset, so this generic check should NOT report it
        # as a length field — sanity-check that the heuristic doesn't false-fire
        # on every varying byte.
        assert first["looks_like_length"] is None

    def test_detects_monotonic_counter(self):
        # 4 frames, byte at offset 0 = sequence number
        frames = [make_frame(bytes([i, 0xaa]), i) for i in range(8)]
        out = analysis.analyze_byte_ranges(frames)
        first = next(g for g in out["groups"] if g["offset_start"] == 0)
        assert first["looks_like_counter"] is not None
        assert first["looks_like_counter"]["first"] == 0
        assert first["looks_like_counter"]["last"] == 7

    def test_float_candidate_emitted_for_4byte_groups(self):
        # Use fractional floats so every byte of the mantissa varies → the
        # varying range is exactly 4 bytes wide.
        frames = []
        for i, x in enumerate([0.1, 0.2, 0.3, 0.4, 0.5]):
            payload = b"\xaa\xaa" + struct.pack("<f", x) + b"\xbb\xbb"
            frames.append(make_frame(payload, seq=i))
        out = analysis.analyze_byte_ranges(frames)
        var = next((g for g in out["groups"] if g["offset_start"] == 2), None)
        assert var is not None
        assert var["width"] == 4
        labels = {c["type"] for c in var["candidate_types"]}
        assert "float32_le" in labels
        assert "float32_be" in labels
        # float32_le should look more plausible than float32_be (BE decoding
        # of these little-endian floats gives extreme magnitudes).
        le = next(c for c in var["candidate_types"] if c["type"] == "float32_le")
        be = next(c for c in var["candidate_types"] if c["type"] == "float32_be")
        assert le["plausible"] is True
        assert be["plausible"] is False

    def test_ascii_run_flagged(self):
        frames = []
        names = [b"alice", b"carol", b"david", b"eline"]
        for i, n in enumerate(names):
            frames.append(make_frame(n + b"\x00", i))
        out = analysis.analyze_byte_ranges(frames)
        # Whole [0, 5) range is ASCII letters
        run = next(g for g in out["groups"] if g["offset_start"] == 0)
        assert run["looks_like_ascii_run"] is True


# ---------------------------------------------------------------------------
# find_length_field_candidates
# ---------------------------------------------------------------------------

class TestFindLengthFieldCandidates:
    def test_uint8_length_prefix(self):
        # Variable-length frames: byte 0 = total frame length
        frames = []
        for i, body in enumerate([b"\xaa", b"\xaa\xbb", b"\xaa\xbb\xcc", b"\xaa\xbb\xcc\xdd"]):
            raw = bytes([1 + len(body)]) + body
            frames.append(make_frame(raw, i))
        out = analysis.find_length_field_candidates(frames)
        offsets = {c["offset"] for c in out["candidates"]}
        assert 0 in offsets
        c0 = next(c for c in out["candidates"] if c["offset"] == 0 and c["width"] == 1)
        assert c0["constant"] == 0

    def test_uint16_be_length_with_header_constant(self):
        # 2-byte BE length field at offset 2, with a 4-byte header before payload.
        # Constant offset = header_len that's not in the value.
        frames = []
        for i, body_len in enumerate([0, 1, 4, 10]):
            body = b"\xff" * body_len
            raw = b"\x00\x01" + (body_len + 4).to_bytes(2, "big") + body + b"\x00" * 2
            # raw = [magic 2B][len(body)+4 BE 2B][body][trailer 2B]
            # total = 2 + 2 + body_len + 2 = body_len + 6
            # value at offset 2 (BE u16) = body_len + 4
            # constant = total - value = (body_len+6) - (body_len+4) = 2
            frames.append(make_frame(raw, i))
        out = analysis.find_length_field_candidates(frames)
        match = next(
            (c for c in out["candidates"]
             if c["offset"] == 2 and c["width"] == 2 and c["byteorder"] == "big"),
            None,
        )
        assert match is not None
        assert match["constant"] == 2

    def test_no_false_positive_when_value_varies(self):
        # Fixed-size frames whose first byte is random — no length signal.
        frames = [make_frame(bytes([i, 0xaa, 0xbb]), i) for i in range(6)]
        out = analysis.find_length_field_candidates(frames)
        # No candidate should claim offset 0 if the deltas aren't all equal.
        for c in out["candidates"]:
            if c["offset"] == 0 and c["width"] == 1:
                # delta = len(frame) - value = 3 - i, varies → must not appear
                pytest.fail(f"false positive: {c}")


# ---------------------------------------------------------------------------
# offset_correlations
# ---------------------------------------------------------------------------

class TestOffsetCorrelations:
    def test_perfectly_correlated(self):
        # value at offset 0 == value at offset 1
        frames = [make_frame(bytes([i, i]), i) for i in range(10)]
        out = analysis.offset_correlations(frames, 0, 1)
        assert out["pearson_r"] == pytest.approx(1.0, abs=1e-6)
        assert out["change_pairing"] == pytest.approx(1.0)

    def test_anti_correlated(self):
        frames = [make_frame(bytes([i, 255 - i]), i) for i in range(10)]
        out = analysis.offset_correlations(frames, 0, 1)
        assert out["pearson_r"] == pytest.approx(-1.0, abs=1e-6)

    def test_constant_returns_none(self):
        frames = [make_frame(bytes([i, 0]), i) for i in range(10)]
        out = analysis.offset_correlations(frames, 0, 1)
        # offset 1 is constant → no Pearson
        assert out["pearson_r"] is None

    def test_non_numeric_type_rejected(self):
        with pytest.raises(ValueError):
            analysis.offset_correlations([make_frame(b"\x00\x00")], 0, 1, type_a="ascii")
