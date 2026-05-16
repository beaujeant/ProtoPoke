"""
Analytical helpers for binary protocol reverse engineering.

Pure functions that operate on lists of ``Frame`` objects.  No I/O, no state
— each helper takes the frames already selected from the session registry and
returns a plain-dict result suitable for JSON serialisation (and therefore for
MCP transport).

The helpers are grouped by purpose:

    Selection / filtering
        ``select_frames`` — direction, size, byte-pattern filtering with pagination.

    Statistics
        ``frame_stats``         — packet-type buckets + per-offset change rate + entropy.
        ``entropy_map``         — per-offset Shannon entropy across a bucket.
        ``cluster_frames``      — auto-group frames by (prefix, size) shape.

    Diffing
        ``compare_two_frames``    — side-by-side hex diff of two frames.
        ``diff_bucket``           — column-by-column diff matrix across many frames.

    Decoding
        ``decode_field``          — parse one ``(offset, size, type)`` triple across frames.

    Heuristics
        ``analyze_byte_ranges``   — generic per-offset / per-group heuristics
                                    (constant, ASCII, float-like, length-like, counter-like).
        ``find_length_field_candidates`` — offsets whose value tracks frame length.
        ``offset_correlations``   — do values at two offsets co-vary?

    Structure discovery
        ``find_constant_byte_sequences`` — recurring n-grams regardless of offset.
        ``align_frames``                 — Needleman-Wunsch alignment of mixed-size frames.
        ``extract_strings``              — printable-ASCII runs (``strings(1)`` for frames).
        ``detect_tlv``                   — try TLV shapes and score completion per frame.

    Semantic field detection
        ``detect_checksums_crcs``        — try sum/xor/CRC/Adler/Fletcher across frames.
        ``detect_timestamps``            — offsets whose value falls in a time epoch range.
        ``detect_compression_encryption``— high-entropy regions + known magic signatures.
        ``echo_detection``               — values sent in one direction that reappear in the other.

All helpers are deliberately protocol-agnostic: no hard-coded magic bytes, no
domain-specific value ranges, no game-protocol assumptions.
"""

from __future__ import annotations

import binascii
import math
import re
import struct
import zlib
from collections import Counter, defaultdict
from typing import Any, Iterable, Optional

from .models import Direction, Frame


# ---------------------------------------------------------------------------
# Selection / filtering
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


def _parse_hex(s: str) -> bytes:
    """Parse a hex string, stripping whitespace and ``0x`` prefixes."""
    cleaned = re.sub(r"\s+|0x", "", s)
    if not _HEX_RE.match(cleaned):
        raise ValueError(f"Invalid hex string: {s!r}")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"Hex string must have even length: {s!r}")
    return bytes.fromhex(cleaned)


def select_frames(
    frames:       list[Frame],
    direction:    Optional[Direction]       = None,
    size_bytes:   Optional[int]             = None,
    min_size:     Optional[int]             = None,
    max_size:     Optional[int]             = None,
    byte_patterns: Optional[list[dict]]     = None,   # [{offset:int, hex:str}]
) -> list[Frame]:
    """
    Filter frames by direction / size / fixed-offset byte patterns.

    All filters are ANDed together.  ``byte_patterns`` requires every pattern
    to match (each pattern is a ``{offset, hex}`` dict).
    """
    out: list[Frame] = []
    parsed_patterns: list[tuple[int, bytes]] = []
    for p in (byte_patterns or []):
        off = int(p["offset"])
        raw = _parse_hex(str(p["hex"]))
        parsed_patterns.append((off, raw))

    for f in frames:
        if direction is not None and f.direction is not direction:
            continue
        L = len(f.raw_bytes)
        if size_bytes is not None and L != size_bytes:
            continue
        if min_size is not None and L < min_size:
            continue
        if max_size is not None and L > max_size:
            continue
        ok = True
        for off, raw in parsed_patterns:
            if off < 0 or off + len(raw) > L:
                ok = False
                break
            if f.raw_bytes[off:off + len(raw)] != raw:
                ok = False
                break
        if not ok:
            continue
        out.append(f)
    return out


def paginate(items: list, limit: int, cursor: int) -> tuple[list, Optional[int]]:
    """Slice ``items`` for pagination.  Returns ``(page, next_cursor)``."""
    if cursor < 0:
        cursor = 0
    end = cursor + max(0, limit)
    page = items[cursor:end]
    next_cursor: Optional[int] = end if end < len(items) else None
    return page, next_cursor


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def _shannon_entropy(values: Iterable[int]) -> float:
    """Shannon entropy (bits) of an iterable of bytes / small ints."""
    counts = Counter(values)
    total = sum(counts.values())
    if total == 0:
        return 0.0
    H = 0.0
    for c in counts.values():
        p = c / total
        H -= p * math.log2(p)
    return H


def _prefix_counts(frames: list[Frame], n: int) -> list[dict]:
    """Top first-N-byte prefixes and their counts."""
    c: Counter = Counter()
    for f in frames:
        if len(f.raw_bytes) >= n:
            c[f.raw_bytes[:n]] += 1
    return [
        {"prefix_hex": p.hex(), "count": k}
        for p, k in c.most_common()
    ]


def _bucket_key(frame: Frame, prefix_len: int) -> tuple[str, int]:
    """Bucket frames by (first-N-bytes-hex, length)."""
    p = frame.raw_bytes[:prefix_len]
    return (p.hex(), len(frame.raw_bytes))


def _bucket_offset_stats(frames: list[Frame]) -> list[dict]:
    """
    Per-offset stats for a single bucket (all frames same size).

    Returns a list of dicts, one per offset, with:
        offset, change_rate, distinct_values, entropy_bits, sample_values
    """
    if not frames:
        return []
    size = len(frames[0].raw_bytes)
    out: list[dict] = []
    for off in range(size):
        col = [f.raw_bytes[off] for f in frames]
        # Change rate: fraction of consecutive frames where value differs
        changes = sum(
            1 for a, b in zip(col, col[1:]) if a != b
        )
        change_rate = changes / max(1, len(col) - 1)
        distinct = sorted(set(col))
        out.append({
            "offset":          off,
            "change_rate":     round(change_rate, 4),
            "distinct_values": len(distinct),
            "entropy_bits":    round(_shannon_entropy(col), 4),
            "sample_values":   [f"0x{v:02x}" for v in distinct[:8]],
        })
    return out


def frame_stats(
    frames:         list[Frame],
    prefix_lengths: tuple[int, ...] = (1, 2, 4),
    bucket_prefix_len: int          = 2,
    max_bucket_offsets: int         = 256,
) -> dict:
    """
    Summary stats for a list of frames.

    Returns a dict with:
        frame_count, direction_counts, size_distribution,
        prefix_distributions (per prefix length),
        timestamp_first / timestamp_last,
        buckets: [{prefix_hex, size_bytes, count, per_offset_stats}]

    ``per_offset_stats`` is only emitted for buckets with ≥3 frames (less than
    that gives no signal) and is capped at ``max_bucket_offsets`` per bucket.
    """
    if not frames:
        return {
            "frame_count":          0,
            "direction_counts":     {},
            "size_distribution":    [],
            "prefix_distributions": {},
            "timestamp_first":      None,
            "timestamp_last":       None,
            "buckets":              [],
        }

    dir_counts: Counter = Counter(f.direction.value for f in frames)
    size_counts: Counter = Counter(len(f.raw_bytes) for f in frames)
    size_dist = [
        {"size_bytes": s, "count": c}
        for s, c in sorted(size_counts.items())
    ]
    prefix_dists = {
        n: _prefix_counts(frames, n) for n in prefix_lengths
    }
    times = [f.timestamp for f in frames]

    # Bucketing by (prefix, size)
    grouped: dict[tuple[str, int], list[Frame]] = defaultdict(list)
    for f in frames:
        key = _bucket_key(f, bucket_prefix_len)
        grouped[key].append(f)

    buckets: list[dict] = []
    for (pfx, sz), bucket_frames in sorted(
        grouped.items(), key=lambda kv: -len(kv[1])
    ):
        entry: dict[str, Any] = {
            "prefix_hex": pfx,
            "size_bytes": sz,
            "count":      len(bucket_frames),
        }
        if len(bucket_frames) >= 3:
            stats = _bucket_offset_stats(bucket_frames)
            entry["per_offset_stats"] = stats[:max_bucket_offsets]
            entry["per_offset_stats_truncated"] = len(stats) > max_bucket_offsets
        buckets.append(entry)

    return {
        "frame_count":          len(frames),
        "direction_counts":     dict(dir_counts),
        "size_distribution":    size_dist,
        "prefix_distributions": prefix_dists,
        "timestamp_first":      min(times),
        "timestamp_last":       max(times),
        "buckets":              buckets,
    }


def entropy_map(frames: list[Frame]) -> dict:
    """
    Per-offset Shannon entropy across a bucket of same-size frames.

    Returns ``{size_bytes, frame_count, entropies: [float, ...]}``.  Entropy is
    in bits (0 = constant, 8 = uniform random byte).
    """
    if not frames:
        return {"size_bytes": 0, "frame_count": 0, "entropies": []}
    size = len(frames[0].raw_bytes)
    if any(len(f.raw_bytes) != size for f in frames):
        return {
            "error":      "entropy_map requires all frames to be the same size",
            "frame_count": len(frames),
        }
    entropies = []
    for off in range(size):
        col = [f.raw_bytes[off] for f in frames]
        entropies.append(round(_shannon_entropy(col), 4))
    return {
        "size_bytes":  size,
        "frame_count": len(frames),
        "entropies":   entropies,
    }


def cluster_frames(
    frames:         list[Frame],
    prefix_len:     int = 2,
) -> dict:
    """
    Group frames into shape-buckets ``(prefix_hex, size_bytes)``.

    Cheap auto-discovery of packet types without the caller having to guess
    prefix lengths.  Returns ``{prefix_len, clusters: [{prefix_hex, size_bytes,
    count, first_seq, last_seq, sample_hex}]}``.

    ``sample_hex`` is the hex of the first frame in the cluster (≤64 bytes).
    """
    grouped: dict[tuple[str, int], list[Frame]] = defaultdict(list)
    for f in frames:
        grouped[_bucket_key(f, prefix_len)].append(f)
    clusters = []
    for (pfx, sz), bucket in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
        seqs = [f.sequence_number for f in bucket]
        sample = bucket[0].raw_bytes[:64]
        clusters.append({
            "prefix_hex":  pfx,
            "size_bytes":  sz,
            "count":       len(bucket),
            "first_seq":   min(seqs),
            "last_seq":    max(seqs),
            "sample_hex":  sample.hex(),
        })
    return {"prefix_len": prefix_len, "clusters": clusters}


# ---------------------------------------------------------------------------
# Diffing
# ---------------------------------------------------------------------------

def _hex_grouped(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


def compare_two_frames(frame_a: Frame, frame_b: Frame) -> dict:
    """
    Byte-level diff between two frames.

    Returns:
        size_a, size_b, common_prefix_len, common_suffix_len,
        differences:   [{offset, value_a_hex, value_b_hex, delta_as_int}],
        side_by_side:  list of {offset, a_hex, b_hex, differs} rows (16 bytes each).
    """
    a = frame_a.raw_bytes
    b = frame_b.raw_bytes
    n = max(len(a), len(b))

    differences: list[dict] = []
    # Coalesce runs of differing bytes into ranges
    run_start: Optional[int] = None
    for i in range(n):
        va = a[i] if i < len(a) else None
        vb = b[i] if i < len(b) else None
        differ = (va != vb)
        if differ and run_start is None:
            run_start = i
        elif not differ and run_start is not None:
            _emit_diff(differences, a, b, run_start, i)
            run_start = None
    if run_start is not None:
        _emit_diff(differences, a, b, run_start, n)

    side_by_side: list[dict] = []
    for off in range(0, n, 16):
        a_chunk = a[off:off + 16]
        b_chunk = b[off:off + 16]
        side_by_side.append({
            "offset":  off,
            "a_hex":   _hex_grouped(a_chunk),
            "b_hex":   _hex_grouped(b_chunk),
            "differs": a_chunk != b_chunk,
        })

    # Common prefix / suffix
    prefix = 0
    while prefix < min(len(a), len(b)) and a[prefix] == b[prefix]:
        prefix += 1
    suffix = 0
    while (
        suffix < min(len(a), len(b)) - prefix
        and a[len(a) - 1 - suffix] == b[len(b) - 1 - suffix]
    ):
        suffix += 1

    return {
        "frame_a_id":         frame_a.id,
        "frame_b_id":         frame_b.id,
        "size_a":             len(a),
        "size_b":             len(b),
        "common_prefix_len":  prefix,
        "common_suffix_len":  suffix,
        "differences":        differences,
        "side_by_side":       side_by_side,
    }


def _emit_diff(out: list[dict], a: bytes, b: bytes, start: int, end: int) -> None:
    sub_a = a[start:end]
    sub_b = b[start:end]
    delta: Optional[int] = None
    if len(sub_a) == len(sub_b) and 1 <= len(sub_a) <= 8:
        try:
            ia = int.from_bytes(sub_a, "big", signed=False)
            ib = int.from_bytes(sub_b, "big", signed=False)
            delta = ib - ia
        except Exception:
            delta = None
    out.append({
        "offset":       start,
        "length":       end - start,
        "value_a_hex":  sub_a.hex(),
        "value_b_hex":  sub_b.hex(),
        "delta_as_int": delta,
    })


def diff_bucket(frames: list[Frame], max_offsets: int = 64) -> dict:
    """
    Column-by-column diff matrix across a bucket of same-size frames.

    For each offset where at least one frame differs from the first, emit the
    column of values (one byte per frame).  Cheap way to spot which offsets
    actually carry information in a bucket.

    Returns ``{size_bytes, frame_count, columns: [{offset, values_hex}]}``.
    Columns capped at ``max_offsets`` (most-varying first).
    """
    if not frames:
        return {"size_bytes": 0, "frame_count": 0, "columns": []}
    size = len(frames[0].raw_bytes)
    if any(len(f.raw_bytes) != size for f in frames):
        return {
            "error":      "diff_bucket requires all frames to be the same size",
            "frame_count": len(frames),
        }

    # Rank offsets by distinct-value count (most variation first)
    offsets = []
    for off in range(size):
        col = [f.raw_bytes[off] for f in frames]
        distinct = len(set(col))
        if distinct > 1:
            offsets.append((off, distinct, col))
    offsets.sort(key=lambda t: -t[1])
    offsets = offsets[:max_offsets]
    offsets.sort(key=lambda t: t[0])  # Re-sort for display

    columns = [
        {
            "offset":     off,
            "distinct":   distinct,
            "values_hex": "".join(f"{v:02x}" for v in col),
        }
        for off, distinct, col in offsets
    ]
    return {
        "size_bytes":  size,
        "frame_count": len(frames),
        "columns":     columns,
    }


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

# Type name → (struct format string, size in bytes)
_STRUCT_TYPES: dict[str, tuple[str, int]] = {
    "uint8":      ("B",  1),
    "int8":       ("b",  1),
    "uint16_le":  ("<H", 2),
    "uint16_be":  (">H", 2),
    "int16_le":   ("<h", 2),
    "int16_be":   (">h", 2),
    "uint32_le":  ("<I", 4),
    "uint32_be":  (">I", 4),
    "int32_le":   ("<i", 4),
    "int32_be":   (">i", 4),
    "uint64_le":  ("<Q", 8),
    "uint64_be":  (">Q", 8),
    "int64_le":   ("<q", 8),
    "int64_be":   (">q", 8),
    "float32_le": ("<f", 4),
    "float32_be": (">f", 4),
    "float64_le": ("<d", 8),
    "float64_be": (">d", 8),
}

_NON_STRUCT_TYPES = {"ascii", "bytes", "cstring"}


def supported_field_types() -> list[str]:
    """Return every type name accepted by ``decode_field`` / friends."""
    return sorted(_STRUCT_TYPES) + sorted(_NON_STRUCT_TYPES)


def _decode_one(raw: bytes, type_name: str) -> Any:
    """Decode a single value from raw bytes.  Raises ValueError on bad input."""
    if type_name in _STRUCT_TYPES:
        fmt, size = _STRUCT_TYPES[type_name]
        if len(raw) != size:
            raise ValueError(
                f"type {type_name!r} needs {size} bytes, got {len(raw)}"
            )
        return struct.unpack(fmt, raw)[0]
    if type_name == "ascii":
        return "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
    if type_name == "bytes":
        return raw.hex()
    if type_name == "cstring":
        nul = raw.find(0)
        chunk = raw if nul < 0 else raw[:nul]
        try:
            return chunk.decode("utf-8", errors="replace")
        except Exception:
            return chunk.decode("latin-1", errors="replace")
    raise ValueError(f"Unknown type: {type_name!r}")


def decode_field(
    frames:       list[Frame],
    offset:       int,
    size:         int,
    type_name:    str,
    deduplicate:  bool = False,
    include_timestamps: bool = True,
) -> list[dict]:
    """
    Decode ``type_name`` from ``raw_bytes[offset:offset+size]`` in every frame.

    Frames too short for the offset/size are returned with ``value=None`` and
    ``error="frame too short"``.

    If ``deduplicate`` is True, only emit a row when the decoded value differs
    from the previous emitted row.  Cheap way to surface state changes
    (counters, coordinates, flags) in a long capture.
    """
    if size <= 0:
        raise ValueError("size must be > 0")
    if type_name not in _STRUCT_TYPES and type_name not in _NON_STRUCT_TYPES:
        raise ValueError(
            f"Unknown type {type_name!r}.  Valid: {supported_field_types()}"
        )
    if type_name in _STRUCT_TYPES:
        _, expected = _STRUCT_TYPES[type_name]
        if size != expected:
            raise ValueError(
                f"type {type_name!r} requires size={expected}, got {size}"
            )

    out: list[dict] = []
    _SENTINEL = object()
    last_value: Any = _SENTINEL
    for f in frames:
        row: dict[str, Any] = {
            "frame_id":        f.id,
            "sequence_number": f.sequence_number,
            "direction":       f.direction.value,
        }
        if include_timestamps:
            row["timestamp"] = f.timestamp
        raw = f.raw_bytes[offset:offset + size]
        if len(raw) < size:
            row["value"]    = None
            row["raw_hex"]  = raw.hex()
            row["error"]    = "frame too short"
        else:
            try:
                value = _decode_one(raw, type_name)
            except Exception as exc:
                row["value"]   = None
                row["raw_hex"] = raw.hex()
                row["error"]   = str(exc)
            else:
                row["value"]   = value
                row["raw_hex"] = raw.hex()
        if deduplicate:
            if row.get("value") == last_value:
                continue
            last_value = row.get("value")
        out.append(row)
    return out


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

def _is_printable_ascii(b: int) -> bool:
    return 32 <= b < 127 or b in (0, 9, 10, 13)


def _looks_like_float32(values: list[bytes], byteorder: str) -> bool:
    """A bucket of 4-byte values is float-like if all decode to finite numbers
    with reasonable magnitudes (or are exactly zero)."""
    if not values:
        return False
    fmt = "<f" if byteorder == "little" else ">f"
    finite = 0
    extreme = 0
    nonzero = 0
    for v in values:
        if len(v) != 4:
            return False
        try:
            x = struct.unpack(fmt, v)[0]
        except struct.error:
            return False
        if not math.isfinite(x):
            return False
        finite += 1
        if x != 0.0:
            nonzero += 1
            ax = abs(x)
            if ax < 1e-30 or ax > 1e30:
                extreme += 1
    # If almost everything is zero this is not really a float signal
    if nonzero == 0:
        return False
    return extreme / max(1, finite) < 0.1


def _is_monotonic(values: list[int], tolerance: float = 0.05) -> bool:
    """True if values are (mostly) non-decreasing."""
    if len(values) < 4:
        return False
    decreases = sum(1 for a, b in zip(values, values[1:]) if b < a)
    return decreases / max(1, len(values) - 1) <= tolerance


def analyze_byte_ranges(frames: list[Frame]) -> dict:
    """
    Generic per-offset heuristics across a bucket of same-size frames.

    Returns ``{size_bytes, frame_count, offsets, groups}``.

    ``offsets`` has one entry per offset:
        offset, change_rate, distinct_values, entropy_bits,
        always_zero, always_same_value, looks_like_printable_ascii.

    ``groups`` is a list of contiguous offset ranges where ``change_rate > 0``,
    each annotated with candidate-type guesses (uint8, int8, integer LE/BE in
    1/2/4/8, float32 LE/BE if width matches), plus ``looks_like_length`` (this
    range's value equals ``frame_len - constant``), ``looks_like_counter``
    (monotonic), and ``looks_like_ascii_run``.
    """
    if not frames:
        return {"size_bytes": 0, "frame_count": 0, "offsets": [], "groups": []}
    size = len(frames[0].raw_bytes)
    if any(len(f.raw_bytes) != size for f in frames):
        return {
            "error":      "analyze_byte_ranges requires all frames to be the same size",
            "frame_count": len(frames),
        }

    offset_info: list[dict] = []
    cols: list[list[int]] = []
    for off in range(size):
        col = [f.raw_bytes[off] for f in frames]
        cols.append(col)
        distinct = set(col)
        changes = sum(1 for a, b in zip(col, col[1:]) if a != b)
        change_rate = changes / max(1, len(col) - 1)
        all_same = len(distinct) == 1
        all_zero = all_same and 0 in distinct
        offset_info.append({
            "offset":                       off,
            "change_rate":                  round(change_rate, 4),
            "distinct_values":              len(distinct),
            "entropy_bits":                 round(_shannon_entropy(col), 4),
            "always_zero":                  all_zero,
            "always_same_value":            all_same,
            "always_same_value_hex":        f"0x{col[0]:02x}" if all_same else None,
            "looks_like_printable_ascii":   all(_is_printable_ascii(b) for b in col),
        })

    # Group contiguous offsets where change_rate > 0
    groups: list[dict] = []
    run_start: Optional[int] = None
    for off in range(size):
        if offset_info[off]["change_rate"] > 0:
            if run_start is None:
                run_start = off
        else:
            if run_start is not None:
                groups.append(_score_group(frames, cols, run_start, off, size))
                run_start = None
    if run_start is not None:
        groups.append(_score_group(frames, cols, run_start, size, size))

    return {
        "size_bytes":  size,
        "frame_count": len(frames),
        "offsets":     offset_info,
        "groups":      groups,
    }


def _score_group(
    frames:    list[Frame],
    cols:      list[list[int]],
    start:     int,
    end:       int,
    frame_size: int,
) -> dict:
    """Score a contiguous range of offsets ``[start, end)`` for likely types."""
    width = end - start
    n = len(frames)
    # Slice the raw byte runs out of every frame
    sub = [f.raw_bytes[start:end] for f in frames]

    # ASCII run
    flat_bytes = b"".join(sub)
    ascii_ratio = (
        sum(1 for b in flat_bytes if _is_printable_ascii(b))
        / max(1, len(flat_bytes))
    )

    candidates: list[dict] = []

    if width == 1:
        ints_u = [s[0] for s in sub]
        ints_s = [struct.unpack("b", s)[0] for s in sub]
        candidates.append({
            "type":         "uint8",
            "min":          min(ints_u),
            "max":          max(ints_u),
            "distinct":     len(set(ints_u)),
        })
        candidates.append({
            "type":         "int8",
            "min":          min(ints_s),
            "max":          max(ints_s),
            "distinct":     len(set(ints_s)),
        })

    for w, fmt_u_le, fmt_u_be, fmt_s_le, fmt_s_be in (
        (2, "<H", ">H", "<h", ">h"),
        (4, "<I", ">I", "<i", ">i"),
        (8, "<Q", ">Q", "<q", ">q"),
    ):
        if width != w:
            continue
        for label, fmt in (
            (f"uint{w*8}_le", fmt_u_le),
            (f"uint{w*8}_be", fmt_u_be),
            (f"int{w*8}_le",  fmt_s_le),
            (f"int{w*8}_be",  fmt_s_be),
        ):
            try:
                vals = [struct.unpack(fmt, s)[0] for s in sub]
            except struct.error:
                continue
            candidates.append({
                "type":     label,
                "min":      min(vals),
                "max":      max(vals),
                "distinct": len(set(vals)),
            })

    # Float candidates (32-bit and 64-bit if widths match)
    floatlike_le = False
    floatlike_be = False
    if width == 4:
        floatlike_le = _looks_like_float32(sub, "little")
        floatlike_be = _looks_like_float32(sub, "big")
        if floatlike_le or floatlike_be:
            candidates.append({
                "type":       "float32_le",
                "plausible":  floatlike_le,
            })
            candidates.append({
                "type":       "float32_be",
                "plausible":  floatlike_be,
            })

    # Length-field heuristic: width 1/2/4 — value == frame_size - constant
    _UINT_FMTS = {1: ("B", "B"), 2: ("<H", ">H"), 4: ("<I", ">I")}
    looks_like_length: Optional[dict] = None
    if width in _UINT_FMTS:
        le_fmt, be_fmt = _UINT_FMTS[width]
        for fmt, bo, label in (
            (le_fmt, "little", f"uint{width*8}_le"),
            (be_fmt, "big",    f"uint{width*8}_be"),
        ):
            try:
                vals = [struct.unpack(fmt, s)[0] for s in sub]
            except struct.error:
                continue
            deltas = [frame_size - v for v in vals]
            if len(set(deltas)) == 1:
                looks_like_length = {
                    "type":          label,
                    "constant":      deltas[0],
                    "interpretation":
                        f"value == frame_size - {deltas[0]} for all frames",
                }
                break
            if width == 1:
                # Endianness doesn't matter for 1-byte ints; skip BE pass
                break

    # Monotonic-counter heuristic on the unsigned big-endian view
    looks_like_counter: Optional[dict] = None
    try:
        big_vals = [int.from_bytes(s, "big", signed=False) for s in sub]
        if _is_monotonic(big_vals):
            looks_like_counter = {
                "byteorder": "big",
                "first":     big_vals[0],
                "last":      big_vals[-1],
            }
        else:
            le_vals = [int.from_bytes(s, "little", signed=False) for s in sub]
            if _is_monotonic(le_vals):
                looks_like_counter = {
                    "byteorder": "little",
                    "first":     le_vals[0],
                    "last":      le_vals[-1],
                }
    except Exception:
        pass

    return {
        "offset_start":          start,
        "offset_end":            end,
        "width":                 width,
        "ascii_ratio":           round(ascii_ratio, 3),
        "looks_like_ascii_run":  ascii_ratio >= 0.8,
        "candidate_types":       candidates,
        "looks_like_length":     looks_like_length,
        "looks_like_counter":    looks_like_counter,
    }


def find_length_field_candidates(frames: list[Frame]) -> dict:
    """
    For every plausible offset / width / byteorder combination, check whether
    the integer value at that offset equals ``len(frame) + constant`` for the
    SAME constant across every frame in the bucket.

    This works across mixed-size frames (which is the whole point — most
    binary protocols have a length field that explains the variation).  Frames
    too short for a given offset are skipped per-candidate.

    Returns ``{frame_count, candidates: [{offset, width, byteorder, signed,
    constant, interpretation}]}``, sorted by lowest offset first.
    """
    if len(frames) < 2:
        return {"frame_count": len(frames), "candidates": []}

    min_size = min(len(f.raw_bytes) for f in frames)
    candidates: list[dict] = []
    for off in range(min_size):
        for width, le_fmt, be_fmt in (
            (1, "B",  "B"),
            (2, "<H", ">H"),
            (4, "<I", ">I"),
        ):
            if off + width > min_size:
                continue
            for fmt, bo in ((le_fmt, "little"), (be_fmt, "big")):
                deltas: set[int] = set()
                ok = True
                for f in frames:
                    raw = f.raw_bytes[off:off + width]
                    if len(raw) != width:
                        ok = False
                        break
                    try:
                        v = struct.unpack(fmt, raw)[0]
                    except struct.error:
                        ok = False
                        break
                    deltas.add(len(f.raw_bytes) - v)
                    if len(deltas) > 1:
                        ok = False
                        break
                if ok and len(deltas) == 1:
                    constant = next(iter(deltas))
                    # Skip the trivial "value is always frame_size - 0
                    # constant for both byteorders on a 1-byte field" case
                    # when the value is just byte == frame_size — width 1
                    # gives the same answer LE or BE; emit only once.
                    if width == 1 and bo == "big":
                        continue
                    candidates.append({
                        "offset":         off,
                        "width":          width,
                        "byteorder":      bo,
                        "constant":       constant,
                        "interpretation":
                            f"uint{width*8} at offset {off} ({bo}-endian) "
                            f"== len(frame) - {constant}",
                    })
    return {"frame_count": len(frames), "candidates": candidates}


def offset_correlations(
    frames:    list[Frame],
    offset_a:  int,
    offset_b:  int,
    type_a:    str = "uint8",
    type_b:    str = "uint8",
) -> dict:
    """
    Do values at two offsets move together?

    Computes Pearson correlation between the decoded integer/float series at
    ``offset_a`` and ``offset_b``.  Useful for detecting paired fields (e.g.
    pairs of coordinates, parallel counters, related flags) without baking in
    domain assumptions.

    Returns ``{frame_count, type_a, type_b, pearson_r, n_used, change_pairing}``
    where ``change_pairing`` is the fraction of consecutive frames where A and
    B BOTH changed or BOTH stayed the same (high values → tightly coupled).
    """
    if type_a not in _STRUCT_TYPES:
        raise ValueError(f"offset_correlations requires numeric types; got type_a={type_a}")
    if type_b not in _STRUCT_TYPES:
        raise ValueError(f"offset_correlations requires numeric types; got type_b={type_b}")
    fmt_a, size_a = _STRUCT_TYPES[type_a]
    fmt_b, size_b = _STRUCT_TYPES[type_b]

    xs: list[float] = []
    ys: list[float] = []
    for f in frames:
        ra = f.raw_bytes[offset_a:offset_a + size_a]
        rb = f.raw_bytes[offset_b:offset_b + size_b]
        if len(ra) != size_a or len(rb) != size_b:
            continue
        try:
            xs.append(float(struct.unpack(fmt_a, ra)[0]))
            ys.append(float(struct.unpack(fmt_b, rb)[0]))
        except struct.error:
            continue

    n = len(xs)
    if n < 2:
        return {
            "frame_count":    len(frames),
            "n_used":         n,
            "pearson_r":      None,
            "change_pairing": None,
            "reason":         "not enough usable samples",
        }

    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    dy = math.sqrt(sum((y - my) ** 2 for y in ys))
    r: Optional[float]
    if dx == 0 or dy == 0:
        r = None
    else:
        r = round(num / (dx * dy), 4)

    paired = 0
    for i in range(1, n):
        a_change = xs[i] != xs[i - 1]
        b_change = ys[i] != ys[i - 1]
        if a_change == b_change:
            paired += 1
    pairing = paired / max(1, n - 1)

    return {
        "frame_count":    len(frames),
        "n_used":         n,
        "type_a":         type_a,
        "type_b":         type_b,
        "pearson_r":      r,
        "change_pairing": round(pairing, 4),
    }


# ---------------------------------------------------------------------------
# Structure discovery
# ---------------------------------------------------------------------------

def find_constant_byte_sequences(
    frames:       list[Frame],
    min_length:   int   = 2,
    max_length:   int   = 8,
    min_coverage: float = 0.8,
    max_results:  int   = 50,
) -> dict:
    """
    Find byte n-grams that appear in at least ``min_coverage`` of the frames,
    regardless of offset.  Surfaces magic markers, version stamps, trailers,
    and recurring substrings that constant-offset stats miss.

    For each length in ``[min_length, max_length]``, every distinct n-gram is
    counted by the number of *frames* containing it (not by occurrences), then
    filtered against ``min_coverage``.  Results are de-duplicated to suppress
    strict substrings of a longer hit at the same or higher coverage — the
    longest distinct pattern wins.

    Returns ``{frame_count, sequences: [{hex, length, frame_count, coverage,
    sample_offsets: [{frame_id, offsets}]}, ...]}``.  Sorted by
    ``(length desc, coverage desc)`` and capped at ``max_results``.
    """
    n = len(frames)
    if n == 0 or min_length < 1 or max_length < min_length:
        return {"frame_count": n, "sequences": []}

    threshold = max(1, math.ceil(min_coverage * n))

    # Map n-gram bytes -> set of frame IDs containing it
    ngram_frames: dict[bytes, set[str]] = defaultdict(set)
    for f in frames:
        raw = f.raw_bytes
        L = len(raw)
        seen_in_frame: set[bytes] = set()
        for length in range(min_length, max_length + 1):
            if length > L:
                break
            for i in range(L - length + 1):
                ng = raw[i:i + length]
                if ng not in seen_in_frame:
                    seen_in_frame.add(ng)
                    ngram_frames[ng].add(f.id)

    # Keep only those above threshold
    hits: list[tuple[bytes, int]] = [
        (ng, len(fids)) for ng, fids in ngram_frames.items()
        if len(fids) >= threshold
    ]

    # Suppress strict substrings of longer hits with same coverage
    by_len: dict[int, list[tuple[bytes, int]]] = defaultdict(list)
    for ng, cnt in hits:
        by_len[len(ng)].append((ng, cnt))
    suppressed: set[bytes] = set()
    lengths_desc = sorted(by_len, reverse=True)
    for i, L in enumerate(lengths_desc):
        for ng, cnt in by_len[L]:
            # If any shorter ng' is a substring of ng with the same coverage,
            # mark ng' for suppression.
            for shorter_L in lengths_desc[i+1:]:
                for ng2, cnt2 in by_len[shorter_L]:
                    if cnt2 == cnt and ng2 in ng:
                        suppressed.add(ng2)

    surviving = [(ng, cnt) for ng, cnt in hits if ng not in suppressed]
    surviving.sort(key=lambda t: (-len(t[0]), -t[1], t[0]))
    surviving = surviving[:max_results]

    sequences: list[dict] = []
    for ng, cnt in surviving:
        # Sample up to 3 frames + first offsets each
        sample_offsets: list[dict] = []
        for f in frames:
            raw = f.raw_bytes
            offsets = []
            start = 0
            while True:
                idx = raw.find(ng, start)
                if idx < 0:
                    break
                offsets.append(idx)
                start = idx + 1
                if len(offsets) >= 4:
                    break
            if offsets:
                sample_offsets.append({"frame_id": f.id, "offsets": offsets})
            if len(sample_offsets) >= 3:
                break
        sequences.append({
            "hex":            ng.hex(),
            "length":         len(ng),
            "frame_count":    cnt,
            "coverage":       round(cnt / n, 4),
            "sample_offsets": sample_offsets,
        })

    return {"frame_count": n, "sequences": sequences}


def _needleman_wunsch(
    a: bytes,
    b: bytes,
    match:    int = 1,
    mismatch: int = -1,
    gap:      int = -2,
) -> tuple[list[Optional[int]], list[Optional[int]]]:
    """
    Classic Needleman-Wunsch global alignment.  Returns two lists the same
    length, each element either an integer byte value or ``None`` for a gap.
    """
    na, nb = len(a), len(b)
    if na == 0 and nb == 0:
        return [], []
    # Score matrix
    H = [[0] * (nb + 1) for _ in range(na + 1)]
    for i in range(1, na + 1):
        H[i][0] = i * gap
    for j in range(1, nb + 1):
        H[0][j] = j * gap
    for i in range(1, na + 1):
        for j in range(1, nb + 1):
            diag = H[i-1][j-1] + (match if a[i-1] == b[j-1] else mismatch)
            up   = H[i-1][j] + gap
            left = H[i][j-1] + gap
            H[i][j] = max(diag, up, left)
    # Trace back
    out_a: list[Optional[int]] = []
    out_b: list[Optional[int]] = []
    i, j = na, nb
    while i > 0 or j > 0:
        if i > 0 and j > 0:
            score = H[i][j]
            diag = H[i-1][j-1] + (match if a[i-1] == b[j-1] else mismatch)
            if score == diag:
                out_a.append(a[i-1]); out_b.append(b[j-1])
                i -= 1; j -= 1
                continue
        if i > 0 and (j == 0 or H[i][j] == H[i-1][j] + gap):
            out_a.append(a[i-1]); out_b.append(None)
            i -= 1
        else:
            out_a.append(None); out_b.append(b[j-1])
            j -= 1
    out_a.reverse(); out_b.reverse()
    return out_a, out_b


def align_frames(
    frames:         list[Frame],
    max_frames:     int = 20,
    max_frame_size: int = 512,
) -> dict:
    """
    Needleman-Wunsch alignment of mixed-size frames against the first frame.

    Draws field boundaries even when prefixes shift — for clusters that share
    structure but have different lengths.  Cost is ``O(n*m)`` per pair, so
    inputs are capped: at most ``max_frames`` frames, each truncated to
    ``max_frame_size`` bytes for the alignment (the original raw bytes are
    not modified).

    Returns:
        {
          "frame_count": N (after capping),
          "alignment_length": K,
          "rows": [{frame_id, aligned}],  # aligned is a string of "xx" or "--"
          "consensus": "xx-?xx",           # "xx" if all rows agree, "??" if differ, "--" if any gap
          "variable_regions": [{start, end, kind: "differ"|"gap"}],
        }
    """
    if not frames:
        return {
            "frame_count": 0, "alignment_length": 0,
            "rows": [], "consensus": "", "variable_regions": [],
        }
    selected = frames[:max_frames]
    trimmed = [f.raw_bytes[:max_frame_size] for f in selected]

    anchor = trimmed[0]
    # Each row is a list of Optional[int]
    rows: list[list[Optional[int]]] = []
    # The anchor row is built up as we merge: track which columns belong to it.
    # We'll do a simple progressive scheme:
    #   - Start with anchor as-is, no gaps.
    #   - For each subsequent frame, align it to the *current* anchor row,
    #     and where the alignment inserts a gap into the anchor, insert a
    #     gap into all previously-aligned rows at that column too.
    anchor_row: list[Optional[int]] = [int(b) for b in anchor]
    rows.append(list(anchor_row))

    def _align_and_merge(prev_anchor: list[Optional[int]], new_seq: bytes):
        # Build a "compact" view of the anchor (skipping gaps from prior merges)
        compact = bytes(b for b in prev_anchor if b is not None)
        col_of: list[int] = [
            col for col, b in enumerate(prev_anchor) if b is not None
        ]
        aligned_a, aligned_b = _needleman_wunsch(compact, new_seq)

        new_rows: list[list[Optional[int]]] = [[] for _ in rows]
        new_anchor: list[Optional[int]] = []
        new_seq_row: list[Optional[int]] = []

        prev_col = 0  # next un-emitted column of prev_anchor
        comp_i = 0    # next un-emitted compact position
        for a_val, b_val in zip(aligned_a, aligned_b):
            if a_val is None:
                # Before emitting a gap inserted in compact, emit any
                # pre-existing gap columns in prev_anchor that lie before
                # the next compact position so they aren't lost.
                target_col = col_of[comp_i] if comp_i < len(col_of) else len(prev_anchor)
                while prev_col < target_col:
                    # prev_anchor[prev_col] is None here by construction
                    for r_idx, prev_row in enumerate(rows):
                        new_rows[r_idx].append(prev_row[prev_col])
                    new_anchor.append(prev_anchor[prev_col])
                    new_seq_row.append(None)
                    prev_col += 1
                # Now the actual gap inserted in compact by NW:
                for r_idx in range(len(rows)):
                    new_rows[r_idx].append(None)
                new_anchor.append(None)
                new_seq_row.append(b_val)
            else:
                target_col = col_of[comp_i]
                # Emit any pre-existing gap columns in prev_anchor first
                while prev_col < target_col:
                    for r_idx, prev_row in enumerate(rows):
                        new_rows[r_idx].append(prev_row[prev_col])
                    new_anchor.append(prev_anchor[prev_col])
                    new_seq_row.append(None)
                    prev_col += 1
                # Then the matching column itself
                for r_idx, prev_row in enumerate(rows):
                    new_rows[r_idx].append(prev_row[target_col])
                new_anchor.append(a_val)
                new_seq_row.append(b_val)
                prev_col = target_col + 1
                comp_i += 1
        # Tail: any remaining gap columns in prev_anchor past the last
        # compact position
        while prev_col < len(prev_anchor):
            for r_idx, prev_row in enumerate(rows):
                new_rows[r_idx].append(prev_row[prev_col])
            new_anchor.append(prev_anchor[prev_col])
            new_seq_row.append(None)
            prev_col += 1

        new_rows.append(new_seq_row)
        return new_anchor, new_rows

    for seq in trimmed[1:]:
        anchor_row, rows = _align_and_merge(anchor_row, seq)

    K = len(anchor_row)
    # Build consensus + variable regions
    consensus_tokens: list[str] = []
    region_kinds: list[Optional[str]] = []  # "differ", "gap", or None
    for col in range(K):
        col_vals = [row[col] for row in rows]
        if any(v is None for v in col_vals):
            if all(v is None for v in col_vals):
                consensus_tokens.append("--")
                region_kinds.append(None)
            else:
                consensus_tokens.append("--")
                region_kinds.append("gap")
        else:
            unique = set(col_vals)
            if len(unique) == 1:
                consensus_tokens.append(f"{col_vals[0]:02x}")
                region_kinds.append(None)
            else:
                consensus_tokens.append("??")
                region_kinds.append("differ")

    # Coalesce variable regions
    variable_regions: list[dict] = []
    run_start: Optional[int] = None
    run_kind: Optional[str] = None
    for col, kind in enumerate(region_kinds):
        if kind is None:
            if run_start is not None:
                variable_regions.append({
                    "start": run_start, "end": col, "kind": run_kind,
                })
                run_start, run_kind = None, None
        else:
            if run_start is None:
                run_start = col
                run_kind = kind
            elif run_kind != kind:
                variable_regions.append({
                    "start": run_start, "end": col, "kind": run_kind,
                })
                run_start = col
                run_kind = kind
    if run_start is not None:
        variable_regions.append({
            "start": run_start, "end": K, "kind": run_kind,
        })

    aligned_rows: list[dict] = []
    for f, row in zip(selected, rows):
        tokens = [("--" if v is None else f"{v:02x}") for v in row]
        aligned_rows.append({
            "frame_id": f.id,
            "aligned":  " ".join(tokens),
        })

    return {
        "frame_count":      len(selected),
        "alignment_length": K,
        "rows":             aligned_rows,
        "consensus":        " ".join(consensus_tokens),
        "variable_regions": variable_regions,
    }


def extract_strings(
    frames:       list[Frame],
    min_length:   int = 4,
    max_per_frame: int = 50,
    include_utf16_le: bool = False,
) -> dict:
    """
    Find printable-ASCII runs of length ≥ ``min_length`` in every frame
    (``strings(1)`` for captured frames).  Stops a run at NUL or any other
    non-printable byte.

    If ``include_utf16_le`` is True, also reports runs of UTF-16-LE-encoded
    ASCII (printable ASCII bytes interleaved with NUL bytes), which is what
    Windows protocols often look like.

    Returns ``{frame_count, total_strings, strings: [{frame_id, offset,
    length, value, encoding}, ...]}``.  Capped at ``max_per_frame`` results
    per frame to bound output size.
    """
    n = len(frames)
    if min_length < 1:
        raise ValueError("min_length must be >= 1")
    out: list[dict] = []
    total = 0
    for f in frames:
        raw = f.raw_bytes
        found_in_frame = 0
        # ASCII runs
        i = 0
        while i < len(raw) and found_in_frame < max_per_frame:
            if _is_printable_ascii(raw[i]) and raw[i] != 0:
                start = i
                while (i < len(raw) and _is_printable_ascii(raw[i])
                       and raw[i] != 0 and raw[i] not in (9, 10, 13)):
                    i += 1
                if i - start >= min_length:
                    out.append({
                        "frame_id": f.id,
                        "offset":   start,
                        "length":   i - start,
                        "value":    raw[start:i].decode("ascii", errors="replace"),
                        "encoding": "ascii",
                    })
                    found_in_frame += 1
                    total += 1
            else:
                i += 1
        # UTF-16 LE: printable ASCII byte followed by 0x00
        if include_utf16_le and found_in_frame < max_per_frame:
            i = 0
            while i + 1 < len(raw) and found_in_frame < max_per_frame:
                if (_is_printable_ascii(raw[i]) and raw[i] != 0
                        and raw[i+1] == 0):
                    start = i
                    chars: list[int] = []
                    while (i + 1 < len(raw)
                           and _is_printable_ascii(raw[i]) and raw[i] != 0
                           and raw[i+1] == 0
                           and raw[i] not in (9, 10, 13)):
                        chars.append(raw[i])
                        i += 2
                    if len(chars) >= min_length:
                        out.append({
                            "frame_id": f.id,
                            "offset":   start,
                            "length":   i - start,
                            "value":    bytes(chars).decode("ascii", errors="replace"),
                            "encoding": "utf-16-le",
                        })
                        found_in_frame += 1
                        total += 1
                else:
                    i += 1
    return {
        "frame_count":   n,
        "total_strings": total,
        "strings":       out,
    }


# Type/length width combinations to try for TLV detection
_TLV_SHAPES: tuple[tuple[int, int, str, bool], ...] = (
    # (type_width, length_width, length_byteorder, length_includes_header)
    (1, 1, "big",    False),
    (1, 1, "big",    True),
    (1, 2, "big",    False), (1, 2, "big",    True),
    (1, 2, "little", False), (1, 2, "little", True),
    (1, 4, "big",    False), (1, 4, "big",    True),
    (1, 4, "little", False), (1, 4, "little", True),
    (2, 1, "big",    False), (2, 1, "big",    True),
    (2, 2, "big",    False), (2, 2, "big",    True),
    (2, 2, "little", False), (2, 2, "little", True),
    (2, 4, "big",    False), (2, 4, "big",    True),
    (2, 4, "little", False), (2, 4, "little", True),
)


def _try_tlv_walk(
    raw:             bytes,
    start:           int,
    type_width:      int,
    length_width:    int,
    length_byteorder: str,
    length_includes_header: bool,
    max_records:     int = 64,
) -> Optional[list[tuple[int, int, int]]]:
    """
    Walk a TLV chain.  Returns a list of ``(type, length, record_end)``
    tuples if the walk consumed bytes without overrunning, otherwise None.
    Stops at ``max_records`` records or when the buffer is exhausted.
    """
    out: list[tuple[int, int, int]] = []
    pos = start
    L = len(raw)
    header_len = type_width + length_width
    while pos < L and len(out) < max_records:
        if pos + header_len > L:
            return None
        t = int.from_bytes(raw[pos:pos + type_width], length_byteorder, signed=False)
        lv = int.from_bytes(
            raw[pos + type_width:pos + header_len], length_byteorder, signed=False
        )
        if length_includes_header:
            value_len = lv - header_len
        else:
            value_len = lv
        if value_len < 0:
            return None
        record_end = pos + header_len + value_len
        if record_end > L:
            return None
        out.append((t, lv, record_end))
        pos = record_end
    return out


def detect_tlv(
    frames:        list[Frame],
    start_offsets: tuple[int, ...] = (0,),
    min_records:   int   = 2,
    min_coverage:  float = 0.6,
    max_results:   int   = 10,
) -> dict:
    """
    Try Type-Length-Value layouts and score how well each one explains the
    captured frames.

    For every combination of ``(type_width, length_width, length_byteorder,
    length_includes_header)`` and every starting offset in ``start_offsets``,
    walk the frame chain.  A frame "matches" a shape if the walk consumes
    the entire buffer (no leftover bytes) and produces at least
    ``min_records`` records.  Shapes that match in at least ``min_coverage``
    of frames are reported.

    Returns ``{frame_count, candidates: [{type_width, length_width,
    length_byteorder, length_includes_header, start_offset, coverage,
    matched_frames, avg_records, common_types: [{type_hex, count}]}, ...]}``
    sorted by ``coverage desc, avg_records desc``.
    """
    n = len(frames)
    if n == 0:
        return {"frame_count": 0, "candidates": []}
    threshold = max(1, math.ceil(min_coverage * n))

    results: list[dict] = []
    for start in start_offsets:
        for tw, lw, bo, inc in _TLV_SHAPES:
            type_counts: Counter = Counter()
            matched = 0
            total_records = 0
            for f in frames:
                walk = _try_tlv_walk(f.raw_bytes, start, tw, lw, bo, inc)
                if walk is None:
                    continue
                if len(walk) < min_records:
                    continue
                # Require the walk to consume the rest of the frame
                final_end = walk[-1][2]
                if final_end != len(f.raw_bytes):
                    continue
                matched += 1
                total_records += len(walk)
                for (t, _lv, _re) in walk:
                    type_counts[t] += 1
            if matched < threshold:
                continue
            avg = total_records / matched if matched else 0.0
            common = [
                {"type_hex": t.to_bytes(tw, bo).hex(), "count": c}
                for t, c in type_counts.most_common(8)
            ]
            results.append({
                "type_width":              tw,
                "length_width":            lw,
                "length_byteorder":        bo,
                "length_includes_header":  inc,
                "start_offset":            start,
                "coverage":                round(matched / n, 4),
                "matched_frames":          matched,
                "avg_records":             round(avg, 2),
                "common_types":            common,
            })

    results.sort(key=lambda r: (-r["coverage"], -r["avg_records"]))
    return {"frame_count": n, "candidates": results[:max_results]}


# ---------------------------------------------------------------------------
# Semantic field detection
# ---------------------------------------------------------------------------

def _sum8(data: bytes) -> int:
    return sum(data) & 0xFF


def _sum16(data: bytes) -> int:
    return sum(data) & 0xFFFF


def _xor8(data: bytes) -> int:
    out = 0
    for b in data:
        out ^= b
    return out


def _fletcher16(data: bytes) -> int:
    sum1 = 0
    sum2 = 0
    for b in data:
        sum1 = (sum1 + b) % 255
        sum2 = (sum2 + sum1) % 255
    return (sum2 << 8) | sum1


def _crc16_ccitt_ffff(data: bytes) -> int:
    return binascii.crc_hqx(data, 0xFFFF)


def _crc16_xmodem(data: bytes) -> int:
    return binascii.crc_hqx(data, 0x0000)


def _crc32_ieee(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def _adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


# Algorithm registry: name -> (width_bytes, fn(bytes)->int)
_CHECKSUM_ALGORITHMS: dict[str, tuple[int, Any]] = {
    "sum8":         (1, _sum8),
    "xor8":         (1, _xor8),
    "sum16":        (2, _sum16),
    "fletcher16":   (2, _fletcher16),
    "crc16_ccitt":  (2, _crc16_ccitt_ffff),
    "crc16_xmodem": (2, _crc16_xmodem),
    "crc32_ieee":   (4, _crc32_ieee),
    "adler32":      (4, _adler32),
}


def detect_checksums_crcs(
    frames:       list[Frame],
    min_coverage: float = 0.9,
    max_results:  int   = 20,
) -> dict:
    """
    Try standard checksum / CRC / Adler / Fletcher algorithms over each
    frame and report which ``(offset, algorithm, byteorder, coverage)``
    matches across most frames.

    For each candidate offset and each algorithm (matched on its native
    width), the algorithm is computed over the frame's bytes *excluding*
    the candidate field.  If the stored value equals the computed value
    in at least ``min_coverage`` of frames, the candidate is reported.

    For multi-byte algorithms, both little-endian and big-endian
    interpretations are tried.

    Returns ``{frame_count, candidates: [{offset, width, algorithm,
    byteorder, coverage, matched_frames}, ...]}`` sorted by coverage.
    """
    n = len(frames)
    if n < 2:
        return {"frame_count": n, "candidates": []}
    threshold = max(1, math.ceil(min_coverage * n))
    min_size = min(len(f.raw_bytes) for f in frames)

    candidates: list[dict] = []
    seen: set[tuple[int, str, str]] = set()

    for offset in range(min_size):
        for algo_name, (width, fn) in _CHECKSUM_ALGORITHMS.items():
            if offset + width > min_size:
                continue
            for bo in (("big",) if width == 1 else ("big", "little")):
                key = (offset, algo_name, bo)
                if key in seen:
                    continue
                seen.add(key)
                matched = 0
                checked = 0
                for f in frames:
                    raw = f.raw_bytes
                    if offset + width > len(raw):
                        continue
                    checked += 1
                    stored = int.from_bytes(raw[offset:offset + width], bo, signed=False)
                    rest = raw[:offset] + raw[offset + width:]
                    try:
                        computed = fn(rest)
                    except Exception:
                        break
                    if stored == computed:
                        matched += 1
                if checked == 0:
                    continue
                coverage = matched / checked
                if matched < threshold:
                    continue
                candidates.append({
                    "offset":        offset,
                    "width":         width,
                    "algorithm":     algo_name,
                    "byteorder":     bo,
                    "coverage":      round(coverage, 4),
                    "matched_frames": matched,
                })

    candidates.sort(key=lambda c: (-c["coverage"], c["offset"]))
    return {"frame_count": n, "candidates": candidates[:max_results]}


# Plausible timestamp ranges (uint integer values)
# Unix epoch seconds: roughly year 2000 .. year 2100
_UNIX_SEC_MIN = 946_684_800       # 2000-01-01
_UNIX_SEC_MAX = 4_102_444_800     # 2100-01-01
# Unix epoch milliseconds
_UNIX_MS_MIN  = _UNIX_SEC_MIN * 1000
_UNIX_MS_MAX  = _UNIX_SEC_MAX * 1000
# NTP timestamp (seconds since 1900-01-01)
_NTP_SEC_OFFSET = 2_208_988_800
_NTP_SEC_MIN  = _UNIX_SEC_MIN + _NTP_SEC_OFFSET
_NTP_SEC_MAX  = _UNIX_SEC_MAX + _NTP_SEC_OFFSET
# Windows FILETIME (100ns since 1601-01-01) — uint64 only
_FILETIME_MIN = 125_911_584_000_000_000   # ~2000-01-01
_FILETIME_MAX = 137_945_088_000_000_000   # ~2100-01-01


_EPOCH_RANGES: tuple[tuple[str, int, int, tuple[int, ...]], ...] = (
    ("unix_seconds",       _UNIX_SEC_MIN,  _UNIX_SEC_MAX,  (4, 8)),
    ("unix_milliseconds",  _UNIX_MS_MIN,   _UNIX_MS_MAX,   (8,)),
    ("ntp_seconds",        _NTP_SEC_MIN,   _NTP_SEC_MAX,   (4, 8)),
    ("windows_filetime",   _FILETIME_MIN,  _FILETIME_MAX,  (8,)),
)


def detect_timestamps(
    frames:       list[Frame],
    min_coverage: float = 0.8,
    max_results:  int   = 20,
) -> dict:
    """
    Find offsets whose decoded unsigned integer value lies in a plausible
    real-world timestamp range across most frames.

    For each ``(offset, width in {4, 8}, byteorder in {little, big})``
    candidate and each known epoch range (unix_seconds, unix_milliseconds,
    ntp_seconds, windows_filetime), check the fraction of frames where the
    decoded value falls inside that range.  If the fraction is at least
    ``min_coverage``, the candidate is reported with the Pearson correlation
    between the decoded value and the frame's capture timestamp (a value
    near 1.0 confirms it's a real timestamp, not just an integer that
    happens to fall in range).

    Returns ``{frame_count, candidates: [{offset, width, byteorder, epoch,
    coverage, matched_frames, pearson_r_with_capture_time, first_value,
    last_value}, ...]}`` sorted by coverage then correlation.
    """
    n = len(frames)
    if n < 2:
        return {"frame_count": n, "candidates": []}
    threshold = max(1, math.ceil(min_coverage * n))
    min_size = min(len(f.raw_bytes) for f in frames)

    candidates: list[dict] = []
    for offset in range(min_size):
        for width in (4, 8):
            if offset + width > min_size:
                continue
            for bo in ("little", "big"):
                values: list[int] = []
                for f in frames:
                    raw = f.raw_bytes
                    if offset + width > len(raw):
                        continue
                    values.append(int.from_bytes(raw[offset:offset+width], bo, signed=False))
                if len(values) < 2:
                    continue
                for epoch_name, lo, hi, allowed_widths in _EPOCH_RANGES:
                    if width not in allowed_widths:
                        continue
                    in_range = sum(1 for v in values if lo <= v <= hi)
                    if in_range < threshold:
                        continue
                    # Correlate value with frame.timestamp
                    times = [f.timestamp for f in frames
                             if offset + width <= len(f.raw_bytes)]
                    if len(times) < 2 or len(set(values)) < 2 or len(set(times)) < 2:
                        r: Optional[float] = None
                    else:
                        mv = sum(values) / len(values)
                        mt = sum(times) / len(times)
                        num = sum((v - mv) * (t - mt) for v, t in zip(values, times))
                        dv = math.sqrt(sum((v - mv) ** 2 for v in values))
                        dt = math.sqrt(sum((t - mt) ** 2 for t in times))
                        r = round(num / (dv * dt), 4) if dv > 0 and dt > 0 else None
                    candidates.append({
                        "offset":         offset,
                        "width":          width,
                        "byteorder":      bo,
                        "epoch":          epoch_name,
                        "coverage":       round(in_range / len(values), 4),
                        "matched_frames": in_range,
                        "pearson_r_with_capture_time": r,
                        "first_value":    values[0],
                        "last_value":     values[-1],
                    })

    candidates.sort(key=lambda c: (
        -c["coverage"],
        -(c["pearson_r_with_capture_time"] or -2.0),
    ))
    return {"frame_count": n, "candidates": candidates[:max_results]}


# Known file/stream magic signatures
_KNOWN_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("gzip",      b"\x1f\x8b"),
    ("zlib",      b"\x78\x01"),
    ("zlib",      b"\x78\x5e"),
    ("zlib",      b"\x78\x9c"),
    ("zlib",      b"\x78\xda"),
    ("bzip2",     b"BZh"),
    ("xz",        b"\xfd7zXZ\x00"),
    ("lz4_frame", b"\x04\x22\x4d\x18"),
    ("zstd",      b"\x28\xb5\x2f\xfd"),
    ("7z",        b"\x37\x7a\xbc\xaf\x27\x1c"),
    ("zip",       b"PK\x03\x04"),
    ("rar",       b"Rar!"),
    ("png",       b"\x89PNG\r\n\x1a\n"),
    ("jpeg",      b"\xff\xd8\xff"),
    ("gif",       b"GIF89a"),
    ("gif",       b"GIF87a"),
    ("pdf",       b"%PDF"),
    ("elf",       b"\x7fELF"),
    ("pe_dos",    b"MZ"),
    ("der_seq",   b"\x30\x82"),       # ASN.1 SEQUENCE with 2-byte length
    ("openssh",   b"SSH-"),
    ("tls_hs",    b"\x16\x03"),       # TLS handshake record (5-byte header)
)


def detect_compression_encryption(
    frames:           list[Frame],
    high_entropy_min: float = 6.5,
    window_size:      int   = 128,
    window_step:      int   = 32,
    max_per_frame:    int   = 6,
) -> dict:
    """
    Detect compressed / encrypted regions and known file/stream magic
    signatures in each frame.

    For each frame, two passes are run:

    1. **Signature scan** — every byte position is checked against a small
       catalogue of well-known magic strings (gzip, zlib, lz4, zstd, png,
       jpeg, zip, ELF, ASN.1, TLS records, …).
    2. **Entropy windows** — a sliding window of ``window_size`` bytes is
       moved across the frame in steps of ``window_step``; windows whose
       Shannon entropy is at least ``high_entropy_min`` bits are reported
       (capped at ``max_per_frame`` per frame).

    Note: Shannon entropy on a window is bounded by ``log2(window_size)``
    bits.  Default ``window_size=128`` allows up to 7 bits and
    ``high_entropy_min=6.5`` reliably catches compressed / encrypted
    payloads while ignoring structured binary data.

    Returns ``{frame_count, total_signatures, total_high_entropy_windows,
    findings: [{frame_id, signatures: [{name, offset}], high_entropy:
    [{offset, length, entropy_bits}]}]}``.
    """
    n = len(frames)
    out_findings: list[dict] = []
    total_sigs = 0
    total_hi = 0
    for f in frames:
        raw = f.raw_bytes
        sigs: list[dict] = []
        for name, magic in _KNOWN_SIGNATURES:
            start = 0
            while True:
                idx = raw.find(magic, start)
                if idx < 0:
                    break
                sigs.append({"name": name, "offset": idx})
                start = idx + 1
        hi: list[dict] = []
        if len(raw) >= window_size:
            for pos in range(0, len(raw) - window_size + 1, window_step):
                window = raw[pos:pos + window_size]
                H = _shannon_entropy(window)
                if H >= high_entropy_min:
                    hi.append({
                        "offset":       pos,
                        "length":       window_size,
                        "entropy_bits": round(H, 4),
                    })
                    if len(hi) >= max_per_frame:
                        break
        if sigs or hi:
            out_findings.append({
                "frame_id":     f.id,
                "signatures":   sigs,
                "high_entropy": hi,
            })
            total_sigs += len(sigs)
            total_hi += len(hi)

    return {
        "frame_count":                n,
        "total_signatures":           total_sigs,
        "total_high_entropy_windows": total_hi,
        "findings":                   out_findings,
    }


def echo_detection(
    frames:        list[Frame],
    widths:        tuple[int, ...] = (2, 4, 8),
    max_distance:  int = 5,
    min_coverage:  float = 0.5,
    max_results:   int = 20,
) -> dict:
    """
    Find values sent in one direction that reappear in the opposite direction
    shortly after — the classic transaction-ID / session-token / echo pattern.

    Walks frames in capture order.  For every source frame F and each width
    in ``widths``, slides a window over F; for each non-trivial value
    (rejects all-zero and all-one-byte windows), looks in the next
    ``max_distance`` frames in the OPPOSITE direction.

    Aggregation is by ``(src_direction, src_offset, dst_offset, width)``:

    - ``opportunities`` — number of source frames where this triple *could*
      have echoed (i.e. the source frame was long enough at ``src_offset``
      and at least one target frame was long enough at ``dst_offset``).
    - ``hits`` — number of those source frames where the value at
      ``src_offset`` was actually found at ``dst_offset`` in at least one
      of that source's targets.

    A triple's ``coverage = hits / opportunities``.  Triples with
    ``coverage >= min_coverage`` are reported.  Counting per *source frame*
    (rather than per source-target pair) keeps the metric meaningful when
    most source frames have several candidate targets in the window.

    Returns ``{frame_count, total_opportunities, candidates: [{src_direction,
    src_offset, dst_offset, width, hits, opportunities, coverage,
    sample_value_hex}, ...]}``.
    """
    n = len(frames)
    if n < 2 or not widths:
        return {"frame_count": n, "total_opportunities": 0, "candidates": []}

    hit_counts: dict[tuple[str, int, int, int], int] = defaultdict(int)
    opp_counts: dict[tuple[str, int, int, int], int] = defaultdict(int)
    sample_values: dict[tuple[str, int, int, int], bytes] = {}

    for i, src in enumerate(frames):
        src_dir = src.direction.value
        src_raw = src.raw_bytes
        targets: list[Frame] = []
        for j in range(i + 1, min(i + 1 + max_distance, n)):
            if frames[j].direction is not src.direction:
                targets.append(frames[j])
        if not targets:
            continue
        # Precompute target byte buffers for cheap dst_off enumeration
        target_lens = [len(t.raw_bytes) for t in targets]
        for width in widths:
            if width > len(src_raw):
                continue
            # The set of dst_offsets that any target supports for this width:
            max_dst = max(tl - width + 1 for tl in target_lens if tl >= width)
            if max_dst <= 0:
                continue
            for src_off in range(len(src_raw) - width + 1):
                value = src_raw[src_off:src_off + width]
                if len(set(value)) <= 1:
                    continue
                # For each dst_off, did the value appear in ANY target at
                # that offset?  (per-source-frame counting)
                matches_at: set[int] = set()
                for tgt, tl in zip(targets, target_lens):
                    if tl < width:
                        continue
                    tgt_raw = tgt.raw_bytes
                    start = 0
                    while True:
                        idx = tgt_raw.find(value, start)
                        if idx < 0:
                            break
                        matches_at.add(idx)
                        start = idx + 1
                # Record opportunities + hits across every supported dst_off
                supported_dst: set[int] = set()
                for tl in target_lens:
                    if tl >= width:
                        for off in range(tl - width + 1):
                            supported_dst.add(off)
                for dst_off in supported_dst:
                    key = (src_dir, src_off, dst_off, width)
                    opp_counts[key] += 1
                    if dst_off in matches_at:
                        hit_counts[key] += 1
                        sample_values.setdefault(key, value)

    candidates: list[dict] = []
    for key, opp in opp_counts.items():
        hits = hit_counts.get(key, 0)
        if hits == 0:
            continue
        coverage = hits / opp
        if coverage < min_coverage:
            continue
        src_dir, src_off, dst_off, width = key
        candidates.append({
            "src_direction":    src_dir,
            "src_offset":       src_off,
            "dst_offset":       dst_off,
            "width":            width,
            "hits":             hits,
            "opportunities":    opp,
            "coverage":         round(coverage, 4),
            "sample_value_hex": sample_values[key].hex(),
        })

    candidates.sort(key=lambda c: (-c["coverage"], -c["width"], -c["hits"], c["src_offset"]))
    return {
        "frame_count":         n,
        "total_opportunities": sum(opp_counts.values()),
        "candidates":          candidates[:max_results],
    }
