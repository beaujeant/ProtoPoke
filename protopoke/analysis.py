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

All helpers are deliberately protocol-agnostic: no hard-coded magic bytes, no
domain-specific value ranges, no game-protocol assumptions.
"""

from __future__ import annotations

import math
import re
import struct
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
