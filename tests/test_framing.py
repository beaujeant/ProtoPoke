"""Tests for all framer implementations."""

from __future__ import annotations

import struct

import pytest

from tcpproxy.models import Direction
from tcpproxy.framing.raw import RawFramer
from tcpproxy.framing.delimiter import DelimiterFramer
from tcpproxy.framing.length_prefix import LengthPrefixFramer

SESS = "test-session"
DIR  = Direction.CLIENT_TO_SERVER


# ---------------------------------------------------------------------------
# RawFramer
# ---------------------------------------------------------------------------

class TestRawFramer:
    def test_one_chunk_one_frame(self):
        f = RawFramer(SESS, DIR)
        frames = f.feed(b"hello")
        assert len(frames) == 1
        assert frames[0].raw_bytes == b"hello"

    def test_empty_chunk_no_frame(self):
        f = RawFramer(SESS, DIR)
        assert f.feed(b"") == []

    def test_multiple_feeds_increment_sequence(self):
        f = RawFramer(SESS, DIR)
        [a] = f.feed(b"a")
        [b] = f.feed(b"b")
        [c] = f.feed(b"c")
        assert a.sequence_number == 0
        assert b.sequence_number == 1
        assert c.sequence_number == 2

    def test_flush_returns_empty(self):
        f = RawFramer(SESS, DIR)
        f.feed(b"something")
        assert f.flush() == []

    def test_frame_metadata(self):
        f = RawFramer(SESS, DIR)
        [frame] = f.feed(b"x")
        assert frame.session_id == SESS
        assert frame.direction is DIR
        assert frame.framer_name == "raw"

    def test_reset_restarts_sequence(self):
        f = RawFramer(SESS, DIR)
        f.feed(b"a")
        f.feed(b"b")
        f.reset()
        [frame] = f.feed(b"c")
        assert frame.sequence_number == 0


# ---------------------------------------------------------------------------
# DelimiterFramer
# ---------------------------------------------------------------------------

class TestDelimiterFramer:
    def test_newline_splits(self):
        f = DelimiterFramer(SESS, DIR, delimiter=b'\n')
        frames = f.feed(b"line1\nline2\n")
        assert len(frames) == 2
        assert frames[0].raw_bytes == b"line1\n"
        assert frames[1].raw_bytes == b"line2\n"

    def test_partial_line_buffered(self):
        f = DelimiterFramer(SESS, DIR, delimiter=b'\n')
        assert f.feed(b"no newline yet") == []

    def test_split_across_two_feeds(self):
        f = DelimiterFramer(SESS, DIR, delimiter=b'\n')
        assert f.feed(b"part1") == []
        frames = f.feed(b"part2\n")
        assert len(frames) == 1
        assert frames[0].raw_bytes == b"part1part2\n"

    def test_flush_emits_partial(self):
        f = DelimiterFramer(SESS, DIR, delimiter=b'\n')
        f.feed(b"no newline")
        frames = f.flush()
        assert len(frames) == 1
        assert frames[0].raw_bytes == b"no newline"

    def test_flush_empty_when_no_buffer(self):
        f = DelimiterFramer(SESS, DIR, delimiter=b'\n')
        assert f.flush() == []

    def test_include_delimiter_false(self):
        f = DelimiterFramer(SESS, DIR, delimiter=b'\n', include_delimiter=False)
        frames = f.feed(b"hello\nworld\n")
        assert frames[0].raw_bytes == b"hello"
        assert frames[1].raw_bytes == b"world"

    def test_crlf_delimiter(self):
        f = DelimiterFramer(SESS, DIR, delimiter=b'\r\n')
        frames = f.feed(b"GET / HTTP/1.0\r\n")
        assert len(frames) == 1
        assert frames[0].raw_bytes == b"GET / HTTP/1.0\r\n"

    def test_multi_byte_delimiter_partial(self):
        f = DelimiterFramer(SESS, DIR, delimiter=b'\r\n')
        # Only the \r arrives first
        assert f.feed(b"data\r") == []
        frames = f.feed(b"\n")
        assert len(frames) == 1
        assert frames[0].raw_bytes == b"data\r\n"

    def test_max_frame_size_safety(self):
        f = DelimiterFramer(SESS, DIR, delimiter=b'\n', max_frame_size=10)
        # Send 20 bytes without a delimiter; should flush at the limit
        frames = f.feed(b"x" * 20)
        assert len(frames) == 1
        assert len(frames[0].raw_bytes) == 20

    def test_empty_delimiter_raises(self):
        with pytest.raises(ValueError):
            DelimiterFramer(SESS, DIR, delimiter=b'')

    def test_reset_clears_buffer(self):
        f = DelimiterFramer(SESS, DIR, delimiter=b'\n')
        f.feed(b"partial")
        f.reset()
        # Buffer should be empty now
        assert f.flush() == []

    def test_sequence_numbers(self):
        f = DelimiterFramer(SESS, DIR, delimiter=b'\n')
        frames = f.feed(b"a\nb\nc\n")
        assert [fr.sequence_number for fr in frames] == [0, 1, 2]


# ---------------------------------------------------------------------------
# LengthPrefixFramer
# ---------------------------------------------------------------------------

class TestLengthPrefixFramer:
    def _pack(self, payload: bytes, prefix_len: int = 4, order: str = 'big') -> bytes:
        fmt_map = {(4,'big'): '>I', (4,'little'): '<I',
                   (2,'big'): '>H', (2,'little'): '<H',
                   (1,'big'): '>B', (1,'little'): '<B'}
        return struct.pack(fmt_map[(prefix_len, order)], len(payload)) + payload

    def test_complete_message(self):
        f = LengthPrefixFramer(SESS, DIR, prefix_length=4)
        data = self._pack(b"hello")
        frames = f.feed(data)
        assert len(frames) == 1
        assert frames[0].raw_bytes == data  # include_prefix=True by default

    def test_payload_only_no_prefix(self):
        f = LengthPrefixFramer(SESS, DIR, prefix_length=4, include_prefix=False)
        data = self._pack(b"hello")
        [frame] = f.feed(data)
        assert frame.raw_bytes == b"hello"

    def test_partial_header_buffered(self):
        f = LengthPrefixFramer(SESS, DIR, prefix_length=4)
        assert f.feed(b"\x00\x00") == []  # Only 2 of 4 header bytes

    def test_partial_payload_buffered(self):
        f = LengthPrefixFramer(SESS, DIR, prefix_length=4)
        # Header says 10 bytes, we only have 5
        assert f.feed(struct.pack(">I", 10) + b"hello") == []

    def test_multiple_messages_in_one_read(self):
        f = LengthPrefixFramer(SESS, DIR, prefix_length=4)
        msg1 = self._pack(b"hello")
        msg2 = self._pack(b"world")
        frames = f.feed(msg1 + msg2)
        assert len(frames) == 2

    def test_message_split_across_reads(self):
        f = LengthPrefixFramer(SESS, DIR, prefix_length=4)
        data = self._pack(b"complete")
        # Split in the middle
        half = len(data) // 2
        assert f.feed(data[:half]) == []
        frames = f.feed(data[half:])
        assert len(frames) == 1
        assert frames[0].raw_bytes == data

    def test_flush_emits_partial(self):
        f = LengthPrefixFramer(SESS, DIR, prefix_length=4)
        f.feed(b"\x00\x00\x00\x05hel")  # Header says 5 bytes, only have 3
        frames = f.flush()
        assert len(frames) == 1

    def test_2_byte_prefix(self):
        f = LengthPrefixFramer(SESS, DIR, prefix_length=2)
        data = self._pack(b"hi", prefix_len=2)
        [frame] = f.feed(data)
        assert frame.raw_bytes == data

    def test_little_endian(self):
        f = LengthPrefixFramer(SESS, DIR, prefix_length=4, byte_order='little')
        payload = b"test"
        data = struct.pack('<I', len(payload)) + payload
        [frame] = f.feed(data)
        assert frame.raw_bytes == data

    def test_invalid_config_raises(self):
        with pytest.raises(ValueError):
            LengthPrefixFramer(SESS, DIR, prefix_length=3)  # 3-byte prefix not supported

    def test_zero_length_payload(self):
        f = LengthPrefixFramer(SESS, DIR, prefix_length=4)
        data = struct.pack(">I", 0)  # Empty payload
        [frame] = f.feed(data)
        # Frame should be just the 4-byte header
        assert frame.raw_bytes == data

    def test_sequence_numbers(self):
        f = LengthPrefixFramer(SESS, DIR, prefix_length=4)
        msg1 = self._pack(b"a")
        msg2 = self._pack(b"b")
        frames = f.feed(msg1 + msg2)
        assert frames[0].sequence_number == 0
        assert frames[1].sequence_number == 1

    def test_reset(self):
        f = LengthPrefixFramer(SESS, DIR, prefix_length=4)
        f.feed(b"\x00\x00\x00\x05hel")  # partial
        f.reset()
        assert f.flush() == []
        # After reset, sequence should restart
        data = self._pack(b"fresh")
        [frame] = f.feed(data)
        assert frame.sequence_number == 0
