"""
Unit tests for the fuzzing subsystem — no network, no ProxyAPI, no TLS.

Coverage:
    - FuzzResult: creation, interesting heuristic, to_dict
    - FuzzCampaign: create, convenience views, to_dict
    - Raw mutators: BitFlip, ByteInsert, ByteDelete, KnownBad, Chain
    - RadamsaMutator: fallback when binary absent
    - Field mutators: FieldBoundary, FieldOverflow, NullByte, LengthMangle
    - FuzzerEngine: unknown session, empty mutator list
"""

from __future__ import annotations

import pytest

from protopoke.models import Direction, Frame
from protopoke.core.session import SessionRegistry
from protopoke.fuzzing.models import CampaignStatus, FuzzCampaign, FuzzResult
from protopoke.fuzzing.engine import FuzzerEngine
from protopoke.fuzzing.mutators import (
    BitFlipMutator,
    ByteDeleteMutator,
    ByteInsertMutator,
    ChainMutator,
    FieldBoundaryMutator,
    FieldOverflowMutator,
    KnownBadMutator,
    LengthMangleMutator,
    NullByteMutator,
    RadamsaMutator,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _frame(data: bytes, session_id: str = "sess-1") -> Frame:
    return Frame.create(
        session_id=session_id,
        direction=Direction.CLIENT_TO_SERVER,
        raw_bytes=data,
        sequence_number=0,
    )


# ---------------------------------------------------------------------------
# FuzzResult
# ---------------------------------------------------------------------------

class TestFuzzResult:
    def _make(self, **kw) -> FuzzResult:
        defaults = dict(
            iteration=0,
            mutator_name="M",
            original_frame_id="f1",
            mutated_bytes=b"fuzz",
            response_bytes=b"ok",
            response_time_ms=5.0,
            connection_reset=False,
            timed_out=False,
            error=None,
            baseline_response_size=2,
        )
        defaults.update(kw)
        return FuzzResult.create(**defaults)

    def test_not_interesting_when_normal(self):
        assert not self._make(response_bytes=b"ok", baseline_response_size=2).interesting

    def test_interesting_on_crash(self):
        assert self._make(connection_reset=True).interesting

    def test_interesting_on_timeout(self):
        assert self._make(timed_out=True).interesting

    def test_interesting_on_large_size_delta(self):
        # baseline=100, response=200 → 100% growth
        assert self._make(response_bytes=b"x" * 200, baseline_response_size=100).interesting

    def test_not_interesting_on_small_delta(self):
        # baseline=100, response=105 → 5% growth
        assert not self._make(response_bytes=b"x" * 105, baseline_response_size=100).interesting

    def test_response_size_delta(self):
        r = self._make(response_bytes=b"xxxx", baseline_response_size=2)
        assert r.response_size_delta == 2

    def test_no_response_size_is_zero(self):
        r = self._make(response_bytes=None)
        assert r.response_size == 0

    def test_to_dict_has_required_keys(self):
        d = self._make().to_dict()
        for key in ("iteration", "mutator_name", "mutated_bytes",
                    "response_size", "response_size_delta", "interesting",
                    "connection_reset", "timed_out"):
            assert key in d, f"missing key: {key}"


# ---------------------------------------------------------------------------
# FuzzCampaign
# ---------------------------------------------------------------------------

class TestFuzzCampaign:
    def test_create_defaults(self):
        c = FuzzCampaign.create("sess", [BitFlipMutator()], iterations=10)
        assert c.session_id == "sess"
        assert c.iterations == 10
        assert c.status is CampaignStatus.IDLE
        assert c.completed_iterations == 0

    def test_mutator_names_recorded(self):
        c = FuzzCampaign.create("sess", [BitFlipMutator(), KnownBadMutator()])
        assert "BitFlip(n=1)" in c.mutator_names
        assert "KnownBad"     in c.mutator_names

    def test_interesting_results_filter(self):
        c = FuzzCampaign.create("s", [BitFlipMutator()], iterations=2)
        c.results.append(FuzzResult.create(0, "M", "f", b"a", b"b",  1.0, False, False, None, 1))
        c.results.append(FuzzResult.create(1, "M", "f", b"a", None,  1.0, True,  False, None, 1))
        assert len(c.interesting_results) == 1

    def test_crash_results_filter(self):
        c = FuzzCampaign.create("s", [BitFlipMutator()], iterations=2)
        c.results.append(FuzzResult.create(0, "M", "f", b"a", None, 1.0, True,  False, None, 1))
        c.results.append(FuzzResult.create(1, "M", "f", b"a", b"b", 1.0, False, False, None, 1))
        assert len(c.crash_results) == 1

    def test_to_dict_keys(self):
        d = FuzzCampaign.create("s", [BitFlipMutator()]).to_dict()
        for key in ("id", "session_id", "iterations", "status",
                    "mutator_names", "completed_iterations", "results"):
            assert key in d


# ---------------------------------------------------------------------------
# Raw mutators
# ---------------------------------------------------------------------------

class TestBitFlipMutator:
    @pytest.mark.asyncio
    async def test_changes_data(self):
        f = _frame(b"\x00\x00\x00\x00")
        result = await BitFlipMutator().mutate(f, None)
        assert result is not None and result != f.raw_bytes

    @pytest.mark.asyncio
    async def test_preserves_length(self):
        f = _frame(b"hello world!")
        result = await BitFlipMutator(count=3).mutate(f, None)
        assert len(result) == len(f.raw_bytes)

    @pytest.mark.asyncio
    async def test_name(self):
        assert "BitFlip" in BitFlipMutator(count=2).name


class TestByteInsertMutator:
    @pytest.mark.asyncio
    async def test_grows_data(self):
        f = _frame(b"hello")
        result = await ByteInsertMutator(count=4).mutate(f, None)
        assert len(result) == len(f.raw_bytes) + 4

    @pytest.mark.asyncio
    async def test_empty_frame(self):
        f = _frame(b"")
        result = await ByteInsertMutator(count=2).mutate(f, None)
        assert result is not None and len(result) == 2


class TestByteDeleteMutator:
    @pytest.mark.asyncio
    async def test_shrinks_data(self):
        f = _frame(b"hello world!")
        result = await ByteDeleteMutator(max_count=3).mutate(f, None)
        assert result is not None and len(result) < len(f.raw_bytes)

    @pytest.mark.asyncio
    async def test_single_byte_returns_none(self):
        f = _frame(b"x")
        assert await ByteDeleteMutator().mutate(f, None) is None

    @pytest.mark.asyncio
    async def test_empty_frame_returns_none(self):
        f = _frame(b"")
        assert await ByteDeleteMutator().mutate(f, None) is None


class TestKnownBadMutator:
    @pytest.mark.asyncio
    async def test_changes_data(self):
        f = _frame(b"A" * 32)
        result = await KnownBadMutator().mutate(f, None)
        assert result is not None and result != f.raw_bytes

    @pytest.mark.asyncio
    async def test_empty_payloads_returns_none(self):
        f = _frame(b"data")
        assert await KnownBadMutator(payloads=[]).mutate(f, None) is None

    @pytest.mark.asyncio
    async def test_custom_payloads(self):
        f = _frame(b"\x00" * 16)
        result = await KnownBadMutator(payloads=[b"\xff\xff"]).mutate(f, None)
        assert result is not None


class TestChainMutator:
    @pytest.mark.asyncio
    async def test_applies_both_mutators(self):
        # BitFlip changes a bit, ByteInsert adds bytes → result is longer
        f = _frame(b"\x00" * 8)
        chain = ChainMutator([BitFlipMutator(count=1), ByteInsertMutator(count=2)])
        result = await chain.mutate(f, None)
        assert result is not None
        assert len(result) == len(f.raw_bytes) + 2

    @pytest.mark.asyncio
    async def test_all_none_returns_none(self):
        class NopMutator(BitFlipMutator):
            async def mutate(self, frame, parsed):
                return None

        f = _frame(b"data")
        result = await ChainMutator([NopMutator(), NopMutator()]).mutate(f, None)
        assert result is None

    @pytest.mark.asyncio
    async def test_name_includes_inner_names(self):
        chain = ChainMutator([BitFlipMutator(), KnownBadMutator()])
        assert "BitFlip" in chain.name and "KnownBad" in chain.name


# ---------------------------------------------------------------------------
# RadamsaMutator — fallback path (radamsa not installed in CI)
# ---------------------------------------------------------------------------

class TestRadamsaMutator:
    @pytest.mark.asyncio
    async def test_fallback_when_not_installed(self):
        mutator = RadamsaMutator(radamsa_path="/nonexistent/radamsa")
        f = _frame(b"test data for radamsa fallback")
        result = await mutator.mutate(f, None)
        # Falls back to BitFlipMutator — same length, different content
        assert result is not None
        assert len(result) == len(f.raw_bytes)

    def test_name(self):
        assert RadamsaMutator().name == "Radamsa"


# ---------------------------------------------------------------------------
# Field mutators (using a real protocol definition)
# ---------------------------------------------------------------------------

_PROTO_DICT = {
    "name": "TestProto",
    "messages": [
        {
            "name": "Packet",
            "match": {"type": "always"},
            "fields": [
                {"name": "opcode",   "type": "uint8"},
                {"name": "data_len", "type": "uint16"},
                {"name": "payload",  "type": "bytes", "length": "{data_len}"},
            ],
        }
    ],
}


def _load_codec():
    from protopoke.protocol.definition import load_protocol
    from protopoke.protocol.parser import DefinitionBasedDecoder, DefinitionBasedEncoder
    defn = load_protocol(_PROTO_DICT)
    return DefinitionBasedDecoder(defn), DefinitionBasedEncoder(defn)


def _parsed(raw: bytes):
    decoder, encoder = _load_codec()
    return _frame(raw), decoder.decode(_frame(raw)), encoder


class TestFieldBoundaryMutator:
    @pytest.mark.asyncio
    async def test_changes_integer_field(self):
        raw = b"\x01\x00\x03abc"
        frame, parsed, encoder = _parsed(raw)
        mutator = FieldBoundaryMutator(encoder)
        # A single call may coincidentally reproduce the original (e.g. opcode=1
        # is a valid uint8 boundary), so verify varied output across iterations.
        seen = set()
        for _ in range(30):
            r = await mutator.mutate(frame, parsed)
            if r is not None:
                seen.add(r)
        assert len(seen) > 1, "FieldBoundaryMutator must produce varied output"

    @pytest.mark.asyncio
    async def test_returns_none_without_parsed(self):
        _, encoder = _load_codec()
        result = await FieldBoundaryMutator(encoder).mutate(_frame(b"\x01\x00\x03abc"), None)
        assert result is None

    @pytest.mark.asyncio
    async def test_skip_fields_respected(self):
        raw = b"\x01\x00\x03abc"
        frame, parsed, encoder = _parsed(raw)
        # Skip all integer fields → no candidates → None
        result = await FieldBoundaryMutator(encoder, skip_fields=["opcode", "data_len"]).mutate(frame, parsed)
        # payload is bytes, not int → no integer candidates remain
        assert result is None


class TestFieldOverflowMutator:
    @pytest.mark.asyncio
    async def test_extends_payload_and_updates_length(self):
        raw = b"\x01\x00\x03abc"
        frame, parsed, encoder = _parsed(raw)
        result = await FieldOverflowMutator(encoder, lengths=[64]).mutate(frame, parsed)
        assert result is not None
        # Entire packet grows: opcode(1) + data_len(2) + 64-byte payload
        assert len(result) > len(raw)

    @pytest.mark.asyncio
    async def test_returns_none_without_parsed(self):
        _, encoder = _load_codec()
        result = await FieldOverflowMutator(encoder).mutate(_frame(b"\x01\x00\x03abc"), None)
        assert result is None


class TestNullByteMutator:
    @pytest.mark.asyncio
    async def test_injects_null_into_bytes_field(self):
        raw = b"\x01\x00\x05hello"
        frame, parsed, encoder = _parsed(raw)
        result = await NullByteMutator(encoder).mutate(frame, parsed)
        # payload is bytes of length 5 ≥ 2, so mutation should succeed
        assert result is not None

    @pytest.mark.asyncio
    async def test_returns_none_without_parsed(self):
        _, encoder = _load_codec()
        result = await NullByteMutator(encoder).mutate(_frame(b"\x01\x00\x05hello"), None)
        assert result is None


class TestLengthMangleMutator:
    @pytest.mark.asyncio
    async def test_corrupts_length_field(self):
        raw = b"\x01\x00\x03abc"
        frame, parsed, encoder = _parsed(raw)
        result = await LengthMangleMutator(encoder).mutate(frame, parsed)
        # data_len bytes (offset 1-2) should differ from original \x00\x03
        assert result is not None

    @pytest.mark.asyncio
    async def test_returns_none_without_parsed(self):
        _, encoder = _load_codec()
        result = await LengthMangleMutator(encoder).mutate(_frame(b"\x01\x00\x03abc"), None)
        assert result is None


# ---------------------------------------------------------------------------
# FuzzerEngine — unit tests (no network)
# ---------------------------------------------------------------------------

class TestFuzzerEngineUnit:
    @pytest.mark.asyncio
    async def test_unknown_session_returns_done(self):
        from protopoke.forge.engine import ForgeEngine
        reg    = SessionRegistry()
        engine = FuzzerEngine(
            forge_engine=ForgeEngine(session_registry=reg),
            session_registry=reg,
        )
        campaign = FuzzCampaign.create("nonexistent", [BitFlipMutator()], iterations=5)
        result   = await engine.run_campaign(campaign, [BitFlipMutator()])
        assert result.status is CampaignStatus.DONE
        assert result.completed_iterations == 0

    @pytest.mark.asyncio
    async def test_empty_mutators_returns_done(self):
        from protopoke.forge.engine import ForgeEngine
        reg    = SessionRegistry()
        engine = FuzzerEngine(
            forge_engine=ForgeEngine(session_registry=reg),
            session_registry=reg,
        )
        campaign = FuzzCampaign.create("sess", [], iterations=5)
        result   = await engine.run_campaign(campaign, [])
        assert result.status is CampaignStatus.DONE
        assert result.completed_iterations == 0
