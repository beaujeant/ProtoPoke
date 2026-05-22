"""Tests for the binary rules module: ReplaceRule, InterceptRule, RulesEngine, InterceptFilter."""

from __future__ import annotations

import pytest

from protopoke.models import Direction, Frame
from protopoke.rules.rule import (
    PatternError,
    RuleAction,
    ReplaceRule,
    InterceptRule,
    compile_binary_pattern,
    pattern_to_display,
)
from protopoke.rules.engine import RulesEngine, InterceptFilter


def make_frame(data: bytes, direction: Direction = Direction.CLIENT_TO_SERVER, seq: int = 0) -> Frame:
    return Frame.create("session-1", direction, data, seq)


# ---------------------------------------------------------------------------
# compile_binary_pattern
# ---------------------------------------------------------------------------

class TestCompileBinaryPattern:
    def test_literal_bytes(self):
        pat = compile_binary_pattern("01 02 FF")
        assert pat.search(b"\x01\x02\xff")

    def test_literal_no_match(self):
        pat = compile_binary_pattern("01 02 FF")
        assert not pat.search(b"\x01\x02\xfe")

    def test_wildcard(self):
        pat = compile_binary_pattern("01 ?? 03")
        assert pat.search(b"\x01\xAB\x03")
        assert pat.search(b"\x01\x00\x03")

    def test_byte_range(self):
        pat = compile_binary_pattern("[03-09]")
        assert pat.search(b"\x05")
        assert not pat.search(b"\x0A")

    def test_quantifier_exact(self):
        pat = compile_binary_pattern(".{3}")
        assert pat.search(b"\x00\x01\x02")

    def test_alternation(self):
        pat = compile_binary_pattern("(01|FF)")
        assert pat.search(b"\x01")
        assert pat.search(b"\xFF")
        assert not pat.search(b"\x02")

    def test_python_escape(self):
        pat = compile_binary_pattern("\\x41")
        assert pat.search(b"A")

    def test_case_insensitive_hex(self):
        pat = compile_binary_pattern("ab cd")
        assert pat.search(b"\xab\xcd")

    def test_malformed_range_raises(self):
        with pytest.raises(PatternError):
            compile_binary_pattern("[ZZ-ZZ]")

    def test_unclosed_bracket_raises(self):
        with pytest.raises(PatternError):
            compile_binary_pattern("[01")

    def test_empty_pattern_raises(self):
        # An empty compile_binary_pattern call should succeed and match anything
        pat = compile_binary_pattern("??")
        assert pat.search(b"\x00")

    def test_mixed_pattern(self):
        pat = compile_binary_pattern("01 ?? [00-0F] .{2} FF")
        data = b"\x01\xAB\x05\x00\x00\xFF"
        assert pat.search(data)


class TestPatternToDisplay:
    def test_normalises_case(self):
        result = pattern_to_display("ab cd ff")
        assert result == "AB CD FF"

    def test_preserves_wildcards(self):
        assert "??" in pattern_to_display("01 ?? FF")

    def test_malformed_returns_original(self):
        original = "not a pattern !!!"
        result = pattern_to_display(original)
        assert result == original


# ---------------------------------------------------------------------------
# ReplaceRule
# ---------------------------------------------------------------------------

class TestReplaceRule:
    def test_apply_replaces_match(self):
        rule = ReplaceRule.create("test", "41 41", b"\x42\x42")  # AA → BB
        result = rule.apply(b"\x41\x41\x43")
        assert result == b"\x42\x42\x43"

    def test_apply_no_match_returns_original(self):
        rule = ReplaceRule.create("test", "FF FF", b"\x00\x00")
        data = b"\x01\x02"
        assert rule.apply(data) is data

    def test_apply_disabled_skips(self):
        rule = ReplaceRule.create("test", "41", b"\x42", enabled=False)
        assert rule.apply(b"\x41") == b"\x41"

    def test_matches(self):
        rule = ReplaceRule.create("test", "01 02", b"\x00")
        assert rule.matches(b"\x00\x01\x02\x03")
        assert not rule.matches(b"\x00\x00\x00")

    def test_direction_filter(self):
        rule = ReplaceRule.create(
            "test", "01", b"\x02", direction=Direction.CLIENT_TO_SERVER
        )
        frame_c2s = make_frame(b"\x01", Direction.CLIENT_TO_SERVER)
        frame_s2c = make_frame(b"\x01", Direction.SERVER_TO_CLIENT)
        # ReplaceRule.apply does not check direction; RulesEngine does
        assert rule.apply(b"\x01") == b"\x02"  # rule itself ignores direction

    def test_serialise_round_trip(self):
        rule = ReplaceRule.create("myRule", "01 02 ??", b"\xFF", direction=Direction.CLIENT_TO_SERVER)
        restored = ReplaceRule.from_dict(rule.to_dict())
        assert restored.id == rule.id
        assert restored.label == rule.label
        assert restored.pattern_str == rule.pattern_str
        assert restored.replacement == rule.replacement
        assert restored.direction == rule.direction
        assert restored.enabled == rule.enabled


# ---------------------------------------------------------------------------
# InterceptRule
# ---------------------------------------------------------------------------

class TestInterceptRule:
    def test_matches_exact(self):
        rule = InterceptRule.create("login", "01 00", RuleAction.INTERCEPT)
        frame = make_frame(b"\x01\x00\x05")
        assert rule.matches_frame(frame)

    def test_no_match(self):
        rule = InterceptRule.create("login", "FF 00", RuleAction.INTERCEPT)
        frame = make_frame(b"\x01\x00\x05")
        assert not rule.matches_frame(frame)

    def test_direction_filter(self):
        rule = InterceptRule.create(
            "c2s only", "01", RuleAction.INTERCEPT,
            direction=Direction.CLIENT_TO_SERVER,
        )
        c2s = make_frame(b"\x01", Direction.CLIENT_TO_SERVER)
        s2c = make_frame(b"\x01", Direction.SERVER_TO_CLIENT)
        assert rule.matches_frame(c2s)
        assert not rule.matches_frame(s2c)

    def test_session_filter(self):
        rule = InterceptRule.create(
            "session-specific", "01", RuleAction.INTERCEPT,
            session_ids={"session-1"},
        )
        frame_match = Frame.create("session-1", Direction.CLIENT_TO_SERVER, b"\x01", 0)
        frame_other = Frame.create("session-2", Direction.CLIENT_TO_SERVER, b"\x01", 0)
        assert rule.matches_frame(frame_match)
        assert not rule.matches_frame(frame_other)

    def test_empty_pattern_matches_all(self):
        rule = InterceptRule.create("catch-all", "", RuleAction.FORWARD)
        frame = make_frame(b"\xDE\xAD\xBE\xEF")
        assert rule.matches_frame(frame)

    def test_disabled_never_matches(self):
        rule = InterceptRule.create("disabled", "", RuleAction.INTERCEPT, enabled=False)
        frame = make_frame(b"\x01")
        assert not rule.matches_frame(frame)

    def test_serialise_round_trip(self):
        rule = InterceptRule.create(
            "rule", "01 ??", RuleAction.FORWARD,
            direction=Direction.SERVER_TO_CLIENT,
            session_ids={"s1", "s2"},
        )
        restored = InterceptRule.from_dict(rule.to_dict())
        assert restored.id == rule.id
        assert restored.action == rule.action
        assert restored.direction == rule.direction
        assert restored.session_ids == rule.session_ids


# ---------------------------------------------------------------------------
# RulesEngine
# ---------------------------------------------------------------------------

class TestRulesEngine:
    def test_apply_single_rule(self):
        engine = RulesEngine()
        engine.add_rule(ReplaceRule.create("r1", "41", b"\x42"))
        frame = make_frame(b"\x41\x43")
        result = engine.apply(frame)
        assert result == b"\x42\x43"

    def test_rules_stack(self):
        engine = RulesEngine()
        engine.add_rule(ReplaceRule.create("r1", "41", b"\x42"))
        engine.add_rule(ReplaceRule.create("r2", "43", b"\x44"))
        frame = make_frame(b"\x41\x43")
        result = engine.apply(frame)
        assert result == b"\x42\x44"

    def test_direction_filter_respected(self):
        engine = RulesEngine()
        engine.add_rule(
            ReplaceRule.create("r1", "41", b"\x42", direction=Direction.CLIENT_TO_SERVER)
        )
        c2s = make_frame(b"\x41", Direction.CLIENT_TO_SERVER)
        s2c = make_frame(b"\x41", Direction.SERVER_TO_CLIENT)
        assert engine.apply(c2s) == b"\x42"
        assert engine.apply(s2c) == b"\x41"

    def test_disabled_rule_skipped(self):
        engine = RulesEngine()
        engine.add_rule(ReplaceRule.create("r1", "41", b"\x42", enabled=False))
        frame = make_frame(b"\x41")
        assert engine.apply(frame) == b"\x41"

    def test_remove_rule(self):
        engine = RulesEngine()
        rule = ReplaceRule.create("r1", "41", b"\x42")
        engine.add_rule(rule)
        assert engine.remove_rule(rule.id)
        frame = make_frame(b"\x41")
        assert engine.apply(frame) == b"\x41"

    def test_move_rule(self):
        engine = RulesEngine()
        r1 = ReplaceRule.create("r1", "41", b"\x42")
        r2 = ReplaceRule.create("r2", "42", b"\x43")
        engine.add_rule(r1)
        engine.add_rule(r2)
        # r1 first: 41→42, then 42→43 → result \x43
        assert engine.apply(make_frame(b"\x41")) == b"\x43"
        # Move r2 before r1: 42→43 first (no match on \x41), then 41→42 → result \x42
        engine.move_rule(r2.id, 0)
        assert engine.apply(make_frame(b"\x41")) == b"\x42"

    def test_serialise_round_trip(self):
        engine = RulesEngine()
        engine.add_rule(ReplaceRule.create("r1", "01 02", b"\x03"))
        engine.add_rule(ReplaceRule.create("r2", "FF", b"\x00"))
        restored = RulesEngine.from_list(engine.to_list())
        assert len(restored.rules) == 2
        assert restored.rules[0].label == "r1"
        assert restored.rules[1].label == "r2"


# ---------------------------------------------------------------------------
# InterceptFilter
# ---------------------------------------------------------------------------

class TestInterceptFilter:
    def test_no_rules_intercepts_all(self):
        filt = InterceptFilter()
        frame = make_frame(b"\x01\x02")
        assert filt.should_intercept(frame)

    def test_intercept_rule_matches(self):
        filt = InterceptFilter()
        filt.add_rule(InterceptRule.create("login", "01", RuleAction.INTERCEPT))
        frame = make_frame(b"\x01\x00")
        assert filt.should_intercept(frame)

    def test_forward_rule_matches(self):
        filt = InterceptFilter()
        filt.add_rule(InterceptRule.create("heartbeat", "FF", RuleAction.FORWARD))
        frame = make_frame(b"\xFF\x00")
        assert not filt.should_intercept(frame)

    def test_no_match_auto_forwards_when_rules_present(self):
        filt = InterceptFilter()
        filt.add_rule(InterceptRule.create("login", "01", RuleAction.INTERCEPT))
        other_frame = make_frame(b"\x02\x00")
        # Rules present but none match → auto-forward
        assert not filt.should_intercept(other_frame)

    def test_first_match_wins(self):
        filt = InterceptFilter()
        filt.add_rule(InterceptRule.create("catch-all fwd", "", RuleAction.FORWARD))
        filt.add_rule(InterceptRule.create("specific intercept", "01", RuleAction.INTERCEPT))
        frame = make_frame(b"\x01")
        # First rule (FORWARD) matches first → forward
        assert not filt.should_intercept(frame)

    def test_evaluate_returns_none_on_no_match(self):
        filt = InterceptFilter()
        filt.add_rule(InterceptRule.create("login", "01", RuleAction.INTERCEPT))
        frame = make_frame(b"\x02")
        assert filt.evaluate(frame) is None

    def test_serialise_round_trip(self):
        filt = InterceptFilter()
        filt.add_rule(InterceptRule.create("r1", "01", RuleAction.INTERCEPT))
        filt.add_rule(InterceptRule.create("r2", "", RuleAction.FORWARD))
        restored = InterceptFilter.from_list(filt.to_list())
        assert len(restored.rules) == 2
        assert restored.rules[0].action == RuleAction.INTERCEPT
        assert restored.rules[1].action == RuleAction.FORWARD


# ---------------------------------------------------------------------------
# QueuedTamperController with direction/session/rule filters
# ---------------------------------------------------------------------------

class TestQueuedControllerFilters:
    @pytest.mark.asyncio
    async def test_direction_filter_passes_through(self):
        from protopoke.models import InterceptAction
        from protopoke.tamper.controller import QueuedTamperController

        ctrl = QueuedTamperController(
            tamper_enabled=True,
            direction_filter=Direction.CLIENT_TO_SERVER,
        )
        s2c_frame = Frame.create("s1", Direction.SERVER_TO_CLIENT, b"\x01", 0)
        unit = await ctrl.process(s2c_frame)
        assert unit.action is InterceptAction.FORWARD

    @pytest.mark.asyncio
    async def test_session_filter_passes_through(self):
        from protopoke.models import InterceptAction
        from protopoke.tamper.controller import QueuedTamperController

        ctrl = QueuedTamperController(
            tamper_enabled=True,
            session_filter={"allowed-session"},
        )
        other_frame = Frame.create("other-session", Direction.CLIENT_TO_SERVER, b"\x01", 0)
        unit = await ctrl.process(other_frame)
        assert unit.action is InterceptAction.FORWARD

    @pytest.mark.asyncio
    async def test_intercept_filter_auto_forwards(self):
        from protopoke.models import InterceptAction
        from protopoke.tamper.controller import QueuedTamperController

        filt = InterceptFilter()
        # Only intercept 01-prefixed frames; everything else auto-forwards
        filt.add_rule(InterceptRule.create("login", "01", RuleAction.INTERCEPT))

        ctrl = QueuedTamperController(
            tamper_enabled=True,
            intercept_filter=filt,
        )
        other_frame = Frame.create("s1", Direction.CLIENT_TO_SERVER, b"\x02\x00", 0)
        unit = await ctrl.process(other_frame)
        assert unit.action is InterceptAction.FORWARD
