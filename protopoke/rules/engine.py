"""
Rules engines: RulesEngine (replace rules) and InterceptFilter (intercept rules).

RulesEngine
-----------
Applies an ordered list of ReplaceRules to frame bytes.  All enabled rules
that match the frame's direction are applied sequentially — rules stack.

InterceptFilter
---------------
Evaluates an ordered list of InterceptRules against a frame and returns a
RuleAction decision.  The first matching rule wins (firewall semantics).

    - If no rules are configured:  ``should_intercept()`` returns ``True``
      (intercept everything — the default).
    - If rules are configured but none match: returns ``False``
      (auto-forward — rules are an allow-list for what to intercept).
    - If a rule matches: use the rule's action (INTERCEPT or FORWARD).
"""

from __future__ import annotations

import logging
from typing import Optional

from ..models import Direction, Frame
from .rule import ReplaceRule, InterceptRule, RuleAction

logger = logging.getLogger(__name__)


class RulesEngine:
    """
    Ordered list of ReplaceRules applied to frame bytes.

    Rules are applied in insertion order.  All enabled rules whose
    direction filter matches the frame are applied; later rules see the
    bytes already modified by earlier rules.

    Usage::

        engine = RulesEngine()
        engine.add_rule(ReplaceRule.create("Null terminator", "00", b"\\n"))

        modified = engine.apply(frame)   # returns bytes
    """

    def __init__(self, variables: Optional[dict] = None) -> None:
        self._rules: list[ReplaceRule] = []
        # Shared global variable store.  Script-type rules receive this dict
        # and may read from or write to it.  Mutations are visible across all
        # pipelines (traffic, tamper, forge) immediately.
        self._variables: dict = variables if variables is not None else {}

    @property
    def rules(self) -> list[ReplaceRule]:
        """Snapshot of the current rule list (ordered)."""
        return list(self._rules)

    def add_rule(self, rule: ReplaceRule) -> None:
        """Append *rule* to the end of the list."""
        self._rules.append(rule)

    def insert_rule(self, index: int, rule: ReplaceRule) -> None:
        """Insert *rule* at *index*."""
        self._rules.insert(index, rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove the rule with *rule_id*. Returns ``True`` if found."""
        for i, r in enumerate(self._rules):
            if r.id == rule_id:
                self._rules.pop(i)
                return True
        return False

    def get_rule(self, rule_id: str) -> Optional[ReplaceRule]:
        """Return the rule with *rule_id*, or ``None`` if not found."""
        for r in self._rules:
            if r.id == rule_id:
                return r
        return None

    def move_rule(self, rule_id: str, new_index: int) -> bool:
        """Move the rule with *rule_id* to *new_index*. Returns ``True`` if found."""
        for i, r in enumerate(self._rules):
            if r.id == rule_id:
                self._rules.pop(i)
                self._rules.insert(new_index, r)
                return True
        return False

    def apply(self, frame: Frame, scope: str = "traffic") -> bytes:
        """
        Apply all matching rules to *frame* and return the resulting bytes.

        Args:
            frame: The frame whose bytes will be transformed.
            scope: Pipeline stage — ``"traffic"`` (default, relay),
                   ``"tamper"`` (operator edited bytes), or ``"forge"``.
                   Rules whose corresponding ``apply_to_*`` flag is
                   ``False`` are skipped.

        Returns the original ``frame.raw_bytes`` if no enabled rule matches.
        """
        data = frame.raw_bytes
        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.direction is not None and rule.direction is not frame.direction:
                continue
            before = data
            data = rule.apply(data, scope=scope, variables=self._variables)
            if data != before:
                logger.debug(
                    "Replace rule %r fired on frame %s (session %s)",
                    rule.label, frame.id[:8], frame.session_id[:8],
                )
        return data

    def apply_bytes(
        self,
        data:      bytes,
        direction: "Optional[Direction]",
        scope:     str,
    ) -> bytes:
        """
        Apply all matching rules to raw *data* (no Frame object).

        Used by the Forge / playbook pipeline where frames are not yet
        (or not) tracked in a session.

        Args:
            data:      Bytes to transform.
            direction: Direction the data will be sent in, used for
                       per-direction rule filters.  Pass ``None`` to
                       match rules that have no direction filter.
            scope:     ``"traffic"``, ``"tamper"`` or ``"forge"``.

        Returns the (possibly modified) bytes.
        """
        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.direction is not None and rule.direction is not direction:
                continue
            before = data
            data = rule.apply(data, scope=scope, variables=self._variables)
            if data != before:
                logger.debug(
                    "Replace rule %r fired (scope=%s)", rule.label, scope
                )
        return data

    def clear(self) -> None:
        """Remove all rules."""
        self._rules.clear()

    def to_list(self) -> list[dict]:
        """Serialise all rules to a JSON-compatible list of dicts."""
        return [r.to_dict() for r in self._rules]

    @classmethod
    def from_list(cls, data: list[dict]) -> "RulesEngine":
        """Deserialise from a list of dicts produced by ``to_list()``."""
        engine = cls()
        for d in data:
            engine.add_rule(ReplaceRule.from_dict(d))
        return engine


class InterceptFilter:
    """
    Ordered list of InterceptRules that decide whether to queue a frame.

    Decision logic (firewall / first-match semantics):

    1. Evaluate rules top-to-bottom.
    2. First rule whose ``matches_frame()`` returns ``True`` → return that
       rule's ``action`` (INTERCEPT or FORWARD).
    3. No rule matches:
       - If the list is **empty**: return ``None`` and let
         ``should_intercept()`` default to ``True`` (classic mode).
       - If the list is **non-empty**: return ``None`` and let
         ``should_intercept()`` default to ``False`` (auto-forward).

    Usage::

        filt = InterceptFilter()
        filt.add_rule(InterceptRule.create("Login", "01 00", RuleAction.INTERCEPT))

        if filt.should_intercept(frame):
            # queue it …
    """

    def __init__(self) -> None:
        self._rules: list[InterceptRule] = []

    @property
    def rules(self) -> list[InterceptRule]:
        """Snapshot of the current rule list (ordered)."""
        return list(self._rules)

    def add_rule(self, rule: InterceptRule) -> None:
        """Append *rule* to the end of the list."""
        self._rules.append(rule)

    def insert_rule(self, index: int, rule: InterceptRule) -> None:
        """Insert *rule* at *index*."""
        self._rules.insert(index, rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove the rule with *rule_id*. Returns ``True`` if found."""
        for i, r in enumerate(self._rules):
            if r.id == rule_id:
                self._rules.pop(i)
                return True
        return False

    def get_rule(self, rule_id: str) -> Optional[InterceptRule]:
        """Return the rule with *rule_id*, or ``None`` if not found."""
        for r in self._rules:
            if r.id == rule_id:
                return r
        return None

    def move_rule(self, rule_id: str, new_index: int) -> bool:
        """Move the rule with *rule_id* to *new_index*. Returns ``True`` if found."""
        for i, r in enumerate(self._rules):
            if r.id == rule_id:
                self._rules.pop(i)
                self._rules.insert(new_index, r)
                return True
        return False

    def evaluate(self, frame: Frame) -> Optional[RuleAction]:
        """
        Evaluate all rules for *frame* and return the first matching action.

        Returns:
            ``RuleAction.INTERCEPT`` — frame should be queued.
            ``RuleAction.FORWARD``   — frame should be auto-forwarded.
            ``None``                 — no rule matched.
        """
        for rule in self._rules:
            if rule.matches_frame(frame):
                logger.debug(
                    "Intercept rule %r matched frame %s (action=%s)",
                    rule.label, frame.id[:8], rule.action.value,
                )
                return rule.action
        return None

    def should_intercept(self, frame: Frame) -> bool:
        """
        Return ``True`` if *frame* should be held in the intercept queue.

        When no rules are configured, returns ``True`` (intercept everything).
        When rules are configured but none match, returns ``False``
        (auto-forward — rules define what to intercept).
        """
        if not self._rules:
            # No rules → intercept everything (the default).
            return True
        action = self.evaluate(frame)
        if action is None:
            # Rules present but none matched → auto-forward
            return False
        return action is RuleAction.INTERCEPT

    def clear(self) -> None:
        """Remove all rules."""
        self._rules.clear()

    def to_list(self) -> list[dict]:
        """Serialise all rules to a JSON-compatible list of dicts."""
        return [r.to_dict() for r in self._rules]

    @classmethod
    def from_list(cls, data: list[dict]) -> "InterceptFilter":
        """Deserialise from a list of dicts produced by ``to_list()``."""
        filt = cls()
        for d in data:
            filt.add_rule(InterceptRule.from_dict(d))
        return filt
