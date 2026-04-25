"""Tests for the SegmentedControl widget."""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Button

from protopoke.ui.widgets.segmented_control import SegmentedControl


def _build_app(
    options: list[tuple[str, object]],
    *,
    value: object = None,
    disabled_values: set[object] | None = None,
):
    class _Host(App):
        def compose(self) -> ComposeResult:
            yield SegmentedControl(
                options,
                value=value,
                disabled_values=disabled_values,
                id="sc",
                name="test_ctl",
            )

    return _Host()


async def test_initial_value_renders_active_class():
    app = _build_app([("A", "a"), ("B", "b")], value="b")
    async with app.run_test() as pilot:
        sc = pilot.app.query_one("#sc", SegmentedControl)
        seg0 = sc.query_one("#_seg-0", Button)
        seg1 = sc.query_one("#_seg-1", Button)
        assert not seg0.has_class("active")
        assert seg1.has_class("active")


async def test_press_posts_changed_with_value():
    app = _build_app([("A", "a"), ("B", "b")], value="a")
    received: list[SegmentedControl.Changed] = []

    class _Recorder(App):
        def compose(self) -> ComposeResult:
            yield SegmentedControl(
                [("A", "a"), ("B", "b")],
                value="a",
                id="sc",
                name="test_ctl",
            )

        def on_segmented_control_changed(self, event: SegmentedControl.Changed) -> None:
            received.append(event)

    async with _Recorder().run_test() as pilot:
        sc = pilot.app.query_one("#sc", SegmentedControl)
        seg1 = sc.query_one("#_seg-1", Button)
        seg1.press()
        await pilot.pause()

    assert len(received) == 1
    assert received[0].value == "b"
    assert received[0].control_name == "test_ctl"


async def test_setter_does_not_post():
    received: list[SegmentedControl.Changed] = []

    class _Recorder(App):
        def compose(self) -> ComposeResult:
            yield SegmentedControl(
                [("A", "a"), ("B", "b")],
                value="a",
                id="sc",
                name="test_ctl",
            )

        def on_segmented_control_changed(self, event: SegmentedControl.Changed) -> None:
            received.append(event)

    async with _Recorder().run_test() as pilot:
        sc = pilot.app.query_one("#sc", SegmentedControl)
        sc.value = "b"
        await pilot.pause()
        seg0 = sc.query_one("#_seg-0", Button)
        seg1 = sc.query_one("#_seg-1", Button)
        assert not seg0.has_class("active")
        assert seg1.has_class("active")
        assert sc.value == "b"

    assert received == []


async def test_disabled_values_block_press():
    received: list[SegmentedControl.Changed] = []

    class _Recorder(App):
        def compose(self) -> ComposeResult:
            yield SegmentedControl(
                [("A", "a"), ("B", "b")],
                value="a",
                disabled_values={"b"},
                id="sc",
                name="test_ctl",
            )

        def on_segmented_control_changed(self, event: SegmentedControl.Changed) -> None:
            received.append(event)

    async with _Recorder().run_test() as pilot:
        sc = pilot.app.query_one("#sc", SegmentedControl)
        seg1 = sc.query_one("#_seg-1", Button)
        assert seg1.disabled
        seg1.press()
        await pilot.pause()
        assert sc.value == "a"
        assert seg1.has_class("active") is False

    assert received == []


async def test_set_disabled_values_repaints():
    """Active value is left alone even when it becomes disabled — the caller's
    job is to also reassign. This matches ParsedView.show_frame semantics."""
    app = _build_app([("A", "a"), ("B", "b")], value="a")
    async with app.run_test() as pilot:
        sc = pilot.app.query_one("#sc", SegmentedControl)
        sc.set_disabled_values({"a"})
        await pilot.pause()
        seg0 = sc.query_one("#_seg-0", Button)
        assert seg0.disabled
        assert not seg0.has_class("active")  # disabled segment never shows as active
        assert sc.value == "a"  # value unchanged


async def test_height_is_one_cell():
    """Regression guard: the widget MUST stay 1 cell tall so it fits inside
    the existing 1-line pane-headers."""
    app = _build_app([("A", "a"), ("B", "b")], value="a")
    async with app.run_test() as pilot:
        sc = pilot.app.query_one("#sc", SegmentedControl)
        assert sc.region.height == 1


async def test_compact_default():
    app = _build_app([("A", "a"), ("B", "b")], value="a")
    async with app.run_test() as pilot:
        sc = pilot.app.query_one("#sc", SegmentedControl)
        for idx in range(2):
            btn = sc.query_one(f"#_seg-{idx}", Button)
            assert btn.compact is True


async def test_none_value_supported():
    """Used by Tamper direction filter where 'Both' has value None."""
    app = _build_app([("Both", None), ("Yes", True)], value=None)
    async with app.run_test() as pilot:
        sc = pilot.app.query_one("#sc", SegmentedControl)
        seg0 = sc.query_one("#_seg-0", Button)
        seg1 = sc.query_one("#_seg-1", Button)
        assert seg0.has_class("active")
        assert not seg1.has_class("active")
        assert sc.value is None
