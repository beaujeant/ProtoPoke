"""
FuzzerTab — Textual TUI tab for the fuzzing subsystem.

Layout:
  ┌──────────────────────────────────────────────────────────────────┐
  │ Session: [<id> ▸]  Frames: [all     ]  Iter: [50]  [✓] Stop crash│  config bar
  │ Mutators: [✓] BitFlip  [✓] ByteInsert  [✓] KnownBad  [ ] Radamsa │  mutator bar
  │ [▶ Start Campaign]  [■ Stop]                          Status: Idle│  action bar
  ├──────────────────────────────────────────────────────────────────┤
  │ #   Mutator          Sent(B)  Resp(B)  ΔSize   Time(ms)  Flags   │  results table
  │ …                                                                  │
  └──────────────────────────────────────────────────────────────────┘

"Flags" column shows: C=crash (TCP RST), T=timeout, ★=interesting.

Clicking a result row opens the mutated bytes in the Forge tab.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Button, Checkbox, DataTable, Input, Label, Select, Static

if TYPE_CHECKING:
    from ...fuzzing.models import FuzzResult

logger = logging.getLogger(__name__)


class FuzzerTab(Widget):
    """
    Tab 5 — Fuzzer: configure and run a fuzzing campaign.
    """

    DEFAULT_CSS = """
    FuzzerTab {
        layout: vertical;
    }
    FuzzerTab .config-bar {
        height: 3;
        align: left middle;
        background: $surface-darken-1;
        padding: 0 1;
    }
    FuzzerTab .config-bar Label {
        margin-right: 1;
    }
    FuzzerTab .config-bar Input {
        width: 8;
        margin-right: 2;
    }
    FuzzerTab .mutator-bar {
        height: 3;
        align: left middle;
        background: $surface-darken-2;
        padding: 0 1;
    }
    FuzzerTab .mutator-bar Checkbox {
        margin-right: 1;
    }
    FuzzerTab .action-bar {
        height: 3;
        align: left middle;
        background: $surface-darken-1;
        padding: 0 1;
    }
    FuzzerTab .action-bar Button {
        margin-right: 1;
        padding: 0 0;
    }
    FuzzerTab #status-label {
        margin-left: 2;
        color: $text-muted;
    }
    FuzzerTab #results-pane {
        height: 1fr;
    }
    FuzzerTab DataTable {
        height: 1fr;
    }
    FuzzerTab .pane-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
        text-style: bold;
    }
    FuzzerTab #session-select {
        width: 22;
        margin-right: 2;
    }
    FuzzerTab #frame-selector-input {
        width: 10;
    }
    FuzzerTab #iter-input {
        width: 6;
    }
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._campaign_running = False
        self._session_ids: list[str] = []

    def compose(self) -> ComposeResult:
        # Config bar
        with Horizontal(classes="config-bar"):
            yield Label("Session:")
            yield Select(
                [],
                id="session-select",
                prompt="(none)",
                allow_blank=True,
            )
            yield Label("Frames:")
            yield Input(placeholder="all", id="frame-selector-input")
            yield Label("Iter:")
            yield Input("50", id="iter-input")
            yield Checkbox("Stop on crash", value=True, id="stop-crash-cb")

        # Mutator bar
        with Horizontal(classes="mutator-bar"):
            yield Label("Mutators:")
            yield Checkbox("BitFlip",    value=True,  id="mut-bitflip")
            yield Checkbox("ByteInsert", value=False, id="mut-byteinsert")
            yield Checkbox("ByteDelete", value=False, id="mut-bytedelete")
            yield Checkbox("KnownBad",   value=True,  id="mut-knownbad")
            yield Checkbox("Radamsa",    value=False, id="mut-radamsa")
            yield Checkbox("FieldBoundary", value=False, id="mut-fieldboundary")
            yield Checkbox("FieldOverflow", value=False, id="mut-fieldoverflow")
            yield Checkbox("NullByte",   value=False, id="mut-nullbyte")
            yield Checkbox("LengthMangle", value=False, id="mut-lengthmangle")

        # Action bar
        with Horizontal(classes="action-bar"):
            yield Button("▶ Start Campaign", variant="success", id="btn-start")
            yield Button("■ Stop",           variant="error",   id="btn-stop")
            yield Label("Status: Idle", id="status-label")

        # Results table
        with Vertical(id="results-pane"):
            yield Static("  Fuzz Results", classes="pane-header")
            yield DataTable(id="results-table", cursor_type="row")

    def on_mount(self) -> None:
        dt = self.query_one("#results-table", DataTable)
        dt.add_column("#",        key="num")
        dt.add_column("Mutator",  key="mutator")
        dt.add_column("Sent(B)",  key="sent")
        dt.add_column("Resp(B)",  key="resp")
        dt.add_column("ΔSize",    key="delta")
        dt.add_column("Time(ms)", key="time")
        dt.add_column("Flags",    key="flags")

    # ------------------------------------------------------------------
    # Session list refresh (called by app when sessions change)
    # ------------------------------------------------------------------

    def refresh_sessions(self, sessions: list) -> None:
        """Update the session dropdown with current sessions."""
        options = [(f"{s.id[:8]}… {s.info.server_host}:{s.info.server_port}", s.id)
                   for s in sessions]
        select = self.query_one("#session-select", Select)
        select.set_options(options)

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""

        if bid == "btn-start":
            event.stop()
            self._start_campaign()

        elif bid == "btn-stop":
            event.stop()
            self._stop_campaign()

    def _start_campaign(self) -> None:
        if self._campaign_running:
            logger.warning("Campaign already running")
            return

        # Read session
        select = self.query_one("#session-select", Select)
        if select.value is Select.BLANK or select.value is None:
            logger.warning("Select a session first")
            return
        session_id = str(select.value)

        # Read frame selector
        frame_sel_raw = self.query_one("#frame-selector-input", Input).value.strip()
        frame_selector = frame_sel_raw if frame_sel_raw and frame_sel_raw != "all" else None

        # Read iterations
        try:
            iterations = int(self.query_one("#iter-input", Input).value.strip())
        except ValueError:
            logger.error("Iterations must be an integer")
            return

        stop_on_crash = self.query_one("#stop-crash-cb", Checkbox).value

        # Build mutator list
        mutators = self._build_mutators()
        if not mutators:
            logger.warning("Select at least one mutator")
            return

        self._campaign_running = True
        self._update_status("Running…")
        self.query_one("#results-table", DataTable).clear()

        self.run_worker(
            self._run_campaign_worker(
                session_id=session_id,
                mutators=mutators,
                iterations=iterations,
                frame_selector=frame_selector,
                stop_on_crash=stop_on_crash,
            ),
            exclusive=True,
        )

    def _stop_campaign(self) -> None:
        # Signal is communicated via the campaign object in the engine;
        # here we just set the flag so the worker notices when it checks.
        self._campaign_running = False
        self._update_status("Stopping…")

    async def _run_campaign_worker(
        self,
        session_id:     str,
        mutators:       list,
        iterations:     int,
        frame_selector: str | None,
        stop_on_crash:  bool,
    ) -> None:
        def on_result(result: "FuzzResult") -> None:
            self._append_result(result)
            if not self._campaign_running:
                # Worker detected stop request — propagate to engine via campaign
                pass

        try:
            campaign = await self.app.api.fuzz_session(
                session_id=session_id,
                mutators=mutators,
                iterations=iterations,
                frame_selector=frame_selector,
                stop_on_crash=stop_on_crash,
                on_result=on_result,
            )
            n_interesting = len(campaign.interesting_results)
            n_crash       = len(campaign.crash_results)
            status = (
                f"Done — {campaign.completed_iterations} iterations, "
                f"{n_interesting} interesting, {n_crash} crashes"
            )
            self._update_status(status)
            logger.info(status)
        except Exception as exc:
            self._update_status(f"Error: {exc}")
            logger.error("Campaign error: %s", exc)
        finally:
            self._campaign_running = False

    # ------------------------------------------------------------------
    # Result display
    # ------------------------------------------------------------------

    def _append_result(self, result: "FuzzResult") -> None:
        dt = self.query_one("#results-table", DataTable)
        flags = ""
        if result.connection_reset:
            flags += "C"
        if result.timed_out:
            flags += "T"
        if result.interesting:
            flags += "★"

        delta_str = f"{result.response_size_delta:+d}" if result.baseline_response_size else "—"

        dt.add_row(
            str(result.iteration + 1),
            result.mutator_name,
            str(len(result.mutated_bytes)),
            str(result.response_size) if result.response_bytes is not None else "—",
            delta_str,
            f"{result.response_time_ms:.0f}",
            flags or "—",
            key=result.id,
        )
        # Scroll to the last row so the user sees live updates
        dt.move_cursor(row=dt.row_count - 1)

    # ------------------------------------------------------------------
    # Row selection → send to Forge
    # ------------------------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "results-table":
            return
        result_id = str(event.row_key.value)
        # Look up the result in the API's last campaign
        # The simplest approach: search in all available campaigns
        # (app will need to expose this; for now notify the user)
        logger.info(
            "Result %s selected — use Forge to replay mutated bytes manually",
            result_id[:8],
        )

    # ------------------------------------------------------------------
    # Status helper
    # ------------------------------------------------------------------

    def _update_status(self, text: str) -> None:
        try:
            self.query_one("#status-label", Label).update(f"Status: {text}")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Mutator construction
    # ------------------------------------------------------------------

    def _build_mutators(self) -> list:
        from ...fuzzing.mutators import (
            BitFlipMutator,
            ByteDeleteMutator,
            ByteInsertMutator,
            FieldBoundaryMutator,
            FieldOverflowMutator,
            KnownBadMutator,
            LengthMangleMutator,
            NullByteMutator,
            RadamsaMutator,
        )

        mutators = []
        cb = lambda id_: self.query_one(f"#{id_}", Checkbox).value  # noqa: E731

        if cb("mut-bitflip"):
            mutators.append(BitFlipMutator())
        if cb("mut-byteinsert"):
            mutators.append(ByteInsertMutator())
        if cb("mut-bytedelete"):
            mutators.append(ByteDeleteMutator())
        if cb("mut-knownbad"):
            mutators.append(KnownBadMutator())
        if cb("mut-radamsa"):
            mutators.append(RadamsaMutator())

        # Protocol-aware mutators require the encoder
        encoder = getattr(self.app.api, "_encoder", None)
        if encoder is not None:
            if cb("mut-fieldboundary"):
                mutators.append(FieldBoundaryMutator(encoder))
            if cb("mut-fieldoverflow"):
                mutators.append(FieldOverflowMutator(encoder))
            if cb("mut-nullbyte"):
                mutators.append(NullByteMutator(encoder))
            if cb("mut-lengthmangle"):
                mutators.append(LengthMangleMutator(encoder))
        else:
            # Warn if protocol-aware mutators were requested but no encoder is loaded
            for mid in ("mut-fieldboundary", "mut-fieldoverflow", "mut-nullbyte", "mut-lengthmangle"):
                if cb(mid):
                    logger.warning(
                        "Protocol-aware mutators require a protocol definition — "
                        "load one in Config first"
                    )
                    break

        return mutators
