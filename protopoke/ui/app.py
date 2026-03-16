"""ProtoPoke — main Textual application."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.widgets import Footer, Header, Switch, TabbedContent, TabPane

from ..api import ProxyAPI
from ..config import ProxyConfig
from ..models import Direction
from ..events.bus import FrameCapturedEvent, SessionClosedEvent, SessionOpenedEvent
from ..project.manager import ProjectManager, ProjectState
from ..forge.models import ForgeRequest
from .modals.request_modal import RequestModal, RequestResult
from .modals.project import NewProjectModal, OpenProjectModal, SaveAsModal
from .tabs.config import ConfigTab
from .tabs.fuzzer import FuzzerTab
from .tabs.tamper import TamperTab
from .tabs.traffic import TrafficTab
from .tabs.forge import ForgeTab
from .tabs.sequence import SequenceTab

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal messages posted by the proxy event handlers → main thread
# ---------------------------------------------------------------------------

class _SessionOpened(Message):
    def __init__(self, session_id: str) -> None:
        super().__init__()
        self.session_id = session_id


class _SessionClosed(Message):
    def __init__(self, session_id: str) -> None:
        super().__init__()
        self.session_id = session_id


class _FrameCaptured(Message):
    def __init__(self, session_id: str, frame_id: str) -> None:
        super().__init__()
        self.session_id = session_id
        self.frame_id   = frame_id


class _TamperedArrived(Message):
    def __init__(self, unit_id: str) -> None:
        super().__init__()
        self.unit_id = unit_id


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class ProtoPoke(App):
    """
    ProtoPoke TUI — Burp Suite for arbitrary binary protocols.

    Keyboard shortcuts:
        F1 → Config tab
        F2 → Traffic tab
        F3 → Tamper tab
        F4 → Forge tab
        ctrl+n → New project
        ctrl+o → Open project
        ctrl+s → Save project
        ctrl+shift+s → Save As
        ctrl+q → Quit
    """

    TITLE = "ProtoPoke"
    SUB_TITLE = "Binary Protocol Proxy"

    BINDINGS = [
        Binding("f1",           "switch_tab('config')",    "Config",    show=True),
        Binding("f2",           "switch_tab('traffic')",   "Traffic",   show=True),
        Binding("f3",           "switch_tab('tamper')",    "Tamper",    show=True),
        Binding("f4",           "switch_tab('forge')",     "Forge",     show=True),
        Binding("f5",           "switch_tab('fuzzer')",    "Fuzzer",    show=True),
        Binding("f6",           "switch_tab('sequence')",  "Sequence",  show=True),
        Binding("ctrl+r",       "send_to_forge",           "→Forge",    show=False, priority=True),
        Binding("ctrl+n",       "new_project",             "New",       show=False),
        Binding("ctrl+o",       "open_project",            "Open",      show=False),
        Binding("ctrl+s",       "save_project",            "Save",      show=False),
        Binding("ctrl+shift+s", "save_project_as",         "Save As",   show=False),
        Binding("ctrl+q",       "quit",                    "Quit",      show=True),
    ]

    DEFAULT_CSS = """
    ProtoPoke TabbedContent {
        height: 1fr;
    }
    ProtoPoke TabPane {
        padding: 0;
        height: 1fr;
    }
    ProtoPoke .status-dirty {
        color: $warning;
    }
    """

    def __init__(
        self,
        config: Optional[ProxyConfig] = None,
        project: Optional[ProjectManager] = None,
    ) -> None:
        super().__init__()
        self._project = project or ProjectManager()
        if config is not None:
            self._project.config = config

        self.api = ProxyAPI(
            config=self._project.config,
            rules_engine=self._project.rules_engine,
            intercept_filter=self._project.intercept_filter,
        )

        self._proxy_running = False

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(id="tabs"):
            with TabPane("Config [F1]", id="config"):
                yield ConfigTab(self._project.config, id="config-tab")
            with TabPane("Traffic [F2]", id="traffic"):
                yield TrafficTab(id="traffic-tab")
            with TabPane("Tamper [F3]", id="tamper"):
                yield TamperTab(id="tamper-tab")
            with TabPane("Forge [F4]", id="forge"):
                yield ForgeTab(id="forge-tab")
            with TabPane("Fuzzer [F5]", id="fuzzer"):
                yield FuzzerTab(id="fuzzer-tab")
            with TabPane("Sequence [F6]", id="sequence"):
                yield SequenceTab(id="sequence-tab")
        yield Footer()

    def on_mount(self) -> None:
        self._register_event_handlers()
        self._update_title()
        # Start polling the intercept queue in the background
        self.set_interval(0.2, self._poll_intercept_queue)

    # ------------------------------------------------------------------
    # Proxy event → Textual message bridge
    # ------------------------------------------------------------------

    def _register_event_handlers(self) -> None:
        """Register callbacks on the EventBus to post Textual messages."""

        async def on_session_opened(event: SessionOpenedEvent) -> None:
            self.post_message(_SessionOpened(event.session.id))

        async def on_session_closed(event: SessionClosedEvent) -> None:
            self.post_message(_SessionClosed(event.session.id))

        async def on_frame_captured(event: FrameCapturedEvent) -> None:
            self.post_message(_FrameCaptured(event.session.id, event.frame.id))

        self.api.on_session_opened(on_session_opened)
        self.api.on_session_closed(on_session_closed)
        self.api.on_frame_captured(on_frame_captured)

    def on__session_opened(self, msg: _SessionOpened) -> None:
        session = self.api.get_session(msg.session_id)
        if session:
            self.query_one("#traffic-tab", TrafficTab).add_session(session)
            self.query_one("#fuzzer-tab", FuzzerTab).refresh_sessions(self.api.list_sessions())
            self.query_one("#forge-tab", ForgeTab).refresh_session_dropdown()

    def on__session_closed(self, msg: _SessionClosed) -> None:
        session = self.api.get_session(msg.session_id)
        if session:
            self.query_one("#traffic-tab", TrafficTab).update_session(session)
            self.query_one("#fuzzer-tab", FuzzerTab).refresh_sessions(self.api.list_sessions())
            self.query_one("#forge-tab", ForgeTab).refresh_session_dropdown()

    def on__frame_captured(self, msg: _FrameCaptured) -> None:
        session = self.api.get_session(msg.session_id)
        if session:
            self.query_one("#traffic-tab", TrafficTab).update_session(session)
            for frame in session.frames:
                if frame.id == msg.frame_id:
                    self.query_one("#traffic-tab", TrafficTab).add_frame_to_current(frame)
                    break

    # ------------------------------------------------------------------
    # Tamper queue polling
    # ------------------------------------------------------------------

    async def _poll_intercept_queue(self) -> None:
        """Drain any newly queued intercepted units and post them to the UI."""
        for unit in self.api.list_intercepted():
            tamper_tab = self.query_one("#tamper-tab", TamperTab)
            if unit.id not in tamper_tab._units:
                tamper_tab.add_unit(unit)

    # ------------------------------------------------------------------
    # Config tab events
    # ------------------------------------------------------------------

    def on_config_tab_applied(self, _event: ConfigTab.Applied) -> None:
        self._project.mark_dirty()
        self._update_title()
        # If the proxy is already running, apply the changes that can take
        # effect without a restart (protocol definition, log level, etc.)
        if self._proxy_running:
            self._apply_dynamic_config()

    def on_config_tab_start_proxy(self, _event: ConfigTab.StartProxy) -> None:
        if not self._proxy_running:
            self.run_worker(self._start_proxy(), exclusive=False, thread=False)

    def on_config_tab_stop_proxy(self, _event: ConfigTab.StopProxy) -> None:
        if self._proxy_running:
            self.run_worker(self._stop_proxy(), exclusive=False, thread=False)

    async def _start_proxy(self) -> None:
        try:
            # Rebuild the ProxyAPI so changes to config (especially
            # tamper_enabled, framer_name) are picked up fresh.
            self._rebuild_api()
            await self.api.start()
            self._proxy_running = True
            self._update_title()
            self.query_one("#config-tab", ConfigTab).notify_proxy_running(True)
            # Sync the tamper toggle in the Tamper tab to reflect config
            try:
                self.query_one("#tamper-tab", TamperTab).query_one(
                    "#tamper-toggle", Switch
                ).value = self.api.config.tamper_enabled
            except Exception:
                pass
            self.notify(
                f"Proxy started on "
                f"{self.api.config.listen_host}:{self.api.config.listen_port}",
                severity="information",
            )
        except Exception as exc:
            self.notify(f"Failed to start proxy: {exc}", severity="error")

    async def _stop_proxy(self) -> None:
        try:
            await self.api.stop()
            self._proxy_running = False
            self._update_title()
            self.query_one("#config-tab", ConfigTab).notify_proxy_running(False)
            self.notify("Proxy stopped.", severity="information")
        except Exception as exc:
            self.notify(f"Failed to stop proxy: {exc}", severity="error")

    def _apply_dynamic_config(self) -> None:
        """
        Apply config changes that can take effect while the proxy is running.

        Called automatically by on_config_tab_applied() when _proxy_running is True.

        Changes that are applied immediately:
        - Protocol definition: reloaded via api.set_protocol_file()
        - Log level: applied to the root logger
        Changes that apply to new connections / next run (no extra action needed,
        they are read from api.config at the relevant time):
        - Framing (new connections use updated framer_name / framer_kwargs)
        - Sequence script (loaded fresh at the start of each run)
        - Max sessions (checked per new connection)
        """
        import logging as _logging

        cfg = self.api.config

        # Protocol definition — reload immediately so new frames are decoded
        if cfg.protocol_definition_path:
            try:
                self.api.set_protocol_file(cfg.protocol_definition_path)
            except Exception as exc:
                self.notify(
                    f"Protocol definition reload failed: {exc}", severity="warning"
                )
        else:
            # Path cleared — reset to passthrough decoder
            from ..protocol.base import PassthroughDecoder
            self.api.set_protocol(PassthroughDecoder())

        # Log level — apply to the root logger immediately
        try:
            _logging.getLogger().setLevel(cfg.log_level)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Tab switching actions
    # ------------------------------------------------------------------

    def action_switch_tab(self, tab_id: str) -> None:
        tabs = self.query_one("#tabs", TabbedContent)
        tabs.active = tab_id

    def action_send_to_forge(self) -> None:
        """Ctrl+R — send the selected Traffic frame to Forge."""
        traffic_tab = self.query_one("#traffic-tab", TrafficTab)
        if traffic_tab._current_frame_id and traffic_tab._current_session_id:
            self.send_frame_to_forge(
                traffic_tab._current_session_id, traffic_tab._current_frame_id
            )
        else:
            self.notify("Select a frame in the Traffic tab first.", severity="warning")

    # ------------------------------------------------------------------
    # Project management actions
    # ------------------------------------------------------------------

    def action_new_project(self) -> None:
        self.push_screen(NewProjectModal(), self._on_new_project)

    def _on_new_project(self, name: str | None) -> None:
        if name is None:
            return
        self._project.new(name)
        # Rebuild API with fresh state
        self._rebuild_api()
        config_tab = self.query_one("#config-tab", ConfigTab)
        config_tab.load_config(self._project.config)
        config_tab.notify_proxy_running(False)
        self.query_one("#traffic-tab", TrafficTab).clear_all()
        self.query_one("#forge-tab", ForgeTab).load_requests([])
        self.query_one("#sequence-tab", SequenceTab).load_sequences([])
        self.query_one("#fuzzer-tab", FuzzerTab).refresh_sessions([])
        self.query_one("#forge-tab", ForgeTab).refresh_session_dropdown()
        self._update_title()
        self.notify(f"New project: {name}")

    def action_open_project(self) -> None:
        self.push_screen(OpenProjectModal(), self._on_open_project)

    def _on_open_project(self, path: str | None) -> None:
        if not path:
            return
        try:
            state = self._project.open(path)
            self._rebuild_api_from_state(state)
            config_tab = self.query_one("#config-tab", ConfigTab)
            config_tab.load_config(state.config)
            config_tab.notify_proxy_running(False)
            self.query_one("#forge-tab", ForgeTab).load_requests(state.forge_requests)
            self.query_one("#sequence-tab", SequenceTab).load_sequences(state.sequence_sessions)
            # Restore logs: load sessions+frames into registry, then populate UI
            traffic_tab = self.query_one("#traffic-tab", TrafficTab)
            traffic_tab.clear_all()
            if state.captured_sessions:
                restored = self.api.load_sessions_from_dicts(state.captured_sessions)
                for session in restored:
                    # add_session populates the session row; show_frames is
                    # called automatically for the first session (auto-select).
                    # For all others the frames appear when the user selects them
                    # (on_data_table_row_highlighted looks up via api.get_session).
                    traffic_tab.add_session(session)
                self.query_one("#fuzzer-tab", FuzzerTab).refresh_sessions(self.api.list_sessions())
                self.query_one("#forge-tab", ForgeTab).refresh_session_dropdown()
            self._update_title()
            self.notify(f"Opened project: {state.name}")
        except Exception as exc:
            self.notify(f"Could not open project: {exc}", severity="error")

    def action_save_project(self) -> None:
        if self._project.path is None:
            self.action_save_project_as()
            return
        try:
            self._sync_forge_requests()
            self._project.save()
            self._update_title()
            self.notify("Project saved.")
        except Exception as exc:
            self.notify(f"Save failed: {exc}", severity="error")

    def action_save_project_as(self) -> None:
        default = str(self._project.path) if self._project.path else ""
        self.push_screen(SaveAsModal(default), self._on_save_as)

    def _on_save_as(self, path: str | None) -> None:
        if not path:
            return
        try:
            self._sync_forge_requests()
            self._project.save_as(path)
            self._update_title()
            self.notify(f"Saved to {path}")
        except Exception as exc:
            self.notify(f"Save failed: {exc}", severity="error")

    def _sync_forge_requests(self) -> None:
        """Copy the current UI state (forge, sequence, traffic) into the project."""
        forge_tab = self.query_one("#forge-tab", ForgeTab)
        self._project.forge_requests = list(forge_tab._requests)
        sequence_tab = self.query_one("#sequence-tab", SequenceTab)
        sequence_tab._save_step_editor()
        self._project.sequence_sessions = list(sequence_tab._sequences)
        # Sync logs: capture all sessions and their frames
        self._project.captured_sessions = [
            self.api.session_to_dict(session)
            for session in self.api.list_sessions()
        ]

    def mark_dirty(self) -> None:
        """Mark the project as having unsaved changes."""
        self._project.mark_dirty()
        self._update_title()

    # ------------------------------------------------------------------
    # Helpers for tabs to call
    # ------------------------------------------------------------------

    def open_new_request_modal(self) -> None:
        sessions = [
            (s.id, f"{s.info.client_host}:{s.info.client_port}", s.info.server_host, s.info.server_port)
            for s in self.api.list_sessions()
        ]
        self.push_screen(RequestModal(sessions), self._on_new_request)

    def _on_new_request(self, result: RequestResult | None) -> None:
        if result is None:
            return
        req = ForgeRequest.create(
            host=result.host,
            port=result.port,
            tls=result.tls,
            source_session_id=result.session_id,
            direction=result.direction,
        )
        req.response_window = result.window
        if result.session_id:
            # Pre-fill with frames from that session
            session = self.api.get_session(result.session_id)
            if session and session.frames:
                req.current_bytes = session.frames[0].raw_bytes
        self.query_one("#forge-tab", ForgeTab).add_request(req)
        self._project.forge_requests.append(req)
        def _do_sw_rep() -> None:
            self.action_switch_tab("forge")
        def _sched_sw_rep() -> None:
            self.call_after_refresh(_do_sw_rep)
        self.call_after_refresh(_sched_sw_rep)

    def terminate_session(self, session_id: str) -> None:
        """Terminate an active session (closes client + server connections)."""
        self.run_worker(
            self._terminate_session(session_id), exclusive=False, thread=False
        )

    async def _terminate_session(self, session_id: str) -> None:
        terminated = await self.api.terminate_session(session_id)
        if not terminated:
            self.notify("Session is already closed.", severity="warning")

    def delete_session(self, session_id: str) -> None:
        """Delete a session from the registry and remove it from the Traffic tab."""
        deleted = self.api.delete_session(session_id)
        if deleted:
            self.query_one("#traffic-tab", TrafficTab).remove_session(session_id)
            self.query_one("#fuzzer-tab", FuzzerTab).refresh_sessions(
                self.api.list_sessions()
            )
            self.query_one("#forge-tab", ForgeTab).refresh_session_dropdown()
        else:
            self.notify("Session not found.", severity="warning")

    def send_frames_to_sequence(
        self, session_id: str, frame_ids: list[str]
    ) -> None:
        """
        Called by TrafficTab — add one or more captured frames as new steps in
        the Sequence tab.

        Only frames whose direction matches the *first* frame in *frame_ids*
        are included, so a sequence always goes in a single direction.
        """
        if not frame_ids:
            return
        session = self.api.get_session(session_id)
        if not session:
            return

        # Resolve frames and determine the direction from the first one
        frames_by_id = {f.id: f for f in session.frames}
        first_frame = frames_by_id.get(frame_ids[0])
        if first_frame is None:
            return
        anchor_direction = first_frame.direction

        # Filter to frames matching that direction, in the order given
        selected_frames = [
            frames_by_id[fid]
            for fid in frame_ids
            if fid in frames_by_id and frames_by_id[fid].direction is anchor_direction
        ]
        if not selected_frames:
            return

        direction_str = (
            "client_to_server"
            if anchor_direction is Direction.CLIENT_TO_SERVER
            else "server_to_client"
        )

        seq_tab = self.query_one("#sequence-tab", SequenceTab)
        for frame in selected_frames:
            seq_tab.add_step_from_bytes(
                raw_bytes=frame.raw_bytes,
                label=f"seq={frame.sequence_number}",
                host=session.info.server_host,
                port=session.info.server_port,
                tls=self.api.config.tls_upstream,
                source_session_id=session_id,
                direction=direction_str,
            )

        self._project.mark_dirty()
        # Double call_after_refresh: lets all widget mounts (new sequence buttons,
        # DataTable updates) settle before the tab switch is applied.
        def _do_switch_sequence() -> None:
            self.action_switch_tab("sequence")
        def _schedule_switch_sequence() -> None:
            self.call_after_refresh(_do_switch_sequence)
        self.call_after_refresh(_schedule_switch_sequence)
        skipped = len(frame_ids) - len(selected_frames)
        msg = f"{len(selected_frames)} frame(s) added to Sequence"
        if skipped:
            msg += f" ({skipped} skipped — wrong direction)"
        self.notify(msg)

    def send_frame_to_forge(self, session_id: str, frame_id: str) -> None:
        """Called by TrafficTab — create a forge request from a captured frame."""
        session = self.api.get_session(session_id)
        if not session:
            return
        frame = next((f for f in session.frames if f.id == frame_id), None)
        if not frame:
            return
        direction = (
            "to_server"
            if frame.direction is Direction.CLIENT_TO_SERVER
            else "to_client"
        )
        req = ForgeRequest.create(
            host=session.info.server_host,
            port=session.info.server_port,
            tls=self.api.config.tls_upstream,
            current_bytes=frame.raw_bytes,
            source_session_id=session_id,
            direction=direction,
        )
        self.query_one("#forge-tab", ForgeTab).add_request(req)
        self._project.forge_requests.append(req)
        # Double call_after_refresh: the first refresh lets the mount settle,
        # the second actually performs the tab switch so it lands after all
        # reactive DOM updates triggered by the mount have been processed.
        def _do_switch_forge() -> None:
            self.action_switch_tab("forge")
        def _schedule_switch_forge() -> None:
            self.call_after_refresh(_do_switch_forge)
        self.call_after_refresh(_schedule_switch_forge)
        self.notify(f"Frame sent to Forge: {frame_id[:8]}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_title(self) -> None:
        name  = self._project.name
        dirty = " *" if self._project.is_dirty else ""
        path  = f" [{self._project.path}]" if self._project.path else " [unsaved]"
        running = "  ▶ RUNNING" if self._proxy_running else ""
        self.sub_title = f"{name}{dirty}{path}{running}"

    def _rebuild_api(self) -> None:
        """Replace the ProxyAPI with a fresh instance from current project state."""
        self.api = ProxyAPI(
            config=self._project.config,
            rules_engine=self._project.rules_engine,
            intercept_filter=self._project.intercept_filter,
        )
        self._register_event_handlers()
        self._proxy_running = False

    def _rebuild_api_from_state(self, state: ProjectState) -> None:
        """Replace the ProxyAPI from a loaded ProjectState."""
        self.api = ProxyAPI(
            config=state.config,
            rules_engine=state.rules_engine,
            intercept_filter=state.intercept_filter,
        )
        self._register_event_handlers()
        self._proxy_running = False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Launch the ProtoPoke TUI, or the MCP server when ``--mcp`` is passed.

    When run as ``protopoke --mcp [options]`` the TUI is skipped and the
    proxy + MCP server starts instead (identical to ``protopoke-mcp``).
    Pass ``--help`` after ``--mcp`` to see MCP-specific options.
    """
    import sys

    if "--mcp" in sys.argv:
        # Strip --mcp from argv and hand the rest to the MCP runner
        mcp_argv = [a for a in sys.argv[1:] if a != "--mcp"]
        from ..mcp.runner import main as mcp_main
        mcp_main(mcp_argv)
        return

    logging.basicConfig(level=logging.WARNING)
    app = ProtoPoke()
    app.run()


if __name__ == "__main__":
    main()
