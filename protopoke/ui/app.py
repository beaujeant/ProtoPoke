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
from ..config import ForwarderConfig
from ..models import Direction
from ..events.bus import FrameCapturedEvent, SessionClosedEvent, SessionOpenedEvent, SessionUpdatedEvent, UpstreamConnectionFailedEvent
from ..project.manager import ProjectManager, ProjectState
from .modals.project import NewProjectModal, OpenProjectModal, SaveAsModal
from .tabs.config import ConfigTab
from .tabs.tamper import TamperTab
from .tabs.traffic import TrafficTab
from .tabs.forge import ForgeTab
from .tabs.fuzzer import FuzzerTab
from .tabs.logs import LogsTab

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


class _UpstreamConnectFailed(Message):
    def __init__(self, forwarder_name: str, client_host: str, client_port: int,
                 upstream_host: str, upstream_port: int, error: str) -> None:
        super().__init__()
        self.forwarder_name = forwarder_name
        self.client_host    = client_host
        self.client_port    = client_port
        self.upstream_host  = upstream_host
        self.upstream_port  = upstream_port
        self.error          = error


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
        F5 → Fuzzer tab
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
        Binding("f6",           "switch_tab('logs')",      "Logs",      show=True),
        Binding("ctrl+f",       "send_to_forge",           "→Forge",    show=False, priority=True),
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
        project: Optional[ProjectManager] = None,
    ) -> None:
        super().__init__()
        self._project = project or ProjectManager()
        self.api = ProxyAPI(
            forwarders=self._project.forwarders,
            rules_engine=self._project.rules_engine,
            intercept_filter=self._project.intercept_filter,
        )

        # Track which forwarder names are currently running
        self._running_forwarders: set[str] = set()

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(id="tabs"):
            with TabPane("Config [F1]", id="config"):
                yield ConfigTab(self._project.forwarders, id="config-tab")
            with TabPane("Traffic [F2]", id="traffic"):
                yield TrafficTab(id="traffic-tab")
            with TabPane("Tamper [F3]", id="tamper"):
                yield TamperTab(id="tamper-tab")
            with TabPane("Forge [F4]", id="forge"):
                yield ForgeTab(id="forge-tab")
            with TabPane("Fuzzer [F5]", id="fuzzer"):
                yield FuzzerTab(id="fuzzer-tab")
            with TabPane("Logs [F6]", id="logs"):
                yield LogsTab(id="logs-tab")
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

        async def on_session_updated(event: SessionUpdatedEvent) -> None:
            self.post_message(_SessionClosed(event.session.id))

        async def on_frame_captured(event: FrameCapturedEvent) -> None:
            self.post_message(_FrameCaptured(event.session.id, event.frame.id))

        async def on_upstream_connection_failed(event: UpstreamConnectionFailedEvent) -> None:
            self.post_message(_UpstreamConnectFailed(
                forwarder_name=event.forwarder_name,
                client_host=event.client_host,
                client_port=event.client_port,
                upstream_host=event.upstream_host,
                upstream_port=event.upstream_port,
                error=event.error,
            ))

        self.api.on_session_opened(on_session_opened)
        self.api.on_session_closed(on_session_closed)
        self.api.on_session_updated(on_session_updated)
        self.api.on_frame_captured(on_frame_captured)
        self.api.on_upstream_connection_failed(on_upstream_connection_failed)

    def on__session_opened(self, msg: _SessionOpened) -> None:
        session = self.api.get_session(msg.session_id)
        if session:
            self.query_one("#traffic-tab", TrafficTab).add_session(session)
            self.query_one("#fuzzer-tab", FuzzerTab).refresh_sessions(self.api.list_sessions())
            # Clear any upstream error banner — the forwarder can reach the server again
            if session.info.forwarder_name:
                self.query_one("#config-tab", ConfigTab).notify_forwarder_error(
                    session.info.forwarder_name, ""
                )

    def on__session_closed(self, msg: _SessionClosed) -> None:
        session = self.api.get_session(msg.session_id)
        if session:
            self.query_one("#traffic-tab", TrafficTab).update_session(session)
            self.query_one("#fuzzer-tab", FuzzerTab).refresh_sessions(self.api.list_sessions())

    def on__frame_captured(self, msg: _FrameCaptured) -> None:
        session = self.api.get_session(msg.session_id)
        if session:
            self.query_one("#traffic-tab", TrafficTab).update_session(session)
            for frame in session.frames:
                if frame.id == msg.frame_id:
                    self.query_one("#traffic-tab", TrafficTab).add_frame_to_current(frame)
                    break

    def on__upstream_connect_failed(self, msg: _UpstreamConnectFailed) -> None:
        error_label = f"error: {msg.error}"
        self.query_one("#config-tab", ConfigTab).notify_forwarder_error(
            msg.forwarder_name, error_label
        )

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

    def on_config_tab_forwarder_applied(self, event: ConfigTab.ForwarderApplied) -> None:
        """User applied settings for a specific forwarder."""
        self._project.mark_dirty()
        self._update_title()
        self._apply_dynamic_config_for(event.old_name, event.forwarder)

    def on_config_tab_forwarder_added(self, event: ConfigTab.ForwarderAdded) -> None:
        """User added a new forwarder — keep project in sync and auto-start if enabled."""
        if event.forwarder not in self._project.forwarders:
            self._project.forwarders.append(event.forwarder)
        self.api.update_forwarders(self._project.forwarders)
        self._project.mark_dirty()
        self._update_title()
        if event.forwarder.enabled:
            self.run_worker(
                self._start_forwarder(event.forwarder.name), exclusive=False, thread=False
            )

    def on_config_tab_forwarder_removed(self, event: ConfigTab.ForwarderRemoved) -> None:
        """User removed a forwarder."""
        self._project.forwarders = [
            f for f in self._project.forwarders if f.name != event.forwarder_name
        ]
        self._running_forwarders.discard(event.forwarder_name)
        self.api.update_forwarders(self._project.forwarders)
        self._project.mark_dirty()
        self._update_title()

    def on_config_tab_forwarder_enabled(self, event: ConfigTab.ForwarderEnabled) -> None:
        """User toggled a forwarder's enabled state — start or stop it."""
        self._project.mark_dirty()
        name = event.forwarder_name
        if event.enabled and name not in self._running_forwarders:
            self.run_worker(self._start_forwarder(name), exclusive=False, thread=False)
        elif not event.enabled and name in self._running_forwarders:
            self.run_worker(self._stop_forwarder(name), exclusive=False, thread=False)

    async def _start_forwarder(self, name: str) -> None:
        try:
            # Sync the API's forwarder list (config may have changed since last start)
            self.api.update_forwarders(self._project.forwarders)
            await self.api.start_forwarder(name)
            self._running_forwarders.add(name)
            self._update_title()
            fwd = next((f for f in self._project.forwarders if f.name == name), None)
            address = (
                f"{fwd.config.listen_host}:{fwd.config.listen_port}"
                if fwd else ""
            )
            self.query_one("#config-tab", ConfigTab).notify_forwarder_running(name, True, address)
            # Sync the tamper toggle in the Tamper tab
            try:
                any_tamper = any(f.config.tamper_enabled for f in self._project.forwarders)
                self.query_one("#tamper-tab", TamperTab).query_one(
                    "#tamper-toggle", Switch
                ).value = any_tamper
            except Exception:
                pass
        except Exception as exc:
            logger.error("Failed to start forwarder '%s': %s", name, exc)

    async def _stop_forwarder(self, name: str) -> None:
        try:
            await self.api.stop_forwarder(name)
            self._running_forwarders.discard(name)
            self._update_title()
            self.query_one("#config-tab", ConfigTab).notify_forwarder_running(name, False)
        except Exception as exc:
            logger.error("Failed to stop forwarder '%s': %s", name, exc)


    def _apply_dynamic_config_for(
        self, old_name: str, forwarder: ForwarderConfig
    ) -> None:
        """
        Apply config changes for a specific forwarder immediately.

        - Protocol definition: reloaded globally (shared decoder)
        - Log level: applied to the root logger
        - Framing: hot-swapped on the forwarder's active sessions
        - Forwarder name change: update API engine mapping
        """
        import logging as _logging

        new_name = forwarder.name
        cfg = forwarder.config

        # If name changed, update the API's engine registry
        if old_name != new_name:
            self.api.update_forwarders(self._project.forwarders)
            if old_name in self._running_forwarders:
                self._running_forwarders.discard(old_name)
                self._running_forwarders.add(new_name)

        # Protocol definition — reload so new frames are decoded
        if cfg.protocol_definition_path:
            try:
                self.api.set_protocol_file(cfg.protocol_definition_path)
            except Exception as exc:
                logger.warning("Protocol definition reload failed: %s", exc)
        else:
            from ..protocol.base import PassthroughDecoder
            self.api.set_protocol(PassthroughDecoder())

        # Log level — apply immediately
        try:
            _logging.getLogger().setLevel(cfg.log_level)
        except Exception:
            pass

        # Framing — hot-swap on this forwarder's active sessions
        try:
            swapped = self.api.set_framer(
                framer_name=cfg.framer_name,
                framer_kwargs=cfg.framer_kwargs,
                custom_framer_path=cfg.custom_framer_path,
                forwarder_name=new_name,
            )
            if swapped:
                logger.info("Framer updated on %d active session(s)", swapped)
        except Exception as exc:
            logger.warning("Framer hot-swap failed: %s", exc)

    # ------------------------------------------------------------------
    # Tab switching actions
    # ------------------------------------------------------------------

    def action_switch_tab(self, tab_id: str) -> None:
        tabs = self.query_one("#tabs", TabbedContent)
        tabs.active = tab_id

    def action_send_to_forge(self) -> None:
        """Ctrl+F — send the selected Traffic frame(s) to Forge."""
        traffic_tab = self.query_one("#traffic-tab", TrafficTab)
        if not traffic_tab._current_session_id:
            logger.warning("Select a frame in the Traffic tab first")
        elif len(traffic_tab._selected_frame_ids) > 1:
            self.send_frames_to_forge(
                traffic_tab._current_session_id,
                list(traffic_tab._selected_frame_ids),
            )
        elif traffic_tab._current_frame_id:
            self.send_frame_to_forge(
                traffic_tab._current_session_id, traffic_tab._current_frame_id
            )
        else:
            logger.warning("Select a frame in the Traffic tab first")

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
        config_tab.load_forwarders(self._project.forwarders)
        self.query_one("#traffic-tab", TrafficTab).clear_all()
        self.query_one("#forge-tab", ForgeTab).load_playbooks([])
        self.query_one("#fuzzer-tab", FuzzerTab).refresh_sessions([])
        self._update_title()
        logger.info("New project: %s", name)

    def action_open_project(self) -> None:
        self.push_screen(OpenProjectModal(), self._on_open_project)

    def _on_open_project(self, path: str | None) -> None:
        if not path:
            return
        try:
            state = self._project.open(path)
            self._rebuild_api_from_state(state)
            config_tab = self.query_one("#config-tab", ConfigTab)
            config_tab.load_forwarders(state.forwarders)
            self.query_one("#forge-tab", ForgeTab).load_playbooks(state.playbooks)
            # Restore logs: load sessions+frames into registry, then populate UI
            traffic_tab = self.query_one("#traffic-tab", TrafficTab)
            traffic_tab.clear_all()
            if state.captured_sessions:
                restored = self.api.load_sessions_from_dicts(state.captured_sessions)
                for session in restored:
                    traffic_tab.add_session(session)
                self.query_one("#fuzzer-tab", FuzzerTab).refresh_sessions(self.api.list_sessions())
            self._update_title()
            logger.info("Opened project: %s", state.name)
        except Exception as exc:
            logger.error("Could not open project: %s", exc)

    def action_save_project(self) -> None:
        if self._project.path is None:
            self.action_save_project_as()
            return
        try:
            self._sync_playbooks()
            self._project.save()
            self._update_title()
            logger.info("Project saved")
        except Exception as exc:
            logger.error("Save failed: %s", exc)

    def action_save_project_as(self) -> None:
        default = str(self._project.path) if self._project.path else ""
        self.push_screen(SaveAsModal(default), self._on_save_as)

    def _on_save_as(self, path: str | None) -> None:
        if not path:
            return
        try:
            self._sync_playbooks()
            self._project.save_as(path)
            self._update_title()
            logger.info("Saved to %s", path)
        except Exception as exc:
            logger.error("Save failed: %s", exc)

    def _sync_playbooks(self) -> None:
        """Copy the current UI state (forge playbooks, traffic) into the project."""
        forge_tab = self.query_one("#forge-tab", ForgeTab)
        forge_tab._save_frame_editor()
        self._project.playbooks = list(forge_tab._playbooks)
        self._project.captured_sessions = [
            self.api.session_to_dict(session)
            for session in self.api.list_sessions()
        ]

    def mark_dirty(self) -> None:
        """Mark the project as having unsaved changes."""
        self._project.mark_dirty()
        self._update_title()

    def terminate_session(self, session_id: str) -> None:
        """Terminate an active session (closes client + server connections)."""
        self.run_worker(
            self._terminate_session(session_id), exclusive=False, thread=False
        )

    async def _terminate_session(self, session_id: str) -> None:
        terminated = await self.api.terminate_session(session_id)
        if not terminated:
            logger.warning("Session %s is already closed", session_id[:8])

    def delete_session(self, session_id: str) -> None:
        """Delete a session from the registry and remove it from the Traffic tab."""
        deleted = self.api.delete_session(session_id)
        if deleted:
            self.query_one("#traffic-tab", TrafficTab).remove_session(session_id)
            self.query_one("#fuzzer-tab", FuzzerTab).refresh_sessions(
                self.api.list_sessions()
            )
        else:
            logger.warning("Session not found: %s", session_id[:8])

    def _tls_upstream_for_session(self, session_id: str) -> bool:
        """Look up tls_upstream from the forwarder that owns this session."""
        session = self.api.get_session(session_id)
        if session and session.info.forwarder_name:
            fwd = next(
                (f for f in self._project.forwarders if f.name == session.info.forwarder_name),
                None,
            )
            if fwd:
                return fwd.config.tls_upstream
        return False

    def send_frame_to_forge(self, session_id: str, frame_id: str) -> None:
        """Called by TrafficTab (Ctrl+F) — create a single-frame playbook in Forge."""
        session = self.api.get_session(session_id)
        if not session:
            return
        frame = next((f for f in session.frames if f.id == frame_id), None)
        if not frame:
            return
        direction = (
            "client_to_server"
            if frame.direction is Direction.CLIENT_TO_SERVER
            else "server_to_client"
        )
        forge_tab = self.query_one("#forge-tab", ForgeTab)
        forge_tab.add_playbook_from_bytes(
            raw_bytes=frame.raw_bytes,
            label=f"Playbook {len(forge_tab._playbooks)+1}",
            host=session.info.server_host,
            port=session.info.server_port,
            tls=self._tls_upstream_for_session(session_id),
            source_session_id=session_id,
            direction=direction,
        )
        self._project.mark_dirty()
        def _do_switch_forge() -> None:
            self.action_switch_tab("forge")
        def _schedule_switch_forge() -> None:
            self.call_after_refresh(_do_switch_forge)
        self.call_after_refresh(_schedule_switch_forge)
        logger.info("Frame sent to Forge: %s", frame_id[:8])

    def send_frames_to_forge(self, session_id: str, frame_ids: list[str]) -> None:
        """Called by TrafficTab — create a multi-frame playbook in Forge."""
        if not frame_ids:
            return
        session = self.api.get_session(session_id)
        if not session:
            return

        frames_by_id = {f.id: f for f in session.frames}
        first_frame = frames_by_id.get(frame_ids[0])
        if first_frame is None:
            return
        anchor_direction = first_frame.direction

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

        forge_tab = self.query_one("#forge-tab", ForgeTab)
        frames_data = [
            (f.raw_bytes, f"frame-{f.sequence_number}", direction_str)
            for f in selected_frames
        ]
        forge_tab.add_frames_to_playbook(
            frames_data=frames_data,
            host=session.info.server_host,
            port=session.info.server_port,
            tls=self._tls_upstream_for_session(session_id),
            source_session_id=session_id,
            playbook_label=f"Playbook {len(forge_tab._playbooks)+1}",
        )
        self._project.mark_dirty()
        def _do_switch_forge() -> None:
            self.action_switch_tab("forge")
        def _schedule_switch_forge() -> None:
            self.call_after_refresh(_do_switch_forge)
        self.call_after_refresh(_schedule_switch_forge)
        skipped = len(frame_ids) - len(selected_frames)
        msg = f"{len(selected_frames)} frame(s) added to Forge"
        if skipped:
            msg += f" ({skipped} skipped — wrong direction)"
        logger.info(msg)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_title(self) -> None:
        name  = self._project.name
        dirty = " *" if self._project.is_dirty else ""
        path  = f" [{self._project.path}]" if self._project.path else " [unsaved]"
        n = len(self._running_forwarders)
        running = f"  ▶ {n} RUNNING" if n else ""
        self.sub_title = f"{name}{dirty}{path}{running}"

    def _rebuild_api(self) -> None:
        """Replace the ProxyAPI with a fresh instance from current project state."""
        self.api = ProxyAPI(
            forwarders=self._project.forwarders,
            rules_engine=self._project.rules_engine,
            intercept_filter=self._project.intercept_filter,
        )
        self._register_event_handlers()
        self._running_forwarders.clear()

    def _rebuild_api_from_state(self, state: ProjectState) -> None:
        """Replace the ProxyAPI from a loaded ProjectState."""
        self.api = ProxyAPI(
            forwarders=state.forwarders,
            rules_engine=state.rules_engine,
            intercept_filter=state.intercept_filter,
        )
        self._register_event_handlers()
        self._running_forwarders.clear()


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

    logging.basicConfig(level=logging.INFO)
    app = ProtoPoke()
    app.run()


if __name__ == "__main__":
    main()
