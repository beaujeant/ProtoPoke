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
from ..events.bus import FrameCapturedEvent, SessionClosedEvent, SessionOpenedEvent
from ..project.manager import ProjectManager, ProjectState
from ..replay.models import RepeaterRequest
from .modals.new_request import NewRequestModal, NewRequestResult
from .modals.project import NewProjectModal, OpenProjectModal, SaveAsModal
from .tabs.config import ConfigTab
from .tabs.intercept import InterceptTab
from .tabs.logs import LogsTab
from .tabs.repeater import RepeaterTab

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


class _InterceptedArrived(Message):
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
        F2 → Logs tab
        F3 → Intercept tab
        F4 → Repeater tab
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
        Binding("f2",           "switch_tab('logs')",      "Logs",      show=True),
        Binding("f3",           "switch_tab('intercept')", "Intercept", show=True),
        Binding("f4",           "switch_tab('repeater')",  "Repeater",  show=True),
        Binding("ctrl+n",       "new_project",             "New",       show=False),
        Binding("ctrl+o",       "open_project",            "Open",      show=False),
        Binding("ctrl+s",       "save_project",            "Save",      show=False),
        Binding("ctrl+shift+s", "save_project_as",         "Save As",   show=False),
        Binding("ctrl+q",       "quit",                    "Quit",      show=True),
    ]

    CSS = """
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
            with TabPane("Logs [F2]", id="logs"):
                yield LogsTab(id="logs-tab")
            with TabPane("Intercept [F3]", id="intercept"):
                yield InterceptTab(id="intercept-tab")
            with TabPane("Repeater [F4]", id="repeater"):
                yield RepeaterTab(id="repeater-tab")
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
            self.query_one("#logs-tab", LogsTab).add_session(session)

    def on__session_closed(self, msg: _SessionClosed) -> None:
        session = self.api.get_session(msg.session_id)
        if session:
            self.query_one("#logs-tab", LogsTab).update_session(session)

    def on__frame_captured(self, msg: _FrameCaptured) -> None:
        session = self.api.get_session(msg.session_id)
        if session:
            self.query_one("#logs-tab", LogsTab).update_session(session)
            for frame in session.frames:
                if frame.id == msg.frame_id:
                    self.query_one("#logs-tab", LogsTab).add_frame_to_current(frame)
                    break

    # ------------------------------------------------------------------
    # Intercept queue polling
    # ------------------------------------------------------------------

    async def _poll_intercept_queue(self) -> None:
        """Drain any newly queued intercepted units and post them to the UI."""
        for unit in self.api.list_intercepted():
            intercept_tab = self.query_one("#intercept-tab", InterceptTab)
            if unit.id not in intercept_tab._units:
                intercept_tab.add_unit(unit)

    # ------------------------------------------------------------------
    # Config tab events
    # ------------------------------------------------------------------

    def on_config_tab_applied(self, _event: ConfigTab.Applied) -> None:
        self._project.mark_dirty()
        self._update_title()

    def on_config_tab_start_proxy(self, _event: ConfigTab.StartProxy) -> None:
        if not self._proxy_running:
            self.run_worker(self._start_proxy(), exclusive=False, thread=False)

    def on_config_tab_stop_proxy(self, _event: ConfigTab.StopProxy) -> None:
        if self._proxy_running:
            self.run_worker(self._stop_proxy(), exclusive=False, thread=False)

    async def _start_proxy(self) -> None:
        try:
            # Rebuild the ProxyAPI so changes to config (especially
            # intercept_enabled, framer_name) are picked up fresh.
            self._rebuild_api()
            await self.api.start()
            self._proxy_running = True
            self._update_title()
            # Sync the intercept toggle in the Intercept tab to reflect config
            try:
                self.query_one("#intercept-tab", InterceptTab).query_one(
                    "#intercept-toggle", Switch
                ).value = self.api.config.intercept_enabled
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
            self.notify("Proxy stopped.", severity="information")
        except Exception as exc:
            self.notify(f"Failed to stop proxy: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Tab switching actions
    # ------------------------------------------------------------------

    def action_switch_tab(self, tab_id: str) -> None:
        tabs = self.query_one("#tabs", TabbedContent)
        tabs.active = tab_id

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
        self.query_one("#config-tab", ConfigTab).load_config(self._project.config)
        self.query_one("#repeater-tab", RepeaterTab).load_requests([])
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
            self.query_one("#config-tab", ConfigTab).load_config(state.config)
            self.query_one("#repeater-tab", RepeaterTab).load_requests(state.repeater_requests)
            self._update_title()
            self.notify(f"Opened project: {state.name}")
        except Exception as exc:
            self.notify(f"Could not open project: {exc}", severity="error")

    def action_save_project(self) -> None:
        if self._project.path is None:
            self.action_save_project_as()
            return
        try:
            self._sync_repeater_requests()
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
            self._sync_repeater_requests()
            self._project.save_as(path)
            self._update_title()
            self.notify(f"Saved to {path}")
        except Exception as exc:
            self.notify(f"Save failed: {exc}", severity="error")

    def _sync_repeater_requests(self) -> None:
        """Copy the current repeater requests from the UI into the project."""
        repeater_tab = self.query_one("#repeater-tab", RepeaterTab)
        self._project.repeater_requests = list(repeater_tab._requests)

    # ------------------------------------------------------------------
    # Helpers for tabs to call
    # ------------------------------------------------------------------

    def open_new_request_modal(self) -> None:
        sessions = [
            (s.id, f"{s.info.client_host}:{s.info.client_port}", s.info.server_host, s.info.server_port)
            for s in self.api.list_sessions()
        ]
        self.push_screen(NewRequestModal(sessions), self._on_new_request)

    def _on_new_request(self, result: NewRequestResult | None) -> None:
        if result is None:
            return
        req = RepeaterRequest.create(
            label=result.label,
            host=result.host,
            port=result.port,
            tls=result.tls,
        )
        if result.session_id:
            # Pre-fill with frames from that session
            session = self.api.get_session(result.session_id)
            if session and session.frames:
                req.current_bytes = session.frames[0].raw_bytes
        self.query_one("#repeater-tab", RepeaterTab).add_request(req)
        self._project.repeater_requests.append(req)
        self.action_switch_tab("repeater")

    def send_frame_to_repeater(self, session_id: str, frame_id: str) -> None:
        """Called by LogsTab — create a repeater request from a captured frame."""
        session = self.api.get_session(session_id)
        if not session:
            return
        frame = next((f for f in session.frames if f.id == frame_id), None)
        if not frame:
            return
        req = RepeaterRequest.create(
            label=f"From {session_id[:8]}",
            host=session.info.server_host,
            port=session.info.server_port,
            tls=self.api.config.tls_upstream,
            current_bytes=frame.raw_bytes,
        )
        self.query_one("#repeater-tab", RepeaterTab).add_request(req)
        self._project.repeater_requests.append(req)
        self.action_switch_tab("repeater")
        self.notify(f"Frame sent to Repeater: {frame_id[:8]}")

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
