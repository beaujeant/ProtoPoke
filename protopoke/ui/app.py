"""ProtoPoke — main Textual application."""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.widgets import Footer, Header, Switch, TabbedContent, TabPane

from ..api import ProtoPokeAPI
from ..config import ForwarderConfig
from ..mcp.host import MCPHost, MCPSettings, mcp_available
from ..models import Direction
from ..events.bus import FrameCapturedEvent, SessionClosedEvent, SessionOpenedEvent, SessionUpdatedEvent, UpstreamConnectionFailedEvent
from ..project.manager import ProjectManager, ProjectState
from .modals.confirm import ConfirmModal
from .modals.project import OpenProjectModal, SaveAsModal
from .tabs.config import ConfigTab
from .tabs.tamper import TamperTab
from .tabs.traffic import TrafficTab
from .tabs.forge import ForgeTab
from .tabs.fuzzer import FuzzerTab
from .tabs.notes import NotesTab
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


class _SessionUpdated(Message):
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
        F6 → Notes tab
        F7 → Logs tab
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
        #Binding("f5",           "switch_tab('fuzzer')",    "Fuzzer",    show=True),
        Binding("f5",           "switch_tab('notes')",     "Notes",     show=True),
        Binding("f6",           "switch_tab('logs')",      "Logs",      show=True),
        Binding("ctrl+f",       "send_to_forge",           "→Forge",    show=False, priority=True),
        Binding("ctrl+o",       "open_project",            "Open",      show=False, priority=True),
        Binding("ctrl+s",       "save_project",            "Save",      show=False, priority=True),
        Binding("ctrl+shift+s", "save_project_as",         "Save As",   show=False, priority=True),
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
        mcp_settings: Optional[MCPSettings] = None,
    ) -> None:
        super().__init__()
        self._project = project or ProjectManager()
        self.api = ProtoPokeAPI(
            forwarders=self._project.forwarders,
            rules_engine=self._project.rules_engine,
            intercept_filter=self._project.intercept_filter,
            knowledge=self._project.knowledge,
        )

        # Track which forwarder names are currently running
        self._running_forwarders: set[str] = set()

        # Embedded MCP server bound to this app's ProtoPokeAPI.  The host
        # closes over ``lambda: self.api`` so that project reloads (which
        # reassign ``self.api``) propagate automatically via ``rebind``.
        self._mcp_host = MCPHost(
            lambda: self.api,
            settings=mcp_settings or self._project_mcp_settings(),
        )

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(id="tabs"):
            with TabPane("Config [F1]", id="config"):
                yield ConfigTab(
                    self._project.forwarders,
                    replace(self._mcp_host.settings),
                    id="config-tab",
                )
            with TabPane("Traffic [F2]", id="traffic"):
                yield TrafficTab(id="traffic-tab")
            with TabPane("Tamper [F3]", id="tamper"):
                yield TamperTab(id="tamper-tab")
            with TabPane("Forge [F4]", id="forge"):
                yield ForgeTab(id="forge-tab")
            #with TabPane("Fuzzer [F5]", id="fuzzer"):
            #    yield FuzzerTab(id="fuzzer-tab")
            with TabPane("Notes [F6]", id="notes"):
                yield NotesTab(self.api, id="notes-tab")
            with TabPane("Logs [F7]", id="logs"):
                yield LogsTab(id="logs-tab")
        yield Footer()

    def on_mount(self) -> None:
        self._register_event_handlers()
        self._update_title()
        # Start polling the intercept queue in the background
        self.set_interval(0.2, self._poll_intercept_queue)
        # Launch the embedded MCP server if it is enabled.  The host is a
        # no-op when ``settings.enabled`` is False, so this is safe to call
        # unconditionally.
        self.run_worker(
            self._mcp_host.start(),
            name="mcp-host-start",
            exclusive=False,
            thread=False,
        )

    async def on_unmount(self) -> None:
        """Stop the embedded MCP server cleanly on app shutdown."""
        try:
            await self._mcp_host.stop()
        except Exception:
            logger.exception("Failed to stop MCP host on app shutdown")

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
            self.post_message(_SessionUpdated(event.session.id))

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

    def on__session_updated(self, msg: _SessionUpdated) -> None:
        session = self.api.get_session(msg.session_id)
        if session:
            self.query_one("#traffic-tab", TrafficTab).update_session(session)

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
        """
        Forward any pending intercepted units from the tamper queue to the UI.

        Called on a 200 ms timer.  Compares the controller's pending list against
        the units already displayed in the Tamper tab and adds any that are new.
        This avoids duplicates without requiring a dedicated asyncio task.
        """
        for unit in self.api.list_intercepted():
            tamper_tab = self.query_one("#tamper-tab", TamperTab)
            if unit.id not in tamper_tab._units:
                tamper_tab.add_unit(unit)

    # ------------------------------------------------------------------
    # Config tab events
    # ------------------------------------------------------------------

    def on_config_tab_forwarder_applied(self, event: ConfigTab.ForwarderApplied) -> None:
        """User applied settings for a specific forwarder."""
        # Hot-swap name/framer/protocol on the running engine first, while the
        # engine is still registered under event.old_name.  update_forwarders()
        # must come after so it finds the engine under its (possibly new) name.
        self._apply_dynamic_config_for(event.old_name, event.forwarder)
        # Sync the project's forwarder list so that subsequent start/stop
        # cycles pick up the new config (host, port, TLS, etc.).
        for i, fwd in enumerate(self._project.forwarders):
            if fwd.name == event.old_name:
                self._project.forwarders[i] = event.forwarder
                break
        self.api.update_forwarders(self._project.forwarders)
        self._project.mark_dirty()
        self._update_title()

    def on_config_tab_forwarder_added(self, event: ConfigTab.ForwarderAdded) -> None:
        """User added a new forwarder — keep project in sync and auto-start if enabled."""
        if event.forwarder not in self._project.forwarders:
            self._project.forwarders.append(event.forwarder)
        self.api.update_forwarders(self._project.forwarders)
        self._project.mark_dirty()
        self._update_title()
        if event.forwarder.enabled:
            self.run_worker(
                self._add_and_start_forwarder(event.forwarder), exclusive=False, thread=False
            )

    def on_config_tab_forwarder_removed(self, event: ConfigTab.ForwarderRemoved) -> None:
        """User removed a forwarder — confirm if active sessions exist."""
        name = event.forwarder_name
        active = [
            s for s in self.api.session_registry.active_sessions()
            if s.info.forwarder_name == name
        ]
        if active:
            count = len(active)
            noun = "connection" if count == 1 else "connections"
            self.app.push_screen(
                ConfirmModal(
                    title="Active connections",
                    body=(
                        f"Forwarder '{name}' still has {count} active {noun}.\n"
                        f"Delete anyway and close all {noun}?"
                    ),
                    confirm_label="Delete & close",
                    confirm_variant="error",
                ),
                lambda confirmed, _name=name: self._on_remove_confirmed(confirmed, _name),
            )
        elif name in self._running_forwarders:
            self.run_worker(
                self._stop_and_remove_forwarder(name), exclusive=False, thread=False
            )
        else:
            self._do_remove_forwarder(name)

    def _on_remove_confirmed(self, confirmed: bool, name: str) -> None:
        if not confirmed:
            return
        self.run_worker(
            self._stop_and_remove_forwarder(name), exclusive=False, thread=False
        )

    def _do_remove_forwarder(self, name: str) -> None:
        self.query_one("#config-tab", ConfigTab).confirm_remove_forwarder(name)
        self._project.forwarders = [
            f for f in self._project.forwarders if f.name != name
        ]
        self._running_forwarders.discard(name)
        self.api.update_forwarders(self._project.forwarders)
        self._project.mark_dirty()
        self._update_title()

    async def _stop_and_remove_forwarder(self, name: str) -> None:
        await self._stop_forwarder(name)
        self._do_remove_forwarder(name)

    def on_config_tab_forwarder_enabled(self, event: ConfigTab.ForwarderEnabled) -> None:
        """User toggled a forwarder's enabled state — start or stop it."""
        self._project.mark_dirty()
        name = event.forwarder_name
        if event.enabled and name not in self._running_forwarders:
            self.run_worker(self._start_forwarder(name), exclusive=False, thread=False)
        elif not event.enabled and name in self._running_forwarders:
            self.run_worker(self._stop_forwarder(name), exclusive=False, thread=False)

    async def on_config_tab_mcpsettings_changed(self, event: ConfigTab.MCPSettingsChanged) -> None:
        """User edited the embedded MCP server settings — apply them."""
        logger.debug("MCPSettingsChanged received: enabled=%s", event.settings.enabled)
        previous_enabled = self._mcp_host.settings.enabled

        if event.settings.enabled and not mcp_available():
            logger.warning(
                "MCP server enable requested but the 'mcp' package is not "
                "installed; keeping MCP disabled."
            )
            self.notify(
                "MCP server unavailable: install with `pip install protopoke[mcp]`.",
                severity="warning",
                timeout=8,
            )
            self._revert_mcp_switch(False)
            return

        try:
            await self.apply_mcp_settings(event.settings)
        except ImportError as exc:
            logger.error("MCP server cannot start: %s", exc)
            self.notify(
                "MCP server unavailable: install with `pip install protopoke[mcp]`.",
                severity="error",
                timeout=8,
            )
            self._revert_mcp_switch(previous_enabled)
        except Exception as exc:
            logger.exception("apply_mcp_settings failed")
            self.notify(
                f"Failed to apply MCP settings: {exc}",
                severity="error",
                timeout=8,
            )
            self._revert_mcp_switch(previous_enabled)

    def _revert_mcp_switch(self, enabled: bool) -> None:
        """Roll the MCP switch back to *enabled* after a failed apply."""
        try:
            self.query_one("#config-tab", ConfigTab).revert_mcp_enabled(enabled)
        except Exception:
            logger.debug("revert_mcp_enabled: ConfigTab not available", exc_info=True)

    async def _start_forwarder(self, name: str) -> None:
        try:
            # Sync the API's forwarder list (config may have changed since last start)
            self.api.update_forwarders(self._project.forwarders)
            await self.api.start_forwarder(name)
            self._running_forwarders.add(name)
            self._update_title()
            fwd = next((f for f in self._project.forwarders if f.name == name), None)
            address = (
                f"{fwd.listen_host}:{fwd.listen_port}"
                if fwd else ""
            )
            self.query_one("#config-tab", ConfigTab).notify_forwarder_running(name, True, address)
            # Sync the tamper toggle in the Tamper tab
            try:
                any_tamper = any(f.tamper_enabled for f in self._project.forwarders)
                self.query_one("#tamper-tab", TamperTab).query_one(
                    "#tamper-toggle", Switch
                ).value = any_tamper
            except Exception:
                pass
        except Exception as exc:
            logger.error("Failed to start forwarder '%s': %s", name, exc)

    async def _add_and_start_forwarder(self, forwarder: ForwarderConfig) -> None:
        """Try to start a newly added forwarder; remove it on failure."""
        name = forwarder.name
        try:
            self.api.update_forwarders(self._project.forwarders)
            await self.api.start_forwarder(name)
            self._running_forwarders.add(name)
            self._update_title()
            address = f"{forwarder.listen_host}:{forwarder.listen_port}"
            self.query_one("#config-tab", ConfigTab).notify_forwarder_running(name, True, address)
            try:
                any_tamper = any(f.tamper_enabled for f in self._project.forwarders)
                self.query_one("#tamper-tab", TamperTab).query_one(
                    "#tamper-toggle", Switch
                ).value = any_tamper
            except Exception:
                pass
        except Exception as exc:
            logger.warning(
                "Forwarder '%s' could not start listening: %s — forwarder not created", name, exc
            )
            self._project.forwarders = [
                f for f in self._project.forwarders if f.name != name
            ]
            self.api.update_forwarders(self._project.forwarders)
            self.query_one("#config-tab", ConfigTab).confirm_remove_forwarder(name)
            self._project.mark_dirty()
            self._update_title()

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

        Uses ``api.update_forwarder_config()`` to hot-swap name, framing,
        and protocol definition on a running forwarder without restart.
        Log level is applied separately (global setting, not per-forwarder).
        """
        import logging as _logging

        new_name = forwarder.name

        try:
            result = self.api.update_forwarder_config(
                old_name,
                new_name=new_name if new_name != old_name else None,
                framer_name=forwarder.framer_name,
                framer_kwargs=forwarder.framer_kwargs,
                custom_framer_path=forwarder.custom_framer_path,
                protocol_definition_path=forwarder.protocol_definition_path,
            )
            if result["renamed"] and old_name in self._running_forwarders:
                self._running_forwarders.discard(old_name)
                self._running_forwarders.add(new_name)
            if result["sessions_reframed"]:
                logger.info(
                    "Framer updated on %d active session(s)",
                    result["sessions_reframed"],
                )
        except Exception as exc:
            logger.warning("Hot-swap config failed: %s", exc)

        # Log level — apply immediately (global, not per-forwarder)
        try:
            _logging.getLogger().setLevel(forwarder.log_level)
        except Exception:
            pass

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

    def action_open_project(self) -> None:
        self.push_screen(OpenProjectModal(), self._on_open_project)

    def _on_open_project(self, path: str | None) -> None:
        if not path:
            return
        try:
            state = self._project.open(path)
            # Remember which forwarders were enabled in the saved state, then
            # disable all — _start_forwarders_on_open will re-enable those that
            # successfully bind.
            enabled_names = [fwd.name for fwd in state.forwarders if fwd.enabled]
            for fwd in state.forwarders:
                fwd.enabled = False
            self._rebuild_api_from_state(state)
            # Apply project-persisted MCP settings to the host if they changed.
            # If the project wants MCP but the optional 'mcp' package is not
            # installed, force it disabled (with a warning) so opening the
            # project does not crash.
            project_mcp = self._project_mcp_settings()
            if project_mcp.enabled and not mcp_available():
                logger.warning(
                    "Project has MCP enabled but the 'mcp' package is not "
                    "installed; keeping MCP disabled."
                )
                self.notify(
                    "Project requested MCP but it's unavailable: install with "
                    "`pip install protopoke[mcp]`.",
                    severity="warning",
                    timeout=8,
                )
                project_mcp = replace(project_mcp, enabled=False)
                self._project.mcp_settings = project_mcp
            self.run_worker(
                self._mcp_host.apply(project_mcp),
                name="mcp-apply-on-open",
                exclusive=False,
                thread=False,
            )
            config_tab = self.query_one("#config-tab", ConfigTab)
            config_tab.load_forwarders(state.forwarders)
            config_tab.load_mcp_settings(self._project_mcp_settings())
            self.query_one("#forge-tab", ForgeTab).load_playbooks(state.playbooks)
            # Restore logs: load sessions+frames into registry, then populate UI
            traffic_tab = self.query_one("#traffic-tab", TrafficTab)
            traffic_tab.clear_all()
            traffic_tab.load_filters(state.frame_filters)
            if state.captured_sessions:
                restored = self.api.load_sessions_from_dicts(state.captured_sessions)
                for session in restored:
                    traffic_tab.add_session(session)
                self.query_one("#fuzzer-tab", FuzzerTab).refresh_sessions(self.api.list_sessions())
            self.query_one("#notes-tab", NotesTab).rebind_api(self.api)
            self._update_title()
            logger.info("Opened project: %s", state.name)
            if enabled_names:
                self.run_worker(
                    self._start_forwarders_on_open(enabled_names), exclusive=False, thread=False
                )
        except Exception as exc:
            logger.error("Could not open project: %s", exc)

    async def _start_forwarders_on_open(self, names: list[str]) -> None:
        """Try to start each forwarder that was enabled when the project was saved."""
        self.api.update_forwarders(self._project.forwarders)
        for name in names:
            fwd = next((f for f in self._project.forwarders if f.name == name), None)
            if fwd is None:
                continue
            try:
                await self.api.start_forwarder(name)
                fwd.enabled = True
                self._running_forwarders.add(name)
                address = f"{fwd.listen_host}:{fwd.listen_port}"
                self.query_one("#config-tab", ConfigTab).notify_forwarder_running(
                    name, True, address
                )
            except Exception as exc:
                logger.warning(
                    "Could not start forwarder '%s' on project open: %s — left disabled",
                    name, exc,
                )
        self._update_title()
        try:
            any_tamper = any(f.tamper_enabled for f in self._project.forwarders)
            self.query_one("#tamper-tab", TamperTab).query_one(
                "#tamper-toggle", Switch
            ).value = any_tamper
        except Exception:
            pass

    def action_save_project(self) -> None:
        if self._project.path is None:
            self.action_save_project_as()
            return
        try:
            self._sync_playbooks()
            self._project.save()
            self._update_title()
            logger.info("Project saved")
            self.notify("Project saved", severity="information", timeout=2)
        except Exception as exc:
            logger.error("Save failed: %s", exc)
            self.notify(f"Save failed: {exc}", severity="error")

    def action_save_project_as(self) -> None:
        default = str(self._project.path) if self._project.path else ""
        self.push_screen(SaveAsModal(default, self._project.name), self._on_save_as)

    def _on_save_as(self, result: tuple[str, str] | None) -> None:
        if not result:
            return
        name, path = result
        from pathlib import Path as _Path
        if _Path(path).exists():
            self.push_screen(
                ConfirmModal(
                    title="File already exists",
                    body=f"'{path}' already exists.\nOverwrite it?",
                    confirm_label="Overwrite",
                    confirm_variant="warning",
                ),
                lambda confirmed, _n=name, _p=path: self._do_save_as(_n, _p) if confirmed else None,
            )
        else:
            self._do_save_as(name, path)

    def _do_save_as(self, name: str, path: str) -> None:
        try:
            self._sync_playbooks()
            self._project.name = name
            self._project.save_as(path)
            self._update_title()
            logger.info("Saved to %s", path)
        except Exception as exc:
            logger.error("Save failed: %s", exc)

    def _sync_playbooks(self) -> None:
        """Copy the current UI state (forge playbooks, traffic, filters) into the project."""
        forge_tab = self.query_one("#forge-tab", ForgeTab)
        forge_tab._save_frame_editor()
        self._project.playbooks = list(forge_tab._playbooks)
        self._project.captured_sessions = [
            self.api.session_to_dict(session)
            for session in self.api.list_sessions()
        ]
        traffic_tab = self.query_one("#traffic-tab", TrafficTab)
        self._project.frame_filters = list(traffic_tab._frame_filters)

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
                return fwd.tls_upstream
        return False

    def _switch_to_forge(self, forge_tab: ForgeTab) -> None:
        """Activate the Forge tab and move focus into it.

        Why: when triggered from a button click, the clicked button (inside the
        Traffic pane) keeps focus, and TabbedContent reactivates whichever pane
        contains the focused widget — snapping the user back to Traffic.
        """
        def _do_switch() -> None:
            self.action_switch_tab("forge")
            try:
                forge_tab.query_one("#playbook-table").focus()
            except Exception:
                pass
        self.call_after_refresh(_do_switch)

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
            source_session_id=session_id if session.is_active() else None,
            direction=direction,
            transport=session.info.transport,
        )
        self._project.mark_dirty()
        self._switch_to_forge(forge_tab)
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
            source_session_id=session_id if session.is_active() else None,
            playbook_label=f"Playbook {len(forge_tab._playbooks)+1}",
            transport=session.info.transport,
        )
        self._project.mark_dirty()
        self._switch_to_forge(forge_tab)
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
        """Replace the ProtoPokeAPI with a fresh instance from current project state."""
        self.api = ProtoPokeAPI(
            forwarders=self._project.forwarders,
            rules_engine=self._project.rules_engine,
            intercept_filter=self._project.intercept_filter,
            knowledge=self._project.knowledge,
        )
        self._register_event_handlers()
        self._running_forwarders.clear()
        # Re-point the live MCP server (if any) at the new API instance.
        self._mcp_host.rebind(self.api)

    def _rebuild_api_from_state(self, state: ProjectState) -> None:
        """Replace the ProtoPokeAPI from a loaded ProjectState."""
        self.api = ProtoPokeAPI(
            forwarders=state.forwarders,
            rules_engine=state.rules_engine,
            intercept_filter=state.intercept_filter,
            knowledge=state.knowledge,
        )
        self._register_event_handlers()
        self._running_forwarders.clear()
        self._mcp_host.rebind(self.api)

    def _project_mcp_settings(self) -> MCPSettings:
        """Read MCP settings from the current project (or defaults)."""
        settings = getattr(self._project, "mcp_settings", None)
        return settings if isinstance(settings, MCPSettings) else MCPSettings()

    async def apply_mcp_settings(self, new_settings: MCPSettings) -> None:
        """Persist and apply new MCP settings (called from the Config tab).

        If ``MCPHost.apply`` raises, it rolls its own settings back; we
        mirror that by restoring the previous project settings so the UI,
        host, and project stay consistent.
        """
        previous = self._project.mcp_settings \
            if isinstance(self._project.mcp_settings, MCPSettings) \
            else MCPSettings()
        self._project.mcp_settings = new_settings
        self._project.mark_dirty()
        try:
            await self._mcp_host.apply(new_settings)
        except Exception:
            self._project.mcp_settings = previous
            raise
        self._update_title()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Launch the ProtoPoke TUI with optional embedded MCP server.

    The MCP server runs as a background asyncio task inside the UI process
    bound to the same :class:`~protopoke.api.ProtoPokeAPI` that the UI uses,
    so an AI client connected over HTTP sees the same sessions, rules, and
    traffic that the operator sees on screen.

    Flags:
        --mcp                  Enable the embedded MCP server on startup
                               (overrides the project's persisted setting).
        --mcp-host HOST        Bind host for the MCP server (default 127.0.0.1).
        --mcp-port PORT        Bind port for the MCP server (default 7878).

    The server can also be toggled at runtime from the Config tab.
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="protopoke",
        description="ProtoPoke — binary protocol proxy and analysis TUI.",
    )
    parser.add_argument(
        "--mcp", action="store_true",
        help="Enable the embedded MCP server on startup.",
    )
    parser.add_argument(
        "--mcp-host", default=None, metavar="HOST",
        help="MCP server bind host (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--mcp-port", type=int, default=None, metavar="PORT",
        help="MCP server bind port (default: 7878).",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    mcp_override: Optional[MCPSettings] = None
    if args.mcp or args.mcp_host is not None or args.mcp_port is not None:
        mcp_override = MCPSettings(
            enabled=bool(args.mcp),
            host=args.mcp_host if args.mcp_host is not None else "127.0.0.1",
            port=args.mcp_port if args.mcp_port is not None else 7878,
        )

    app = ProtoPoke(mcp_settings=mcp_override)
    app.run()


if __name__ == "__main__":
    main()
