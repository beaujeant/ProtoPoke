"""ConfigTab — forwarder configuration panel (supports multiple forwarders)."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Button, Input, Label, Select, Switch, Static, Rule
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.message import Message

from ...config import ForwarderConfig, ProxyConfig
from ..modals.framer_edit import FramerEditModal, FramerSettings
from ..modals.file_picker import FilePickerModal


_LOG_LEVEL_OPTIONS = [
    ("DEBUG", "DEBUG"),
    ("INFO", "INFO"),
    ("WARNING", "WARNING"),
    ("ERROR", "ERROR"),
]


def _framer_summary(
    framer_name: str,
    framer_kwargs: dict,
    custom_path: str | None = None,
) -> str:
    """Return a one-line human-readable description of the current framer settings."""
    if framer_name == "raw":
        return "raw — pass raw read() chunks"
    if framer_name == "delimiter":
        delim = framer_kwargs.get("delimiter", b"\n")
        hex_str = delim.hex() if isinstance(delim, (bytes, bytearray)) else str(delim)
        return f"delimiter on 0x{hex_str}"
    if framer_name == "length_prefix":
        pl = framer_kwargs.get("prefix_length", 4)
        bo = framer_kwargs.get("byte_order", "big")
        offset = framer_kwargs.get("prefix_offset", 0)
        add = framer_kwargs.get("length_add", 0)
        parts = [f"{pl}-byte {bo}-endian length prefix"]
        if offset:
            parts.append(f"offset +{offset}")
        if add:
            parts.append(f"length {add:+d}")
        return "  ".join(parts)
    if framer_name == "line":
        return "line — split on \\r\\n or \\n"
    if framer_name == "custom":
        return f"custom: {custom_path}" if custom_path else "custom — path not set"
    return framer_name


# ---------------------------------------------------------------------------
# ForwarderRow — one row in the left-panel list
# ---------------------------------------------------------------------------

class ForwarderRow(Widget):
    """
    One row in the forwarder list panel.

    Shows: enabled toggle | name | status | Start | Stop | Remove
    """

    # -- Messages -----------------------------------------------------------

    class Selected(Message):
        """User clicked the row body — open this forwarder in the editor."""
        def __init__(self, forwarder_name: str) -> None:
            super().__init__()
            self.forwarder_name = forwarder_name

    class ToggleEnabled(Message):
        """User flipped the enabled switch."""
        def __init__(self, forwarder_name: str, enabled: bool) -> None:
            super().__init__()
            self.forwarder_name = forwarder_name
            self.enabled = enabled

    class StartRequested(Message):
        """User clicked the ▶ Start button on this row."""
        def __init__(self, forwarder_name: str) -> None:
            super().__init__()
            self.forwarder_name = forwarder_name

    class StopRequested(Message):
        """User clicked the ■ Stop button on this row."""
        def __init__(self, forwarder_name: str) -> None:
            super().__init__()
            self.forwarder_name = forwarder_name

    class RemoveRequested(Message):
        """User clicked the ✕ Remove button on this row."""
        def __init__(self, forwarder_name: str) -> None:
            super().__init__()
            self.forwarder_name = forwarder_name

    # -- CSS ----------------------------------------------------------------

    DEFAULT_CSS = """
    ForwarderRow {
        height: 5;
        border: solid $panel;
        margin: 0 0 1 0;
        padding: 0 1;
        background: $surface;
    }
    ForwarderRow:hover {
        border: solid $primary;
    }
    ForwarderRow.selected {
        border: solid $accent;
        background: $surface-lighten-1;
    }
    ForwarderRow .fwd-top-row {
        height: 3;
        align: left middle;
    }
    ForwarderRow .fwd-status-row {
        height: 2;
        align: left middle;
        padding-left: 6;
    }
    ForwarderRow .fwd-name {
        width: 1fr;
        content-align: left middle;
        padding: 0 1;
    }
    ForwarderRow .fwd-status {
        color: $text-muted;
    }
    ForwarderRow .fwd-status.running {
        color: $success;
    }
    ForwarderRow .btn-fwd-start {
        min-width: 9;
        width: 9;
        margin: 0 0 0 1;
    }
    ForwarderRow .btn-fwd-stop {
        min-width: 9;
        width: 9;
        margin: 0 0 0 1;
    }
    ForwarderRow .btn-fwd-remove {
        min-width: 5;
        width: 5;
        margin: 0 0 0 1;
    }
    ForwarderRow Switch {
        margin: 0;
        width: 5;
    }
    """

    def __init__(self, forwarder: ForwarderConfig, **kwargs) -> None:
        super().__init__(**kwargs)
        self.forwarder = forwarder
        self._is_running = False
        self._loading = True

    def compose(self) -> ComposeResult:
        fwd = self.forwarder
        with Horizontal(classes="fwd-top-row"):
            yield Switch(value=fwd.enabled, id=f"sw-enabled-{self._slug()}", classes="fwd-enabled-sw")
            yield Static(fwd.name, classes="fwd-name", id=f"fwd-name-{self._slug()}")
            yield Button("▶ Start", variant="success", id=f"btn-start-{self._slug()}",
                         classes="btn-fwd-start", disabled=not fwd.enabled)
            yield Button("■ Stop", variant="error", id=f"btn-stop-{self._slug()}",
                         classes="btn-fwd-stop", disabled=True)
            yield Button("✕", variant="error", id=f"btn-remove-{self._slug()}",
                         classes="btn-fwd-remove")
        with Horizontal(classes="fwd-status-row"):
            yield Static("● stopped", classes="fwd-status", id=f"fwd-status-{self._slug()}")

    def on_mount(self) -> None:
        self.call_after_refresh(self._release_loading)

    def _release_loading(self) -> None:
        self._loading = False

    def _slug(self) -> str:
        """Safe ID fragment derived from the forwarder name."""
        return "".join(c if c.isalnum() else "-" for c in self.forwarder.name)

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if self._loading:
            return
        self.forwarder.enabled = event.value
        # Update Start button availability — can't start a disabled forwarder
        if not self._is_running:
            try:
                self.query_one(f"#btn-start-{self._slug()}", Button).disabled = not event.value
            except Exception:
                pass
        self.post_message(self.ToggleEnabled(self.forwarder.name, event.value))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        slug = self._slug()
        if event.button.id == f"btn-start-{slug}":
            self.post_message(self.StartRequested(self.forwarder.name))
        elif event.button.id == f"btn-stop-{slug}":
            self.post_message(self.StopRequested(self.forwarder.name))
        elif event.button.id == f"btn-remove-{slug}":
            self.post_message(self.RemoveRequested(self.forwarder.name))

    def on_click(self, event) -> None:
        # Clicking anywhere on the row selects it for editing,
        # unless the click was on a button or switch (they handle themselves).
        self.post_message(self.Selected(self.forwarder.name))

    def set_running(self, running: bool, address: str = "") -> None:
        """Update the row's Start/Stop state and status label."""
        self._is_running = running
        slug = self._slug()
        try:
            self.query_one(f"#btn-start-{slug}", Button).disabled = running
            self.query_one(f"#btn-stop-{slug}", Button).disabled = not running
            status = self.query_one(f"#fwd-status-{slug}", Static)
            if running:
                status.update(f"● listening on {address}")
                status.add_class("running")
                status.remove_class("fwd-status")
                status.add_class("fwd-status")
            else:
                status.update("● stopped")
                status.remove_class("running")
        except Exception:
            pass

    def set_selected(self, selected: bool) -> None:
        if selected:
            self.add_class("selected")
        else:
            self.remove_class("selected")

    def refresh_name(self) -> None:
        """Re-render the name label after the forwarder name changed."""
        slug = self._slug()
        try:
            self.query_one(f"#fwd-name-{slug}", Static).update(self.forwarder.name)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# ForwarderEditor — per-forwarder settings form (right panel)
# ---------------------------------------------------------------------------

class ForwarderEditor(Widget):
    """
    Editable form for a single ForwarderConfig.

    Shown in the right panel when a ForwarderRow is selected.
    """

    class Applied(Message):
        """User clicked Apply — config has been written to the ForwarderConfig."""
        def __init__(self, forwarder_name: str, forwarder: ForwarderConfig) -> None:
            super().__init__()
            self.forwarder_name = forwarder_name
            self.forwarder = forwarder

    # Widget IDs that must be disabled while this forwarder is running.
    _LOCKED_WHEN_RUNNING = (
        "fe-listen-host", "fe-listen-port",
        "fe-upstream-host", "fe-upstream-port", "fe-connect-timeout",
        "fe-tls-listen", "fe-tls-upstream",
        "fe-ca-cert", "fe-browse-ca-cert",
        "fe-ca-key", "fe-browse-ca-key",
        "fe-tls-cert", "fe-browse-tls-cert",
        "fe-tls-key", "fe-browse-tls-key",
    )

    DEFAULT_CSS = """
    ForwarderEditor {
        height: 1fr;
    }
    ForwarderEditor ScrollableContainer {
        height: 1fr;
    }
    ForwarderEditor .section-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0;
        text-style: bold;
    }
    ForwarderEditor .field-row {
        height: 3;
        margin-bottom: 0;
        align: left middle;
    }
    ForwarderEditor .field-label {
        width: 26;
        padding: 0 1;
    }
    ForwarderEditor .field-input {
        width: 1fr;
    }
    ForwarderEditor .action-row {
        height: 3;
        margin-top: 1;
        margin-bottom: 1;
        padding-right: 2;
        align: right middle;
    }
    ForwarderEditor Button {
        margin-right: 1;
    }
    ForwarderEditor Switch {
        margin: 0;
    }
    ForwarderEditor .btn-framer-edit {
        width: 8;
        min-width: 8;
        margin: 0 1;
    }
    ForwarderEditor .btn-browse {
        width: 10;
        min-width: 10;
        margin-left: 1;
    }
    ForwarderEditor .framer-summary {
        width: 1fr;
        padding: 0 1;
        color: $text-muted;
        content-align: left middle;
        height: 3;
    }
    ForwarderEditor .fe-name-row {
        height: 3;
        align: left middle;
        margin-bottom: 1;
        background: $panel;
        padding: 0 1;
    }
    ForwarderEditor .fe-name-label {
        width: 10;
        padding: 0 1;
    }
    ForwarderEditor #fe-name {
        width: 1fr;
    }
    ForwarderEditor .empty-hint {
        content-align: center middle;
        height: 1fr;
        color: $text-muted;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.forwarder: ForwarderConfig | None = None
        self._framer_name: str = "raw"
        self._framer_kwargs: dict = {}
        self._custom_framer_path: str | None = None
        self._dirty: bool = False
        self._loading: bool = True
        self._is_running: bool = False

    def compose(self) -> ComposeResult:
        # Shown when no forwarder is selected
        yield Static(
            "Select a forwarder on the left to edit its settings.",
            classes="empty-hint",
            id="fe-empty-hint",
        )
        # The actual form (hidden until a forwarder is selected)
        with Vertical(id="fe-form", classes="fe-form"):
            with Horizontal(classes="fe-name-row"):
                yield Label("Name:", classes="fe-name-label")
                yield Input(value="", id="fe-name")

            with ScrollableContainer():
                # ---- Listener ----
                yield Static("  Listener", classes="section-header")
                with Horizontal(classes="field-row"):
                    yield Label("Listen host:", classes="field-label")
                    yield Input(value="127.0.0.1", id="fe-listen-host", classes="field-input")
                with Horizontal(classes="field-row"):
                    yield Label("Listen port:", classes="field-label")
                    yield Input(value="8080", id="fe-listen-port",
                                restrict=r"\d*", classes="field-input")

                # ---- Forwarder ----
                yield Static("  Forwarder", classes="section-header")
                with Horizontal(classes="field-row"):
                    yield Label("Upstream host:", classes="field-label")
                    yield Input(value="127.0.0.1", id="fe-upstream-host", classes="field-input")
                with Horizontal(classes="field-row"):
                    yield Label("Upstream port:", classes="field-label")
                    yield Input(value="9090", id="fe-upstream-port",
                                restrict=r"\d*", classes="field-input")
                with Horizontal(classes="field-row"):
                    yield Label("Connect timeout (s):", classes="field-label")
                    yield Input(value="10.0", id="fe-connect-timeout", classes="field-input")
                with Horizontal(classes="field-row"):
                    yield Label("Tamper (intercept):", classes="field-label")
                    yield Switch(value=False, id="fe-tamper-enabled")

                # ---- TLS ----
                yield Static("  TLS / SSL", classes="section-header")
                with Horizontal(classes="field-row"):
                    yield Label("TLS on listener side:", classes="field-label")
                    yield Switch(value=False, id="fe-tls-listen")
                with Horizontal(classes="field-row"):
                    yield Label("TLS upstream:", classes="field-label")
                    yield Switch(value=False, id="fe-tls-upstream")
                with Vertical(id="fe-tls-paths"):
                    with Horizontal(classes="field-row"):
                        yield Label("CA cert path:", classes="field-label")
                        yield Input(value="", id="fe-ca-cert",
                                    placeholder="~/.protopoke/ca.crt", classes="field-input")
                        yield Button("Browse", id="fe-browse-ca-cert", classes="btn-browse")
                    with Horizontal(classes="field-row"):
                        yield Label("CA key path:", classes="field-label")
                        yield Input(value="", id="fe-ca-key",
                                    placeholder="~/.protopoke/ca.key", classes="field-input")
                        yield Button("Browse", id="fe-browse-ca-key", classes="btn-browse")
                    with Horizontal(classes="field-row"):
                        yield Label("Manual cert path:", classes="field-label")
                        yield Input(value="", id="fe-tls-cert",
                                    placeholder="(optional override)", classes="field-input")
                        yield Button("Browse", id="fe-browse-tls-cert", classes="btn-browse")
                    with Horizontal(classes="field-row"):
                        yield Label("Manual key path:", classes="field-label")
                        yield Input(value="", id="fe-tls-key",
                                    placeholder="(optional override)", classes="field-input")
                        yield Button("Browse", id="fe-browse-tls-key", classes="btn-browse")

                # ---- Framing ----
                yield Static("  Framing", classes="section-header")
                with Horizontal(classes="field-row"):
                    yield Label("Framer:", classes="field-label")
                    yield Button("Edit", id="fe-btn-framer-edit", classes="btn-framer-edit")
                    yield Static(
                        _framer_summary(self._framer_name, self._framer_kwargs, self._custom_framer_path),
                        id="fe-framer-summary",
                        classes="framer-summary",
                    )

                # ---- Protocol ----
                yield Static("  Protocol Definition", classes="section-header")
                with Horizontal(classes="field-row"):
                    yield Label("Definition file:", classes="field-label")
                    yield Input(value="", id="fe-proto-def",
                                placeholder="/path/to/protocol.yaml", classes="field-input")
                    yield Button("Browse", id="fe-browse-proto-def", classes="btn-browse")

                # ---- Misc ----
                yield Static("  Miscellaneous", classes="section-header")
                with Horizontal(classes="field-row"):
                    yield Label("Log level:", classes="field-label")
                    yield Select(
                        [(lbl, val) for lbl, val in _LOG_LEVEL_OPTIONS],
                        value="INFO",
                        id="fe-log-level",
                    )
                with Horizontal(classes="field-row"):
                    yield Label("Max sessions (0=∞):", classes="field-label")
                    yield Input(value="0", id="fe-max-sessions",
                                restrict=r"\d*", classes="field-input")
                with Horizontal(classes="field-row"):
                    yield Label("Buffer size (bytes):", classes="field-label")
                    yield Input(value="4096", id="fe-read-buffer",
                                restrict=r"\d*", classes="field-input")

            # Action bar
            with Horizontal(classes="action-row"):
                yield Button(
                    "Apply",
                    variant="primary",
                    id="fe-btn-apply",
                    disabled=True,
                )

    def on_mount(self) -> None:
        self.query_one("#fe-form").display = False
        self.query_one("#fe-tls-paths").display = False
        self.call_after_refresh(self._release_loading)

    def _release_loading(self) -> None:
        self._loading = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_forwarder(self, forwarder: ForwarderConfig) -> None:
        """Load a ForwarderConfig into the form."""
        self.forwarder = forwarder
        self._is_running = False
        self._loading = True

        # Show the form, hide the hint
        self.query_one("#fe-empty-hint").display = False
        self.query_one("#fe-form").display = True

        cfg = forwarder.config
        self._framer_name = cfg.framer_name
        self._framer_kwargs = dict(cfg.framer_kwargs)
        self._custom_framer_path = cfg.custom_framer_path

        def _set(wid: str, val: str) -> None:
            self.query_one(f"#{wid}", Input).value = val

        def _sw(wid: str, val: bool) -> None:
            self.query_one(f"#{wid}", Switch).value = val

        def _sel(wid: str, val: str) -> None:
            self.query_one(f"#{wid}", Select).value = val

        _set("fe-name",           forwarder.name)
        _set("fe-listen-host",    cfg.listen_host)
        _set("fe-listen-port",    str(cfg.listen_port))
        _set("fe-upstream-host",  cfg.upstream_host)
        _set("fe-upstream-port",  str(cfg.upstream_port))
        _set("fe-connect-timeout", str(cfg.connect_timeout))
        _sw("fe-tamper-enabled",  cfg.tamper_enabled)
        _sw("fe-tls-listen",      cfg.tls_listen)
        _sw("fe-tls-upstream",    cfg.tls_upstream)
        self.query_one("#fe-tls-paths").display = cfg.tls_listen
        _set("fe-ca-cert",   cfg.ca_cert_path or "")
        _set("fe-ca-key",    cfg.ca_key_path or "")
        _set("fe-tls-cert",  cfg.tls_cert_path or "")
        _set("fe-tls-key",   cfg.tls_key_path or "")
        self._update_framer_summary()
        _set("fe-proto-def",  cfg.protocol_definition_path or "")
        _sel("fe-log-level",  cfg.log_level)
        _set("fe-max-sessions", str(cfg.max_sessions))
        _set("fe-read-buffer",  str(cfg.read_buffer_size))

        self.call_after_refresh(self._on_load_complete)

    def set_running(self, running: bool) -> None:
        """Lock/unlock fields based on whether this forwarder is running."""
        self._is_running = running
        for wid_id in self._LOCKED_WHEN_RUNNING:
            try:
                self.query_one(f"#{wid_id}").disabled = running
            except Exception:
                pass

    def _on_load_complete(self) -> None:
        self._loading = False
        self._clear_dirty()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _update_framer_summary(self) -> None:
        try:
            self.query_one("#fe-framer-summary", Static).update(
                _framer_summary(self._framer_name, self._framer_kwargs, self._custom_framer_path)
            )
        except Exception:
            pass

    def _read_form(self) -> str | None:
        """
        Write form values back into self.forwarder.config (and name).

        Returns the new forwarder name (may have changed from old name).
        Returns None if no forwarder is loaded.
        """
        if self.forwarder is None:
            return None

        def _str(wid: str) -> str:
            return self.query_one(f"#{wid}", Input).value.strip()

        def _int(wid: str, default: int = 0) -> int:
            try:
                return int(_str(wid))
            except ValueError:
                return default

        def _float(wid: str, default: float = 0.0) -> float:
            try:
                return float(_str(wid))
            except ValueError:
                return default

        def _sw(wid: str) -> bool:
            return self.query_one(f"#{wid}", Switch).value

        def _sel(wid: str) -> str:
            val = self.query_one(f"#{wid}", Select).value
            return str(val) if val else ""

        new_name = _str("fe-name") or self.forwarder.name
        self.forwarder.name = new_name

        cfg = self.forwarder.config
        cfg.listen_host        = _str("fe-listen-host") or "127.0.0.1"
        cfg.listen_port        = _int("fe-listen-port", 8080)
        cfg.upstream_host      = _str("fe-upstream-host") or "127.0.0.1"
        cfg.upstream_port      = _int("fe-upstream-port", 9090)
        cfg.connect_timeout    = _float("fe-connect-timeout", 10.0)
        cfg.tamper_enabled     = _sw("fe-tamper-enabled")
        cfg.tls_listen         = _sw("fe-tls-listen")
        cfg.tls_upstream       = _sw("fe-tls-upstream")
        cfg.ca_cert_path       = _str("fe-ca-cert") or None
        cfg.ca_key_path        = _str("fe-ca-key") or None
        cfg.tls_cert_path      = _str("fe-tls-cert") or None
        cfg.tls_key_path       = _str("fe-tls-key") or None
        cfg.framer_name        = self._framer_name
        cfg.framer_kwargs      = dict(self._framer_kwargs)
        cfg.custom_framer_path = self._custom_framer_path
        cfg.protocol_definition_path = _str("fe-proto-def") or None
        cfg.log_level          = _sel("fe-log-level") or "INFO"
        cfg.max_sessions       = _int("fe-max-sessions", 0)
        cfg.read_buffer_size   = _int("fe-read-buffer", 4096)

        return new_name

    def _mark_dirty(self) -> None:
        self._dirty = True
        try:
            self.query_one("#fe-btn-apply", Button).disabled = False
        except Exception:
            pass

    def _clear_dirty(self) -> None:
        self._dirty = False
        try:
            self.query_one("#fe-btn-apply", Button).disabled = True
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        if not self._loading:
            self._mark_dirty()

    def on_select_changed(self, event: Select.Changed) -> None:
        if not self._loading:
            self._mark_dirty()

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id == "fe-tls-listen":
            try:
                self.query_one("#fe-tls-paths").display = event.value
            except Exception:
                pass
        if not self._loading:
            self._mark_dirty()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id

        _browse_map = {
            "fe-browse-ca-cert":   "fe-ca-cert",
            "fe-browse-ca-key":    "fe-ca-key",
            "fe-browse-tls-cert":  "fe-tls-cert",
            "fe-browse-tls-key":   "fe-tls-key",
            "fe-browse-proto-def": "fe-proto-def",
        }
        if btn_id in _browse_map:
            target_id = _browse_map[btn_id]
            current = self.query_one(f"#{target_id}", Input).value.strip() or None
            def _on_pick(path: str | None, _tid: str = target_id) -> None:
                if path is not None:
                    self.query_one(f"#{_tid}", Input).value = path
            self.app.push_screen(FilePickerModal(current), _on_pick)
            return

        if btn_id == "fe-btn-framer-edit":
            settings: FramerSettings = {
                "framer_name": self._framer_name,
                "framer_kwargs": dict(self._framer_kwargs),
                "custom_framer_path": self._custom_framer_path,
            }
            self.app.push_screen(FramerEditModal(settings), self._on_framer_edit_result)
        elif btn_id == "fe-btn-apply":
            if self.forwarder is None:
                return
            old_name = self.forwarder.name
            new_name = self._read_form()
            self._clear_dirty()
            if new_name:
                self.post_message(self.Applied(old_name, self.forwarder))

    def _on_framer_edit_result(self, result: FramerSettings | None) -> None:
        if result is None:
            return
        self._framer_name = result["framer_name"]
        self._framer_kwargs = dict(result["framer_kwargs"])
        self._custom_framer_path = result.get("custom_framer_path")
        self._update_framer_summary()
        self._mark_dirty()


# ---------------------------------------------------------------------------
# ConfigTab — two-panel forwarder manager
# ---------------------------------------------------------------------------

class ConfigTab(Widget):
    """
    Tab 1 — Forwarder configuration.

    Left panel:  scrollable list of ForwarderRow widgets (one per forwarder).
    Right panel: ForwarderEditor showing the selected forwarder's settings.

    Posts messages for all user actions so the app can react (start/stop
    forwarders, rebuild the API, persist project state, etc.).
    """

    # -- Messages -----------------------------------------------------------

    class ForwarderAdded(Message):
        """User clicked '+ Add Forwarder' — a new default forwarder was created."""
        def __init__(self, forwarder: ForwarderConfig) -> None:
            super().__init__()
            self.forwarder = forwarder

    class ForwarderRemoved(Message):
        """User removed a forwarder."""
        def __init__(self, forwarder_name: str) -> None:
            super().__init__()
            self.forwarder_name = forwarder_name

    class ForwarderApplied(Message):
        """User clicked Apply on the editor — config has been written."""
        def __init__(self, old_name: str, forwarder: ForwarderConfig) -> None:
            super().__init__()
            self.old_name = old_name
            self.forwarder = forwarder

    class ForwarderEnabled(Message):
        """User toggled a forwarder's enabled switch."""
        def __init__(self, forwarder_name: str, enabled: bool) -> None:
            super().__init__()
            self.forwarder_name = forwarder_name
            self.enabled = enabled

    class StartForwarder(Message):
        """User wants to start a specific forwarder."""
        def __init__(self, forwarder_name: str) -> None:
            super().__init__()
            self.forwarder_name = forwarder_name

    class StopForwarder(Message):
        """User wants to stop a specific forwarder."""
        def __init__(self, forwarder_name: str) -> None:
            super().__init__()
            self.forwarder_name = forwarder_name

    class StartAll(Message):
        """User clicked 'Start All'."""

    class StopAll(Message):
        """User clicked 'Stop All'."""

    # -- CSS ----------------------------------------------------------------

    DEFAULT_CSS = """
    ConfigTab {
        padding: 0;
    }
    ConfigTab > Horizontal {
        height: 1fr;
    }
    ConfigTab #fwd-list-panel {
        width: 38;
        border-right: solid $primary-darken-2;
        padding: 0 1;
    }
    ConfigTab #fwd-list-scroll {
        height: 1fr;
    }
    ConfigTab #fwd-list-actions {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    ConfigTab #fwd-list-actions Button {
        margin-right: 1;
    }
    ConfigTab #fwd-editor-panel {
        width: 1fr;
        padding: 0 1;
    }
    """

    def __init__(
        self,
        forwarders: list[ForwarderConfig],
        *,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self._forwarders: list[ForwarderConfig] = list(forwarders)
        self._selected_name: str | None = None

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="fwd-list-panel"):
                with ScrollableContainer(id="fwd-list-scroll"):
                    for fwd in self._forwarders:
                        yield ForwarderRow(fwd, id=self._row_id(fwd.name))
                with Horizontal(id="fwd-list-actions"):
                    yield Button("+ Add", id="btn-add-forwarder")
                    yield Button("▶ All", variant="success", id="btn-start-all")
                    yield Button("■ All", variant="error", id="btn-stop-all")
            with Vertical(id="fwd-editor-panel"):
                yield ForwarderEditor(id="fwd-editor")

    def on_mount(self) -> None:
        # Auto-select the first forwarder if any
        if self._forwarders:
            self._select_forwarder(self._forwarders[0].name)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_id(name: str) -> str:
        slug = "".join(c if c.isalnum() else "-" for c in name)
        return f"fwd-row-{slug}"

    def _select_forwarder(self, name: str) -> None:
        self._selected_name = name
        editor = self.query_one("#fwd-editor", ForwarderEditor)
        # Deselect all rows
        for row in self.query(ForwarderRow):
            row.set_selected(False)
        # Select and load
        fwd = next((f for f in self._forwarders if f.name == name), None)
        if fwd is None:
            return
        try:
            self.query_one(f"#{self._row_id(name)}", ForwarderRow).set_selected(True)
        except Exception:
            pass
        editor.load_forwarder(fwd)

    def _unique_forwarder_name(self, base: str = "Forwarder") -> str:
        existing = {f.name for f in self._forwarders}
        if base not in existing:
            return base
        i = 2
        while f"{base} {i}" in existing:
            i += 1
        return f"{base} {i}"

    # ------------------------------------------------------------------
    # Button handling
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-add-forwarder":
            name = self._unique_forwarder_name()
            new_fwd = ForwarderConfig(name=name, enabled=True, config=ProxyConfig())
            self._forwarders.append(new_fwd)
            row = ForwarderRow(new_fwd, id=self._row_id(name))
            self.query_one("#fwd-list-scroll").mount(row)
            self._select_forwarder(name)
            self.post_message(self.ForwarderAdded(new_fwd))
        elif btn_id == "btn-start-all":
            self.post_message(self.StartAll())
        elif btn_id == "btn-stop-all":
            self.post_message(self.StopAll())

    # ------------------------------------------------------------------
    # ForwarderRow message handlers
    # ------------------------------------------------------------------

    def on_forwarder_row_selected(self, event: ForwarderRow.Selected) -> None:
        self._select_forwarder(event.forwarder_name)

    def on_forwarder_row_start_requested(self, event: ForwarderRow.StartRequested) -> None:
        self.post_message(self.StartForwarder(event.forwarder_name))

    def on_forwarder_row_stop_requested(self, event: ForwarderRow.StopRequested) -> None:
        self.post_message(self.StopForwarder(event.forwarder_name))

    def on_forwarder_row_toggle_enabled(self, event: ForwarderRow.ToggleEnabled) -> None:
        self.post_message(self.ForwarderEnabled(event.forwarder_name, event.enabled))

    def on_forwarder_row_remove_requested(self, event: ForwarderRow.RemoveRequested) -> None:
        name = event.forwarder_name
        self._forwarders = [f for f in self._forwarders if f.name != name]
        try:
            row = self.query_one(f"#{self._row_id(name)}", ForwarderRow)
            row.remove()
        except Exception:
            pass
        # Select another forwarder if the removed one was selected
        if self._selected_name == name:
            if self._forwarders:
                self._select_forwarder(self._forwarders[0].name)
            else:
                self._selected_name = None
                editor = self.query_one("#fwd-editor", ForwarderEditor)
                editor.forwarder = None
                try:
                    editor.query_one("#fe-empty-hint").display = True
                    editor.query_one("#fe-form").display = False
                except Exception:
                    pass
        self.post_message(self.ForwarderRemoved(name))

    # ------------------------------------------------------------------
    # ForwarderEditor message handler
    # ------------------------------------------------------------------

    def on_forwarder_editor_applied(self, event: ForwarderEditor.Applied) -> None:
        old_name = event.old_name
        fwd = event.forwarder
        new_name = fwd.name

        # If the name changed, update row ID and refresh the row label
        if old_name != new_name:
            # Update the row widget's ID
            try:
                row = self.query_one(f"#{self._row_id(old_name)}", ForwarderRow)
                row.id = self._row_id(new_name)
                row.refresh_name()
            except Exception:
                pass
            self._selected_name = new_name

        self.post_message(self.ForwarderApplied(old_name, fwd))

    # ------------------------------------------------------------------
    # Public API (called by app.py)
    # ------------------------------------------------------------------

    def load_forwarders(self, forwarders: list[ForwarderConfig]) -> None:
        """Replace the entire forwarder list (e.g. after project open/new)."""
        self._forwarders = list(forwarders)
        self._selected_name = None

        # Remove existing rows
        for row in list(self.query(ForwarderRow)):
            row.remove()

        # Mount new rows
        scroll = self.query_one("#fwd-list-scroll")
        for fwd in self._forwarders:
            scroll.mount(ForwarderRow(fwd, id=self._row_id(fwd.name)))

        # Reset the editor
        editor = self.query_one("#fwd-editor", ForwarderEditor)
        editor.forwarder = None

        # Auto-select first forwarder
        if self._forwarders:
            self.call_after_refresh(lambda: self._select_forwarder(self._forwarders[0].name))
        else:
            try:
                editor.query_one("#fe-empty-hint").display = True
                editor.query_one("#fe-form").display = False
            except Exception:
                pass

    def notify_forwarder_running(
        self, name: str, running: bool, address: str = ""
    ) -> None:
        """Update the row status indicator and lock/unlock editor fields."""
        try:
            row = self.query_one(f"#{self._row_id(name)}", ForwarderRow)
            row.set_running(running, address)
        except Exception:
            pass
        editor = self.query_one("#fwd-editor", ForwarderEditor)
        if editor.forwarder and editor.forwarder.name == name:
            editor.set_running(running)
