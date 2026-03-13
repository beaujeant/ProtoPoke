"""ConfigTab — proxy configuration form."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Button, Input, Label, Select, Switch, Static, Rule
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.message import Message

from ...config import ProxyConfig
from ..modals.framer_edit import FramerEditModal, FramerSettings


_LOG_LEVEL_OPTIONS = [
    ("DEBUG", "DEBUG"),
    ("INFO", "INFO"),
    ("WARNING", "WARNING"),
    ("ERROR", "ERROR"),
]


def _framer_summary(framer_name: str, framer_kwargs: dict) -> str:
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
    return framer_name


class ConfigTab(Widget):
    """
    Tab 1 — Proxy configuration.

    Displays all ProxyConfig fields as an editable form.  Changes are applied
    to the live config object when the user clicks [Apply] or presses the
    proxy Start/Stop toggle.

    Posts ``ConfigTab.Applied`` when the user applies changes.
    Posts ``ConfigTab.StartProxy`` / ``ConfigTab.StopProxy`` for lifecycle.
    """

    # ------------------------------------------------------------------
    # Messages
    # ------------------------------------------------------------------

    class Applied(Message):
        """User clicked Apply — config fields have been written to self.config."""

    class StartProxy(Message):
        """User wants to start the proxy."""

    class StopProxy(Message):
        """User wants to stop the proxy."""

    # ------------------------------------------------------------------

    DEFAULT_CSS = """
    ConfigTab {
        padding: 0 1;
    }
    ConfigTab ScrollableContainer {
        height: 1fr;
    }
    ConfigTab .section-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        text-style: bold;
    }
    ConfigTab .field-row {
        height: 3;
        margin-bottom: 0;
        align: left middle;
    }
    ConfigTab .field-label {
        width: 26;
        padding: 0 1;
    }
    ConfigTab .field-input {
        width: 1fr;
    }
    ConfigTab .action-row {
        height: 3;
        margin-top: 1;
        margin-bottom: 1;
        padding-right: 2;
        align: right middle;
    }
    ConfigTab Button {
        margin-right: 1;
    }
    ConfigTab .status-bar {
        height: 3;
        background: $surface-darken-1;
        padding: 0 1;
        align: left middle;
    }
    ConfigTab Switch {
        margin: 0;
    }
    ConfigTab .btn-framer-edit {
        width: 8;
        min-width: 8;
        margin-right: 1;
    }
    ConfigTab .framer-summary {
        width: 1fr;
        padding: 0 1;
        color: $text-muted;
        content-align: left middle;
        height: 3;
    }
    """

    def __init__(
        self,
        config: ProxyConfig,
        *,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self.config = config
        # Local framer state — kept in sync with config on Apply/load_config
        self._framer_name: str = config.framer_name
        self._framer_kwargs: dict = dict(config.framer_kwargs)

    def compose(self) -> ComposeResult:
        cfg = self.config

        with ScrollableContainer():
            # ---- Listener ----
            yield Static("  Listener", classes="section-header")
            with Horizontal(classes="field-row"):
                yield Label("Listen host:", classes="field-label")
                yield Input(value=cfg.listen_host, id="listen-host", classes="field-input")
            with Horizontal(classes="field-row"):
                yield Label("Listen port:", classes="field-label")
                yield Input(value=str(cfg.listen_port), id="listen-port",
                            restrict=r"\d*", classes="field-input")

            # ---- Forwarder ----
            yield Static("  Forwarder", classes="section-header")
            with Horizontal(classes="field-row"):
                yield Label("Upstream host:", classes="field-label")
                yield Input(value=cfg.upstream_host, id="upstream-host", classes="field-input")
            with Horizontal(classes="field-row"):
                yield Label("Upstream port:", classes="field-label")
                yield Input(value=str(cfg.upstream_port), id="upstream-port",
                            restrict=r"\d*", classes="field-input")
            with Horizontal(classes="field-row"):
                yield Label("Connect timeout (s):", classes="field-label")
                yield Input(value=str(cfg.connect_timeout), id="connect-timeout",
                            classes="field-input")

            # ---- TLS ----
            yield Static("  TLS / SSL", classes="section-header")
            with Horizontal(classes="field-row"):
                yield Label("TLS on listener side:", classes="field-label")
                yield Switch(value=cfg.tls_listen, id="tls-listen")
            with Horizontal(classes="field-row"):
                yield Label("TLS upstream:", classes="field-label")
                yield Switch(value=cfg.tls_upstream, id="tls-upstream")
            with Horizontal(classes="field-row"):
                yield Label("CA cert path:", classes="field-label")
                yield Input(value=cfg.ca_cert_path or "", id="ca-cert",
                            placeholder="~/.protopoke/ca.crt", classes="field-input")
            with Horizontal(classes="field-row"):
                yield Label("CA key path:", classes="field-label")
                yield Input(value=cfg.ca_key_path or "", id="ca-key",
                            placeholder="~/.protopoke/ca.key", classes="field-input")
            with Horizontal(classes="field-row"):
                yield Label("Manual cert path:", classes="field-label")
                yield Input(value=cfg.tls_cert_path or "", id="tls-cert",
                            placeholder="(optional override)", classes="field-input")
            with Horizontal(classes="field-row"):
                yield Label("Manual key path:", classes="field-label")
                yield Input(value=cfg.tls_key_path or "", id="tls-key",
                            placeholder="(optional override)", classes="field-input")

            # ---- Framing ----
            yield Static("  Framing", classes="section-header")
            with Horizontal(classes="field-row"):
                yield Label("Framer:", classes="field-label")
                yield Button("Edit", id="btn-framer-edit", classes="btn-framer-edit")
                yield Static(
                    _framer_summary(self._framer_name, self._framer_kwargs),
                    id="framer-summary",
                    classes="framer-summary",
                )

            # ---- Protocol ----
            yield Static("  Protocol Definition", classes="section-header")
            with Horizontal(classes="field-row"):
                yield Label("Definition file:", classes="field-label")
                yield Input(value=cfg.protocol_definition_path or "", id="proto-def",
                            placeholder="/path/to/protocol.yaml", classes="field-input")

            # ---- Sequencer ----
            yield Static("  Sequencer", classes="section-header")
            with Horizontal(classes="field-row"):
                yield Label("Script path:", classes="field-label")
                yield Input(value=cfg.sequencer_script or "", id="sequencer-script",
                            placeholder="/path/to/my_protocol_script.py",
                            classes="field-input")

            # ---- Misc ----
            yield Static("  Miscellaneous", classes="section-header")
            with Horizontal(classes="field-row"):
                yield Label("Log level:", classes="field-label")
                yield Select(
                    [(lbl, val) for lbl, val in _LOG_LEVEL_OPTIONS],
                    value=cfg.log_level,
                    id="log-level",
                )
            with Horizontal(classes="field-row"):
                yield Label("Max sessions (0=∞):", classes="field-label")
                yield Input(value=str(cfg.max_sessions), id="max-sessions",
                            restrict=r"\d*", classes="field-input")

        # ---- Action bar ----
        with Horizontal(classes="action-row"):
            yield Button(
                "Apply",
                variant="primary",
                id="btn-apply",
                classes="btn-small",
            )
            yield Button("▶ Start Proxy", variant="success", id="btn-start")
            yield Button("■ Stop Proxy", variant="error", id="btn-stop")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _update_framer_summary(self) -> None:
        """Refresh the framer summary Static widget from current instance vars."""
        self.query_one("#framer-summary", Static).update(
            _framer_summary(self._framer_name, self._framer_kwargs)
        )

    def _read_form(self) -> None:
        """Write all form values back into self.config."""
        cfg = self.config

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

        cfg.listen_host        = _str("listen-host") or "127.0.0.1"
        cfg.listen_port        = _int("listen-port", 8080)
        cfg.upstream_host      = _str("upstream-host") or "127.0.0.1"
        cfg.upstream_port      = _int("upstream-port", 9090)
        cfg.connect_timeout    = _float("connect-timeout", 10.0)
        cfg.tls_listen         = _sw("tls-listen")
        cfg.tls_upstream       = _sw("tls-upstream")
        cfg.ca_cert_path       = _str("ca-cert") or None
        cfg.ca_key_path        = _str("ca-key") or None
        cfg.tls_cert_path      = _str("tls-cert") or None
        cfg.tls_key_path       = _str("tls-key") or None
        # Framer settings come from instance vars (edited via FramerEditModal)
        cfg.framer_name   = self._framer_name
        cfg.framer_kwargs = dict(self._framer_kwargs)
        cfg.protocol_definition_path = _str("proto-def") or None
        cfg.sequencer_script         = _str("sequencer-script") or None
        cfg.log_level          = _sel("log-level") or "INFO"
        cfg.max_sessions       = _int("max-sessions", 0)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-framer-edit":
            settings: FramerSettings = {
                "framer_name": self._framer_name,
                "framer_kwargs": dict(self._framer_kwargs),
            }
            self.app.push_screen(FramerEditModal(settings), self._on_framer_edit_result)
        elif event.button.id == "btn-apply":
            self._read_form()
            self.post_message(self.Applied())
        elif event.button.id == "btn-start":
            self._read_form()
            self.post_message(self.Applied())
            self.post_message(self.StartProxy())
        elif event.button.id == "btn-stop":
            self.post_message(self.StopProxy())

    def _on_framer_edit_result(self, result: FramerSettings | None) -> None:
        """Callback invoked when FramerEditModal is dismissed."""
        if result is None:
            return
        self._framer_name = result["framer_name"]
        self._framer_kwargs = dict(result["framer_kwargs"])
        self._update_framer_summary()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_config(self, config: ProxyConfig) -> None:
        """Reload the form from a new ProxyConfig object (e.g. after project open)."""
        self.config = config

        def _set(wid: str, val: str) -> None:
            self.query_one(f"#{wid}", Input).value = val

        def _sw(wid: str, val: bool) -> None:
            self.query_one(f"#{wid}", Switch).value = val

        def _sel(wid: str, val: str) -> None:
            self.query_one(f"#{wid}", Select).value = val

        cfg = config
        _set("listen-host", cfg.listen_host)
        _set("listen-port", str(cfg.listen_port))
        _set("upstream-host", cfg.upstream_host)
        _set("upstream-port", str(cfg.upstream_port))
        _set("connect-timeout", str(cfg.connect_timeout))
        _sw("tls-listen", cfg.tls_listen)
        _sw("tls-upstream", cfg.tls_upstream)
        _set("ca-cert", cfg.ca_cert_path or "")
        _set("ca-key", cfg.ca_key_path or "")
        _set("tls-cert", cfg.tls_cert_path or "")
        _set("tls-key", cfg.tls_key_path or "")
        # Update framer instance vars and refresh summary
        self._framer_name = cfg.framer_name
        self._framer_kwargs = dict(cfg.framer_kwargs)
        self._update_framer_summary()
        _set("proto-def",         cfg.protocol_definition_path or "")
        _set("sequencer-script",  cfg.sequencer_script or "")
        _sel("log-level",         cfg.log_level)
        _set("max-sessions", str(cfg.max_sessions))
