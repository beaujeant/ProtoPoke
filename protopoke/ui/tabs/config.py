"""ConfigTab — proxy configuration form."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Button, Input, Label, Select, Switch, Static, Rule
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.message import Message

from ...config import ProxyConfig


_FRAMER_OPTIONS = [
    ("raw — pass raw read() chunks", "raw"),
    ("delimiter — split on byte sequence", "delimiter"),
    ("length_prefix — fixed-size length header", "length_prefix"),
    ("line — split on \\r\\n or \\n", "line"),
]

_LOG_LEVEL_OPTIONS = [
    ("DEBUG", "DEBUG"),
    ("INFO", "INFO"),
    ("WARNING", "WARNING"),
    ("ERROR", "ERROR"),
]


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
                yield Select(
                    [(lbl, val) for lbl, val in _FRAMER_OPTIONS],
                    value=cfg.framer_name,
                    id="framer-name",
                )
            with Horizontal(classes="field-row"):
                yield Label("Custom framer path:", classes="field-label")
                yield Input(value=cfg.custom_framer_path or "", id="custom-framer-path",
                            placeholder="/path/to/my_framer.py", classes="field-input")
            with Horizontal(classes="field-row"):
                yield Label("Custom framer class:", classes="field-label")
                yield Input(value=cfg.custom_framer_class or "", id="custom-framer-class",
                            placeholder="MyFramer", classes="field-input")
            with Horizontal(classes="field-row"):
                yield Label("Framer kwargs (JSON):", classes="field-label")
                yield Input(
                    value=self._framer_kwargs_to_str(cfg.framer_kwargs),
                    id="framer-kwargs",
                    placeholder='e.g. {"delimiter": "0d0a"} or {"header_size": 4}',
                    classes="field-input",
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
                #compact=True,
            )
            yield Button("▶ Start Proxy", variant="success", id="btn-start")
            yield Button("■ Stop Proxy", variant="error", id="btn-stop")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _framer_kwargs_to_str(kwargs: dict) -> str:
        """Serialise framer_kwargs to a JSON string for display in the Input."""
        import json
        if not kwargs:
            return ""
        # bytes values are stored as hex strings in to_dict(); show them as-is
        display: dict = {}
        for k, v in kwargs.items():
            display[k] = v.hex() if isinstance(v, (bytes, bytearray)) else v
        return json.dumps(display)

    @staticmethod
    def _parse_framer_kwargs(text: str) -> dict:
        """Parse the framer_kwargs JSON input back to a dict (bytes values as hex → bytes)."""
        import json
        text = text.strip()
        if not text:
            return {}
        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            return {}
        result: dict = {}
        for k, v in raw.items():
            if isinstance(v, str):
                try:
                    result[k] = bytes.fromhex(v)
                except ValueError:
                    result[k] = v
            else:
                result[k] = v
        return result

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
        cfg.framer_name         = _sel("framer-name") or "raw"
        cfg.framer_kwargs       = self._parse_framer_kwargs(_str("framer-kwargs"))
        cfg.custom_framer_path  = _str("custom-framer-path") or None
        cfg.custom_framer_class = _str("custom-framer-class") or None
        cfg.protocol_definition_path = _str("proto-def") or None
        cfg.sequencer_script         = _str("sequencer-script") or None
        cfg.log_level          = _sel("log-level") or "INFO"
        cfg.max_sessions       = _int("max-sessions", 0)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-apply":
            self._read_form()
            self.post_message(self.Applied())
        elif event.button.id == "btn-start":
            self._read_form()
            self.post_message(self.Applied())
            self.post_message(self.StartProxy())
        elif event.button.id == "btn-stop":
            self.post_message(self.StopProxy())

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
        _sel("framer-name", cfg.framer_name)
        _set("framer-kwargs", self._framer_kwargs_to_str(cfg.framer_kwargs))
        _set("custom-framer-path", cfg.custom_framer_path or "")
        _set("custom-framer-class", cfg.custom_framer_class or "")
        _set("proto-def",         cfg.protocol_definition_path or "")
        _set("sequencer-script",  cfg.sequencer_script or "")
        _sel("log-level",         cfg.log_level)
        _set("max-sessions", str(cfg.max_sessions))
