"""ForwarderEditModal — modal dialog for adding/editing a forwarder."""

from __future__ import annotations

import socket
from copy import deepcopy

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Switch, Static
from textual.containers import Horizontal, Vertical, ScrollableContainer

from ...config import ForwarderConfig, ForwarderType
from .file_picker import FilePickerModal
from .framer_edit import FramerEditModal, FramerSettings


_LOG_LEVEL_OPTIONS = [
    ("DEBUG", "DEBUG"),
    ("INFO", "INFO"),
    ("WARNING", "WARNING"),
    ("ERROR", "ERROR"),
]


_FORWARDER_TYPE_OPTIONS = [
    ("TCP", ForwarderType.TCP.value),
    ("UDP", ForwarderType.UDP.value),
    ("SOCKS5", ForwarderType.SOCKS5.value),
]


def _get_listen_interfaces() -> list[tuple[str, str]]:
    """Return a list of (label, value) tuples for available listen interfaces."""
    interfaces: dict[str, str] = {}
    interfaces["0.0.0.0"] = "0.0.0.0 (all interfaces)"
    interfaces["127.0.0.1"] = "127.0.0.1 (loopback)"
    interfaces["::"] = ":: (all interfaces IPv6)"
    interfaces["::1"] = "::1 (loopback IPv6)"
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addr = info[4][0]
            if addr not in interfaces:
                interfaces[addr] = addr
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        addr = s.getsockname()[0]
        if addr not in interfaces:
            interfaces[addr] = addr
        s.close()
    except Exception:
        pass
    return [(label, val) for val, label in interfaces.items()]


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


class ForwarderEditModal(ModalScreen):
    """
    Modal dialog for adding or editing a forwarder configuration.

    Dismisses with a :class:`ForwarderConfig` on Save, or ``None`` on Cancel/Escape.
    """

    DEFAULT_CSS = """
    ForwarderEditModal {
        align: center middle;
    }
    ForwarderEditModal > Vertical {
        width: 80;
        max-height: 90%;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    ForwarderEditModal .modal-title {
        text-style: bold;
        margin-bottom: 1;
        color: $text;
    }
    ForwarderEditModal ScrollableContainer {
        height: 1fr;
        min-height: 10;
    }
    ForwarderEditModal .section-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0;
        text-style: bold;
        margin-top: 1;
    }
    ForwarderEditModal .field-row {
        height: 3;
        margin-bottom: 0;
        align: left middle;
    }
    ForwarderEditModal .field-label {
        width: 26;
        padding: 0 1;
    }
    ForwarderEditModal .field-input {
        width: 1fr;
    }
    ForwarderEditModal Switch {
        margin: 0;
    }
    ForwarderEditModal .btn-browse {
        width: 10;
        min-width: 10;
        margin-left: 1;
    }
    ForwarderEditModal .btn-framer-edit {
        width: 8;
        min-width: 8;
        margin: 0 1;
    }
    ForwarderEditModal .framer-summary {
        width: 1fr;
        padding: 0 1;
        color: $text-muted;
        content-align: left middle;
        height: 3;
    }
    ForwarderEditModal .buttons {
        height: 3;
        margin-top: 1;
        align: right middle;
    }
    ForwarderEditModal .buttons Button {
        margin-left: 1;
    }
    ForwarderEditModal #fm-tls-paths {
        height: auto;
    }
    """

    # Widget IDs that require a restart and should be disabled while running.
    _RESTART_ONLY_IDS = frozenset({
        "fm-type",
        "fm-listen-host", "fm-listen-port",
        "fm-upstream-host", "fm-upstream-port",
        "fm-max-sessions", "fm-read-buffer",
        "fm-tls-listen", "fm-tls-upstream",
        "fm-ca-cert", "fm-ca-key", "fm-tls-cert", "fm-tls-key",
        "fm-browse-ca-cert", "fm-browse-ca-key",
        "fm-browse-tls-cert", "fm-browse-tls-key",
        "fm-udp-idle", "fm-socks-user", "fm-socks-pass",
    })

    def __init__(
        self,
        forwarder: ForwarderConfig | None = None,
        *,
        existing_names: set[str] | None = None,
        is_running: bool = False,
    ) -> None:
        """
        Parameters
        ----------
        forwarder:
            The forwarder to edit, or ``None`` to create a new one.
        existing_names:
            Names already in use (for duplicate-name validation).
        is_running:
            Whether the forwarder is currently running.  When ``True``,
            fields that require a restart (network, TLS, sessions) are
            disabled; only hot-swappable fields (name, framing, protocol)
            remain editable.
        """
        super().__init__()
        if forwarder is not None:
            self._forwarder = deepcopy(forwarder)
            self._original_name = forwarder.name
            self._is_new = False
        else:
            self._forwarder = ForwarderConfig(name="Forwarder", enabled=True)
            self._original_name = ""
            self._is_new = True

        self._existing_names = existing_names or set()
        self._is_running = is_running
        self._framer_name = self._forwarder.framer_name
        self._framer_kwargs = dict(self._forwarder.framer_kwargs)
        self._custom_framer_path = self._forwarder.custom_framer_path

    def compose(self) -> ComposeResult:
        fwd = self._forwarder
        title = "Add Forwarder" if self._is_new else "Edit Forwarder"
        ifaces = _get_listen_interfaces()

        # Determine which interface option to pre-select
        listen_val = fwd.listen_host
        iface_values = {v for _, v in ifaces}
        if listen_val not in iface_values:
            # Add the current value as a custom entry
            ifaces.append((listen_val, listen_val))

        with Vertical():
            yield Label(title, classes="modal-title")

            with ScrollableContainer():
                # ---- Name + Type ----
                with Horizontal(classes="field-row"):
                    yield Label("Name:", classes="field-label")
                    yield Input(value=self._forwarder.name, id="fm-name", classes="field-input")
                with Horizontal(classes="field-row"):
                    yield Label("Type:", classes="field-label")
                    yield Select(
                        _FORWARDER_TYPE_OPTIONS,
                        value=self._forwarder.forwarder_type.value,
                        id="fm-type",
                        classes="field-input",
                        allow_blank=False,
                    )

                # ---- Listener ----
                yield Static("  Listener", classes="section-header")
                with Horizontal(classes="field-row"):
                    yield Label("Listen host:", classes="field-label")
                    yield Select(
                        ifaces,
                        value=listen_val,
                        id="fm-listen-host",
                        classes="field-input",
                        allow_blank=False,
                    )
                with Horizontal(classes="field-row"):
                    yield Label("Listen port:", classes="field-label")
                    yield Input(
                        value=str(fwd.listen_port),
                        id="fm-listen-port",
                        restrict=r"\d*",
                        classes="field-input",
                    )

                # ---- Upstream (TCP / UDP) ----
                with Vertical(id="fm-section-upstream"):
                    yield Static("  Upstream", classes="section-header")
                    with Horizontal(classes="field-row"):
                        yield Label("Upstream host:", classes="field-label")
                        yield Input(value=fwd.upstream_host, id="fm-upstream-host", classes="field-input")
                    with Horizontal(classes="field-row"):
                        yield Label("Upstream port:", classes="field-label")
                        yield Input(
                            value=str(fwd.upstream_port),
                            id="fm-upstream-port",
                            restrict=r"\d*",
                            classes="field-input",
                        )

                # ---- UDP-specific ----
                with Vertical(id="fm-section-udp"):
                    yield Static("  UDP", classes="section-header")
                    with Horizontal(classes="field-row"):
                        yield Label("Idle timeout (s):", classes="field-label")
                        yield Input(
                            value=str(fwd.udp_idle_timeout),
                            id="fm-udp-idle",
                            restrict=r"[\d.]*",
                            classes="field-input",
                        )

                # ---- SOCKS5-specific ----
                with Vertical(id="fm-section-socks"):
                    yield Static("  SOCKS5 auth", classes="section-header")
                    with Horizontal(classes="field-row"):
                        yield Label("Username:", classes="field-label")
                        yield Input(
                            value=fwd.socks_auth_user or "",
                            id="fm-socks-user",
                            placeholder="(blank = no auth)",
                            classes="field-input",
                        )
                    with Horizontal(classes="field-row"):
                        yield Label("Password:", classes="field-label")
                        yield Input(
                            value=fwd.socks_auth_pass or "",
                            id="fm-socks-pass",
                            password=True,
                            classes="field-input",
                        )

                # ---- Sessions / buffer ----
                yield Static("  Sessions", classes="section-header")
                with Horizontal(classes="field-row"):
                    yield Label("Max sessions (0=∞):", classes="field-label")
                    yield Input(
                        value=str(fwd.max_sessions),
                        id="fm-max-sessions",
                        restrict=r"\d*",
                        classes="field-input",
                    )
                with Horizontal(classes="field-row"):
                    yield Label("Buffer size (bytes):", classes="field-label")
                    yield Input(
                        value=str(fwd.read_buffer_size),
                        id="fm-read-buffer",
                        restrict=r"\d*",
                        classes="field-input",
                    )

                # ---- TLS client side ----
                with Vertical(id="fm-section-tls"):
                    yield Static("  SSL/TLS", classes="section-header")
                    with Horizontal(classes="field-row"):
                        yield Label("SSL/TLS client side:", classes="field-label")
                        yield Switch(value=fwd.tls_listen, id="fm-tls-listen")
                    with Horizontal(classes="field-row"):
                        yield Label("SSL/TLS upstream:", classes="field-label")
                        yield Switch(value=fwd.tls_upstream, id="fm-tls-upstream")
                    with Vertical(id="fm-tls-paths"):
                        with Horizontal(classes="field-row"):
                            yield Label("CA cert path:", classes="field-label")
                            yield Input(
                                value=fwd.ca_cert_path or "",
                                id="fm-ca-cert",
                                placeholder="~/.protopoke/ca.crt",
                                classes="field-input",
                            )
                            yield Button("Browse", id="fm-browse-ca-cert", classes="btn-browse")
                        with Horizontal(classes="field-row"):
                            yield Label("CA key path:", classes="field-label")
                            yield Input(
                                value=fwd.ca_key_path or "",
                                id="fm-ca-key",
                                placeholder="~/.protopoke/ca.key",
                                classes="field-input",
                            )
                            yield Button("Browse", id="fm-browse-ca-key", classes="btn-browse")
                        with Horizontal(classes="field-row"):
                            yield Label("Manual cert path:", classes="field-label")
                            yield Input(
                                value=fwd.tls_cert_path or "",
                                id="fm-tls-cert",
                                placeholder="(optional override)",
                                classes="field-input",
                            )
                            yield Button("Browse", id="fm-browse-tls-cert", classes="btn-browse")
                        with Horizontal(classes="field-row"):
                            yield Label("Manual key path:", classes="field-label")
                            yield Input(
                                value=fwd.tls_key_path or "",
                                id="fm-tls-key",
                                placeholder="(optional override)",
                                classes="field-input",
                            )
                            yield Button("Browse", id="fm-browse-tls-key", classes="btn-browse")

                # ---- Framing ----
                with Vertical(id="fm-section-framing"):
                    yield Static("  Framing", classes="section-header")
                    with Horizontal(classes="field-row"):
                        yield Label("Framer:", classes="field-label")
                        yield Button("Edit", id="fm-btn-framer-edit", classes="btn-framer-edit")
                        yield Static(
                            _framer_summary(self._framer_name, self._framer_kwargs, self._custom_framer_path),
                            id="fm-framer-summary",
                            classes="framer-summary",
                        )

                # ---- Protocol ----
                yield Static("  Protocol Definition", classes="section-header")
                with Horizontal(classes="field-row"):
                    yield Label("Definition file:", classes="field-label")
                    yield Input(
                        value=fwd.protocol_definition_path or "",
                        id="fm-proto-def",
                        placeholder="/path/to/protocol.yaml",
                        classes="field-input",
                    )
                    yield Button("Browse", id="fm-browse-proto-def", classes="btn-browse")

            # ---- Action buttons ----
            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="fm-btn-cancel")
                yield Button("Save", variant="primary", id="fm-btn-save")

    def _set_tls_paths_enabled(self, enabled: bool) -> None:
        """Enable or disable the TLS cert/key inputs and browse buttons."""
        tls_ids = ["fm-ca-cert", "fm-ca-key", "fm-tls-cert", "fm-tls-key",
                   "fm-browse-ca-cert", "fm-browse-ca-key", "fm-browse-tls-cert", "fm-browse-tls-key"]
        for wid in tls_ids:
            try:
                self.query_one(f"#{wid}").disabled = not enabled
            except Exception:
                pass

    def _apply_type_visibility(self, type_value: str) -> None:
        """Show or hide sections based on the selected forwarder type."""
        # Default: all sections visible (TCP)
        show_upstream = True
        show_tls      = True
        show_udp      = False
        show_socks    = False
        framing_disabled = False

        if type_value == ForwarderType.UDP.value:
            show_tls = False
            show_udp = True
            framing_disabled = True   # UDP forces RawFramer
        elif type_value == ForwarderType.SOCKS5.value:
            show_upstream = False     # target is client-supplied
            show_tls      = False     # SOCKS5 + tls_listen is rejected at config
            show_socks    = True

        for sect_id, visible in (
            ("fm-section-upstream", show_upstream),
            ("fm-section-tls",      show_tls),
            ("fm-section-udp",      show_udp),
            ("fm-section-socks",    show_socks),
        ):
            try:
                self.query_one(f"#{sect_id}").display = visible
            except Exception:
                pass

        try:
            self.query_one("#fm-btn-framer-edit").disabled = framing_disabled
        except Exception:
            pass

    def on_mount(self) -> None:
        # Enable/disable TLS path fields based on the client-side TLS toggle
        self._set_tls_paths_enabled(self._forwarder.tls_listen)

        # Show/hide sections based on the configured forwarder type
        self._apply_type_visibility(self._forwarder.forwarder_type.value)

        # Disable fields that require a restart when the forwarder is running
        if self._is_running:
            for wid in self._RESTART_ONLY_IDS:
                try:
                    self.query_one(f"#{wid}").disabled = True
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "fm-type":
            value = event.value if event.value is not Select.BLANK else ForwarderType.TCP.value
            self._apply_type_visibility(str(value))

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id == "fm-tls-listen":
            self._set_tls_paths_enabled(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id

        _browse_map = {
            "fm-browse-ca-cert":   "fm-ca-cert",
            "fm-browse-ca-key":    "fm-ca-key",
            "fm-browse-tls-cert":  "fm-tls-cert",
            "fm-browse-tls-key":   "fm-tls-key",
            "fm-browse-proto-def": "fm-proto-def",
        }
        if btn_id in _browse_map:
            target_id = _browse_map[btn_id]
            current = self.query_one(f"#{target_id}", Input).value.strip() or None

            def _on_pick(path: str | None, _tid: str = target_id) -> None:
                if path is not None:
                    self.query_one(f"#{_tid}", Input).value = path
            self.app.push_screen(FilePickerModal(current), _on_pick)
            return

        if btn_id == "fm-btn-framer-edit":
            settings: FramerSettings = {
                "framer_name": self._framer_name,
                "framer_kwargs": dict(self._framer_kwargs),
                "custom_framer_path": self._custom_framer_path,
            }
            self.app.push_screen(FramerEditModal(settings), self._on_framer_edit_result)
        elif btn_id == "fm-btn-save":
            self._save()
        elif btn_id == "fm-btn-cancel":
            self.dismiss(None)

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)

    def _on_framer_edit_result(self, result: FramerSettings | None) -> None:
        if result is None:
            return
        self._framer_name = result["framer_name"]
        self._framer_kwargs = dict(result["framer_kwargs"])
        self._custom_framer_path = result.get("custom_framer_path")
        try:
            self.query_one("#fm-framer-summary", Static).update(
                _framer_summary(self._framer_name, self._framer_kwargs, self._custom_framer_path)
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def _save(self) -> None:
        """Read form values, build a ForwarderConfig, and dismiss."""

        def _str(wid: str) -> str:
            return self.query_one(f"#{wid}", Input).value.strip()

        def _int(wid: str, default: int = 0) -> int:
            try:
                return int(_str(wid))
            except ValueError:
                return default

        def _sw(wid: str) -> bool:
            return self.query_one(f"#{wid}", Switch).value

        def _sel(wid: str) -> str:
            val = self.query_one(f"#{wid}", Select).value
            return str(val) if val and val is not Select.BLANK else ""

        name = _str("fm-name") or "Forwarder"

        # Duplicate name check (allow keeping the same name when editing)
        if name != self._original_name and name in self._existing_names:
            self.app.notify(f"A forwarder named '{name}' already exists.", severity="error")
            return

        fwd = self._forwarder
        fwd.name = name

        type_value = _sel("fm-type") or ForwarderType.TCP.value
        try:
            fwd.forwarder_type = ForwarderType(type_value)
        except ValueError:
            fwd.forwarder_type = ForwarderType.TCP

        fwd.listen_host = _sel("fm-listen-host") or "127.0.0.1"
        fwd.listen_port = _int("fm-listen-port", 8080)
        fwd.upstream_host = _str("fm-upstream-host") or "127.0.0.1"
        fwd.upstream_port = _int("fm-upstream-port", 9090)
        fwd.max_sessions = _int("fm-max-sessions", 0)
        fwd.read_buffer_size = _int("fm-read-buffer", 4096)

        # UDP and SOCKS5 cannot use tls_listen — strip it preemptively so
        # ForwarderConfig.__post_init__ doesn't reject the save.
        if fwd.forwarder_type in (ForwarderType.UDP, ForwarderType.SOCKS5):
            fwd.tls_listen = False
        else:
            fwd.tls_listen = _sw("fm-tls-listen")
        fwd.tls_upstream = _sw("fm-tls-upstream")
        fwd.ca_cert_path = _str("fm-ca-cert") or None
        fwd.ca_key_path = _str("fm-ca-key") or None
        fwd.tls_cert_path = _str("fm-tls-cert") or None
        fwd.tls_key_path = _str("fm-tls-key") or None

        # UDP-specific
        try:
            fwd.udp_idle_timeout = float(_str("fm-udp-idle") or "60")
        except ValueError:
            fwd.udp_idle_timeout = 60.0
        if fwd.udp_idle_timeout <= 0:
            fwd.udp_idle_timeout = 60.0

        # SOCKS5-specific
        fwd.socks_auth_user = _str("fm-socks-user") or None
        fwd.socks_auth_pass = _str("fm-socks-pass") or None
        if fwd.socks_auth_user is None:
            fwd.socks_auth_pass = None  # password without username is ignored

        # UDP forwarders force the RawFramer (no stateful framer makes sense
        # for datagrams).
        if fwd.forwarder_type is ForwarderType.UDP:
            fwd.framer_name = "raw"
            fwd.framer_kwargs = {}
            fwd.custom_framer_path = None
        else:
            fwd.framer_name = self._framer_name
            fwd.framer_kwargs = dict(self._framer_kwargs)
            fwd.custom_framer_path = self._custom_framer_path
        fwd.protocol_definition_path = _str("fm-proto-def") or None

        self.dismiss(fwd)
