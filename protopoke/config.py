"""
Forwarder configuration.

All runtime settings for a single forwarder live here as a single dataclass.
This makes it easy to:
- Create configs programmatically (in scripts, tests)
- Load from a file (JSON)
- Pass a config around without global state
- Override individual fields for testing

There is no global config singleton. Every ProxyEngine and ProtoPokeAPI takes
an explicit ForwarderConfig.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class ForwarderType(str, Enum):
    """Transport type for a forwarder."""

    TCP    = "tcp"
    UDP    = "udp"
    SOCKS5 = "socks5"


@dataclass
class ForwarderConfig:
    """
    Configuration for one named forwarder instance.

    Identity:
        name:    Human-readable label shown in the Config tab.
        enabled: When False the forwarder is excluded from "Start All".

    Networking:
        listen_host:      Local address to bind on. Use "0.0.0.0" for all interfaces.
        listen_port:      Local TCP port to accept connections on.
        upstream_host:    Remote host to forward connections to.
        upstream_port:    Remote TCP port to forward connections to.
        connect_timeout:  Seconds to wait when connecting to upstream.
        read_buffer_size: Bytes per asyncio read() call. Doesn't affect framing
                          logic — just controls how often the relay wakes up.

    Sessions:
        max_sessions:     Maximum concurrent proxied connections. 0 = unlimited.

    Interception:
        tamper_enabled: When True, frames are held in the tamper queue
                           waiting for a human verdict. When False, everything
                           is forwarded immediately.

    Framing:
        framer_name:    Which framer to use. Must be a key in
                        protopoke.framing.FRAMER_REGISTRY.
                        - "raw":           Passthrough; each read() chunk = one frame.
                        - "delimiter":     Split on a byte sequence.
                        - "length_prefix": Fixed-size integer length header.
                        - "line":          Split on \\r\\n or \\n.
        framer_kwargs:  Extra kwargs forwarded to the framer constructor.
                        e.g. {"delimiter": b"\\r\\n"} for the delimiter framer.

    Logging:
        log_level: Python logging level name ("DEBUG", "INFO", "WARNING", ...).

    TLS:
        tls_listen:    Wrap client connections with TLS (MITM mode).
        tls_upstream:  Connect to upstream server over TLS. Upstream cert
                       verification is always disabled — this tool is for
                       reverse engineering and accepts any certificate.
        ca_cert_path:  CA cert path. Auto-generated at ~/.protopoke/ca.crt.
        ca_key_path:   CA key path.  Auto-generated at ~/.protopoke/ca.key.
        tls_cert_path: Manual cert override (skips auto-CA).
        tls_key_path:  Private key for tls_cert_path.
    """

    # Identity
    name:    str  = "Forwarder"
    enabled: bool = True

    # Transport type — selects the listening engine (TCP/UDP/SOCKS5).
    forwarder_type: ForwarderType = ForwarderType.TCP

    # Networking
    listen_host:      str   = "127.0.0.1"
    listen_port:      int   = 8080
    upstream_host:    str   = "127.0.0.1"
    upstream_port:    int   = 9090
    connect_timeout:  float = 10.0
    read_buffer_size: int   = 4096

    # SOCKS5 — credentials. None means no-auth method advertised.
    socks_auth_user: Optional[str] = None
    socks_auth_pass: Optional[str] = None

    # Sessions
    max_sessions: int = 0  # 0 = unlimited

    # Lifecycle
    # When True (default), the upstream server connection is kept alive after
    # the client disconnects.  The session transitions to ONLY_SERVER and stays
    # there until the server closes or the user terminates the session, so the
    # Forge tab can keep injecting frames into the live connection.  Set to
    # False to restore the legacy behaviour where a client disconnect tears
    # down the server connection via a TCP half-close.
    keep_upstream_on_client_disconnect: bool = True
    # Symmetric counterpart: when True (default), the client connection is kept
    # writable after the upstream server disconnects.  The session transitions
    # to ONLY_CLIENT and the proxy does NOT half-close its write side toward
    # the client, so the Forge tab can keep injecting server→client frames.
    # Set to False to restore the legacy behaviour where a server disconnect
    # propagates a TCP half-close to the client.
    keep_client_on_server_disconnect: bool = True

    # Interception
    tamper_enabled: bool = False

    # Framing
    framer_name:   str  = "raw"
    framer_kwargs: dict = field(default_factory=dict)

    # Logging
    log_level: str = "INFO"

    # ------------------------------------------------------------------
    # TLS / SSL
    # ------------------------------------------------------------------

    # Listening side — wrap client→proxy connections with TLS (MITM mode).
    # The proxy presents a certificate to the client; the client must trust
    # the proxy CA (see ca_cert_path) for the handshake to succeed silently.
    tls_listen: bool = False

    # Upstream side — connect to the upstream server over TLS.
    # Certificate verification is always disabled: this tool is for reverse
    # engineering and must accept self-signed / expired / unknown-CA certs.
    tls_upstream: bool = False

    # --- CA for auto-generated per-session leaf certificates (Burp-style) ---
    # If both are None the CA is stored at ~/.protopoke/ca.crt / ca.key and
    # reused across proxy restarts.  Point these at your own CA to use a root
    # that clients already trust (e.g. a corporate CA).
    ca_cert_path: Optional[str] = None
    ca_key_path:  Optional[str] = None

    # --- Manual cert override ---
    # Supply a ready-made certificate instead of auto-generating one via the CA.
    # When set, ca_cert_path / ca_key_path are ignored.  Useful for wildcard
    # certs or certs that clients trust unconditionally.
    tls_cert_path: Optional[str] = None
    tls_key_path:  Optional[str] = None

    # ------------------------------------------------------------------
    # Protocol definition
    # ------------------------------------------------------------------

    # Path to a .yaml or .json protocol definition file.
    # When set, ProtoPokeAPI auto-loads the definition on start() and attaches
    # a DefinitionBasedDecoder so that frames are automatically parsed.
    # The definition can also be loaded manually via api.set_protocol_file().
    protocol_definition_path: Optional[str] = None

    # ------------------------------------------------------------------
    # Custom framer
    # ------------------------------------------------------------------

    # Path to a Python file containing a custom Framer subclass.
    # The first Framer subclass found in the file is used automatically —
    # no class name is required.  When set, framer_name is ignored.
    custom_framer_path: Optional[str] = None

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def __post_init__(self) -> None:
        # Allow string values from JSON to be coerced to enum.
        if isinstance(self.forwarder_type, str):
            self.forwarder_type = ForwarderType(self.forwarder_type)

        if self.forwarder_type is ForwarderType.SOCKS5 and self.tls_listen:
            raise ValueError(
                "SOCKS5 forwarders cannot have tls_listen=True. "
                "Wrapping the SOCKS5 handshake in TLS is non-standard and not supported. "
                "Disable TLS-listen or change the forwarder type."
            )

        if self.forwarder_type is ForwarderType.UDP and self.tls_listen:
            raise ValueError(
                "UDP forwarders cannot have tls_listen=True (DTLS is not supported)."
            )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dict."""
        d: dict = {}
        for f in self.__dataclass_fields__:
            val = getattr(self, f)
            if isinstance(val, dict):
                # framer_kwargs may contain bytes values (e.g. delimiter).
                # Encode bytes as hex strings for JSON compatibility.
                val = {
                    k: (v.hex() if isinstance(v, (bytes, bytearray)) else v)
                    for k, v in val.items()
                }
            elif isinstance(val, ForwarderType):
                val = val.value
            d[f] = val
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ForwarderConfig":
        """Deserialise from a dict (as produced by to_dict())."""
        kwargs = {}
        for f_name, f_obj in cls.__dataclass_fields__.items():
            if f_name not in d:
                continue
            val = d[f_name]
            # framer_kwargs: re-decode any hex-encoded bytes values
            if f_name == "framer_kwargs" and isinstance(val, dict):
                decoded: dict = {}
                for k, v in val.items():
                    if isinstance(v, str):
                        try:
                            decoded[k] = bytes.fromhex(v)
                        except ValueError:
                            decoded[k] = v
                    else:
                        decoded[k] = v
                val = decoded
            elif f_name == "forwarder_type" and isinstance(val, str):
                val = ForwarderType(val)
            kwargs[f_name] = val
        return cls(**kwargs)

    def save(self, path: str | Path) -> None:
        """Write config as JSON to *path*."""
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "ForwarderConfig":
        """Load config from a JSON file written by save()."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)
