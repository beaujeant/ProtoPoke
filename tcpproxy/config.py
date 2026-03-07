"""
Proxy configuration.

All runtime settings live here as a single dataclass. This makes it easy to:
- Create configs programmatically (in scripts, tests)
- Load from a file (JSON/TOML — add a classmethod for that)
- Pass a config around without global state
- Override individual fields for testing

There is no global config singleton. Every ProxyEngine and ProxyAPI takes
an explicit ProxyConfig.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ProxyConfig:
    """
    Configuration for one proxy instance.

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
        intercept_enabled: When True, frames are held in the intercept queue
                           waiting for a human verdict. When False, everything
                           is forwarded immediately.

    Framing:
        framer_name:    Which framer to use. Must be a key in
                        tcpproxy.framing.FRAMER_REGISTRY.
                        - "raw":          Passthrough; each read() chunk = one frame.
                        - "delimiter":    Split on a byte sequence.
                        - "length_prefix": Fixed-size integer length header.
        framer_kwargs:  Extra kwargs forwarded to the framer constructor.
                        e.g. {"delimiter": b"\\r\\n"} for the delimiter framer.

    Logging:
        log_level: Python logging level name ("DEBUG", "INFO", "WARNING", ...).

    TLS:
        tls_listen:          Wrap client connections with TLS (MITM mode).
        tls_upstream:        Connect to upstream server over TLS.
        tls_upstream_verify: Verify upstream cert/hostname (default True).
        ca_cert_path:        CA cert path. Auto-generated at ~/.tcpproxy/ca.crt.
        ca_key_path:         CA key path.  Auto-generated at ~/.tcpproxy/ca.key.
        tls_cert_path:       Manual cert override (skips auto-CA).
        tls_key_path:        Private key for tls_cert_path.
    """
    # Networking
    listen_host:      str   = "127.0.0.1"
    listen_port:      int   = 8080
    upstream_host:    str   = "127.0.0.1"
    upstream_port:    int   = 9090
    connect_timeout:  float = 10.0
    read_buffer_size: int   = 4096

    # Sessions
    max_sessions: int = 0  # 0 = unlimited

    # Interception
    intercept_enabled: bool = False

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
    tls_upstream: bool = False

    # When True (default) the proxy verifies the upstream server's certificate
    # chain and hostname.  Set False to accept any certificate — useful for
    # self-signed or expired certs on internal services (equivalent to Burp's
    # "Accept any certificate" toggle).
    tls_upstream_verify: bool = True

    # --- CA for auto-generated per-session leaf certificates (Burp-style) ---
    # If both are None the CA is stored at ~/.tcpproxy/ca.crt / ca.key and
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
