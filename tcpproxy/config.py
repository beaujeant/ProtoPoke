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
