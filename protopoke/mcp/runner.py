"""
ProtoPoke MCP server runner.

Starts the TCP proxy and exposes all proxy operations as MCP tools via
the Model Context Protocol (stdio transport), so AI assistants such as
Claude can control the proxy directly.

Usage
-----
As a standalone command (after ``pip install protopoke[mcp]``)::

    protopoke-mcp [options]

Or inline with ``--mcp`` from the main entry point::

    protopoke --mcp [options]

Options
-------
    --listen-host HOST          Proxy listen address (default: 127.0.0.1)
    --listen-port PORT          Proxy listen port    (default: 8080)
    --upstream-host HOST        Upstream host        (default: 127.0.0.1)
    --upstream-port PORT        Upstream port        (default: 9090)
    --tamper                    Enable tamper on startup
    --tls-listen                Wrap client side with TLS (MITM mode)
    --tls-upstream              Connect to upstream over TLS
    --framer NAME               Framer: raw | delimiter | length_prefix
    --protocol PATH             Path to .yaml/.json protocol definition
    --config PATH               Load a ProxyConfig from a JSON file
    --log-level LEVEL           Logging level (default: WARNING)
    --name NAME                 MCP server name (default: ProtoPoke)

Integration with Claude Desktop
---------------------------------
Add to ``~/Library/Application Support/Claude/claude_desktop_config.json``::

    {
      "mcpServers": {
        "protopoke": {
          "command": "protopoke-mcp",
          "args": ["--upstream-host", "10.0.0.1", "--upstream-port", "9090"]
        }
      }
    }
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import Optional

from ..api import ProxyAPI
from ..config import ForwarderConfig, ProxyConfig
from .server import build_mcp_server


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="protopoke-mcp",
        description="ProtoPoke MCP server — expose proxy operations as AI tools.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Networking
    p.add_argument("--listen-host",   default=None,  metavar="HOST",
                   help="Proxy listen address (default: 127.0.0.1)")
    p.add_argument("--listen-port",   default=None,  type=int, metavar="PORT",
                   help="Proxy listen port (default: 8080)")
    p.add_argument("--upstream-host", default=None,  metavar="HOST",
                   help="Upstream host to forward connections to (default: 127.0.0.1)")
    p.add_argument("--upstream-port", default=None,  type=int, metavar="PORT",
                   help="Upstream port (default: 9090)")

    # Tamper
    p.add_argument("--tamper", action="store_true",
                   help="Enable tamper on startup (frames held for review)")

    # TLS (upstream cert verification is always disabled in reverser mode)
    p.add_argument("--tls-listen", action="store_true",
                   help="Wrap client connections with TLS (MITM mode)")
    p.add_argument("--tls-upstream", action="store_true",
                   help="Connect to upstream over TLS (cert verification always disabled)")

    # Framing / Protocol
    p.add_argument("--framer", default=None, metavar="NAME",
                   help="Framer: raw (default) | delimiter | length_prefix")
    p.add_argument("--protocol", default=None, metavar="PATH",
                   help="Path to a .yaml/.json protocol definition file")

    # Config file
    p.add_argument("--config", default=None, metavar="PATH",
                   help="Load a ProxyConfig JSON file produced by protopoke (overridden by other flags)")

    # Logging / naming
    p.add_argument("--log-level", default="WARNING", metavar="LEVEL",
                   help="Python logging level (default: WARNING)")
    p.add_argument("--name", default="ProtoPoke", metavar="NAME",
                   help="MCP server name shown to the AI client (default: ProtoPoke)")

    return p


def _make_config(args: argparse.Namespace) -> ProxyConfig:
    """Build a ProxyConfig from parsed CLI arguments."""
    # Start from a file if provided, otherwise from defaults
    if args.config:
        config = ProxyConfig.load(args.config)
    else:
        config = ProxyConfig()

    # Apply individual overrides (CLI flags win over file values)
    if args.listen_host   is not None: config.listen_host       = args.listen_host
    if args.listen_port   is not None: config.listen_port       = args.listen_port
    if args.upstream_host is not None: config.upstream_host     = args.upstream_host
    if args.upstream_port is not None: config.upstream_port     = args.upstream_port
    if args.tamper:                    config.tamper_enabled = True
    if args.tls_listen:                config.tls_listen        = True
    if args.tls_upstream:              config.tls_upstream      = True
    if args.framer        is not None: config.framer_name       = args.framer
    if args.protocol      is not None: config.protocol_definition_path = args.protocol

    return config


async def _run(config: ProxyConfig, mcp_name: str) -> None:
    """Start the proxy and serve the MCP server until EOF on stdin."""
    api = ProxyAPI(forwarders=[ForwarderConfig(name="Default", enabled=True, config=config)])

    logging.info(
        "ProtoPoke MCP: starting proxy %s:%d → %s:%d",
        config.listen_host, config.listen_port,
        config.upstream_host, config.upstream_port,
    )

    await api.start()

    mcp = build_mcp_server(api, name=mcp_name)

    try:
        # FastMCP.run_async() serves over stdio and blocks until the client
        # closes the connection (or the process is killed).
        await mcp.run_async()
    finally:
        await api.stop()


def main(argv: Optional[list[str]] = None) -> None:
    """Entry point for the ``protopoke-mcp`` command."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.WARNING),
        stream=sys.stderr,  # MCP uses stdout; log to stderr
        format="%(levelname)s %(name)s: %(message)s",
    )

    config = _make_config(args)

    try:
        asyncio.run(_run(config, mcp_name=args.name))
    except KeyboardInterrupt:
        pass
