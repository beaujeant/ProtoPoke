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
    --project PATH              Load forwarders/rules/playbooks from a .pp project file
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

Or with a project file::

    {
      "mcpServers": {
        "protopoke": {
          "command": "protopoke-mcp",
          "args": ["--project", "/path/to/myproject.pp"]
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

from ..api import ProtoPokeAPI
from ..config import ForwarderConfig
from .server import build_mcp_server


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="protopoke-mcp",
        description="ProtoPoke MCP server — expose proxy operations as AI tools.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Networking (convenience shortcuts — create a "Default" forwarder)
    p.add_argument("--listen-host",   default=None,  metavar="HOST",
                   help="Proxy listen address (default: 127.0.0.1)")
    p.add_argument("--listen-port",   default=None,  type=int, metavar="PORT",
                   help="Proxy listen port (default: 8080)")
    p.add_argument("--upstream-host", default=None,  metavar="HOST",
                   help="Upstream host to forward connections to (default: 127.0.0.1)")
    p.add_argument("--upstream-port", default=None,  type=int, metavar="PORT",
                   help="Upstream port (default: 9090)")

    # Project file
    p.add_argument("--project", default=None, metavar="PATH",
                   help="Load forwarders, rules, and playbooks from a .pp project file")

    # Logging / naming
    p.add_argument("--log-level", default="WARNING", metavar="LEVEL",
                   help="Python logging level (default: WARNING)")
    p.add_argument("--name", default="ProtoPoke", metavar="NAME",
                   help="MCP server name shown to the AI client (default: ProtoPoke)")

    return p


def _make_forwarders(args: argparse.Namespace) -> tuple[
    list[ForwarderConfig],
    "Optional[RulesEngine]",
    "Optional[InterceptFilter]",
]:
    """Build forwarders (and optionally rules) from parsed CLI arguments."""
    from ..rules.engine import RulesEngine, InterceptFilter

    rules_engine: Optional[RulesEngine] = None
    intercept_filter: Optional[InterceptFilter] = None

    # If a project file is provided, load everything from it
    if args.project:
        from ..project.manager import ProjectManager
        pm = ProjectManager()
        state = pm.open(args.project)
        forwarders = state.forwarders
        rules_engine = state.rules_engine
        intercept_filter = state.intercept_filter
        return forwarders, rules_engine, intercept_filter

    # Otherwise build a single forwarder from CLI args (if any upstream specified)
    has_network = any([
        args.listen_host, args.listen_port,
        args.upstream_host, args.upstream_port,
    ])

    if has_network:
        fwd = ForwarderConfig(name="Default", enabled=True)
        if args.listen_host   is not None: fwd.listen_host   = args.listen_host
        if args.listen_port   is not None: fwd.listen_port   = args.listen_port
        if args.upstream_host is not None: fwd.upstream_host  = args.upstream_host
        if args.upstream_port is not None: fwd.upstream_port  = args.upstream_port
        return [fwd], None, None

    # No config at all — start with no forwarders; AI configures via tools
    return [], None, None


async def _run(
    forwarders: list[ForwarderConfig],
    rules_engine: "Optional[RulesEngine]",
    intercept_filter: "Optional[InterceptFilter]",
    mcp_name: str,
) -> None:
    """Start the proxy and serve the MCP server until EOF on stdin."""
    kwargs: dict = {"forwarders": forwarders}
    if rules_engine is not None:
        kwargs["rules_engine"] = rules_engine
    if intercept_filter is not None:
        kwargs["intercept_filter"] = intercept_filter

    api = ProtoPokeAPI(**kwargs)

    if forwarders:
        logging.info(
            "ProtoPoke MCP: starting %d forwarder(s)", len(forwarders),
        )
        await api.start()
    else:
        logging.info("ProtoPoke MCP: started with no forwarders (configure via tools)")

    mcp = build_mcp_server(api, name=mcp_name)

    try:
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

    forwarders, rules_engine, intercept_filter = _make_forwarders(args)

    try:
        asyncio.run(_run(forwarders, rules_engine, intercept_filter, mcp_name=args.name))
    except KeyboardInterrupt:
        pass
