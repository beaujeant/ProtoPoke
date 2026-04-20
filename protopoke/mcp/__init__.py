"""MCP server for ProtoPoke — exposes ProtoPokeAPI operations as AI-callable tools.

Typical usage is via the Textual UI with ``protopoke --mcp``, which starts an
embedded MCP server bound to the live UI state and served over streamable-http
at ``http://127.0.0.1:7878/mcp`` by default.

For programmatic use::

    from protopoke.api import ProtoPokeAPI
    from protopoke.config import ForwarderConfig
    from protopoke.mcp import MCPHost, MCPSettings

    api = ProtoPokeAPI([ForwarderConfig(name="Default", upstream_host="...")])
    host = MCPHost(api, MCPSettings(enabled=True))
    await host.start()
"""

from .host import MCPHost, MCPSettings
from .server import build_mcp_server

__all__ = ["build_mcp_server", "MCPHost", "MCPSettings"]
