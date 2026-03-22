"""MCP server for ProtoPoke — exposes ProtoPokeAPI operations as AI-callable tools.

Usage:
    from protopoke.api import ProtoPokeAPI
    from protopoke.config import ForwarderConfig
    from protopoke.mcp.server import build_mcp_server

    api = ProtoPokeAPI([ForwarderConfig(name="Default", upstream_host="...")])
    mcp = build_mcp_server(api)
    mcp.run()
"""

from .server import build_mcp_server

__all__ = ["build_mcp_server"]
