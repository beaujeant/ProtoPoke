"""MCP server for ProtoPoke — exposes ProxyAPI operations as AI-callable tools.

Usage:
    from protopoke.api import ProxyAPI
    from protopoke.config import ProxyConfig
    from protopoke.mcp.server import build_mcp_server

    api = ProxyAPI(ProxyConfig(...))
    mcp = build_mcp_server(api)
    mcp.run()
"""

from .server import build_mcp_server

__all__ = ["build_mcp_server"]
