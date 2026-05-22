"""Stdio <-> streamable-http MCP bridge.

ProtoPoke's embedded MCP server only speaks ``streamable-http`` because it
lives inside the long-running TUI process and shares the same
:class:`~protopoke.api.ProtoPokeAPI` instance with the operator. Several MCP
clients - including the standard Claude Desktop, ChatGPT Desktop, Cursor
configured for stdio servers, and many community agents - only support
launching ``stdio`` MCP servers from their config file. This module provides
a minimal stdio <-> HTTP forwarder so those clients can talk to a running
ProtoPoke TUI.

Usage::

    # Operator side (once):
    protopoke --mcp

    # AI client side (Claude Desktop config, etc.):
    {"command": "protopoke-mcp"}

The bridge is intentionally stateless: it forwards every JSON-RPC message
in both directions and exits when either side closes. Spawning multiple
bridges against the same TUI is safe; each one is an independent HTTP
client against the single embedded server.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_URL = "http://127.0.0.1:7878/mcp"
ENV_URL = "PROTOPOKE_MCP_URL"


async def run_bridge(url: str) -> None:
    """Forward MCP messages between stdio (this process) and an HTTP MCP server.

    Returns when either transport closes. Surfaces transport errors as the
    underlying exception types (httpx / anyio); the console entry point
    wraps them in a friendly message.
    """
    try:
        import anyio
        from mcp.client.streamable_http import streamablehttp_client
        from mcp.server.stdio import stdio_server
    except ImportError as exc:
        raise ImportError(
            "The 'mcp' package is required for the stdio bridge. "
            "Install it with: pip install 'protopoke[mcp]'"
        ) from exc

    async with streamablehttp_client(url) as (http_read, http_write, _get_session_id):
        async with stdio_server() as (stdio_read, stdio_write):
            async with anyio.create_task_group() as tg:
                async def pump(reader, writer, label: str) -> None:
                    try:
                        async for message in reader:
                            if isinstance(message, Exception):
                                logger.warning(
                                    "%s: dropping malformed message: %s", label, message
                                )
                                continue
                            await writer.send(message)
                    finally:
                        tg.cancel_scope.cancel()

                tg.start_soon(pump, stdio_read, http_write, "stdio->http")
                tg.start_soon(pump, http_read, stdio_write, "http->stdio")


def _looks_like_connect_failure(exc: BaseException) -> bool:
    """Detect TCP-refusal / DNS failures buried in a (possibly nested) ExceptionGroup."""
    if isinstance(exc, (ConnectionError, OSError)):
        return True
    name = type(exc).__name__
    if name in ("ConnectError", "ConnectTimeout", "ReadError", "RemoteProtocolError"):
        return True
    inner = getattr(exc, "exceptions", None)
    if inner:
        return any(_looks_like_connect_failure(e) for e in inner)
    return False


def _friendly_connect_error(url: str, original: BaseException) -> str:
    return (
        f"Could not reach the ProtoPoke MCP server at {url}.\n"
        f"Start the TUI with `protopoke --mcp` (and check --mcp-host / --mcp-port "
        f"if you moved it).\n"
        f"Underlying error: {original!r}"
    )


def main() -> None:
    """Console-script entry point: ``protopoke-mcp``."""
    parser = argparse.ArgumentParser(
        prog="protopoke-mcp",
        description=(
            "Stdio bridge to ProtoPoke's embedded MCP server. Launched by "
            "stdio-only AI clients (Claude Desktop, ChatGPT Desktop, ...) to "
            "reach the streamable-http MCP endpoint served by `protopoke --mcp`."
        ),
    )
    parser.add_argument(
        "--url",
        default=os.environ.get(ENV_URL, DEFAULT_URL),
        metavar="URL",
        help=(
            f"URL of the ProtoPoke MCP server. "
            f"Default: {DEFAULT_URL} (override via ${ENV_URL} or this flag)."
        ),
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Log forwarder activity to stderr.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        stream=sys.stderr,
        format="protopoke-mcp: %(message)s",
    )

    try:
        import anyio
    except ImportError as exc:
        print(
            "protopoke-mcp: the 'mcp' extra is not installed. "
            "Run: pip install 'protopoke[mcp]'",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc

    try:
        anyio.run(run_bridge, args.url)
    except KeyboardInterrupt:
        pass
    except BaseException as exc:  # noqa: BLE001 - we want to classify any failure
        if _looks_like_connect_failure(exc):
            print(
                f"protopoke-mcp: {_friendly_connect_error(args.url, exc)}",
                file=sys.stderr,
            )
            raise SystemExit(1) from exc
        raise


if __name__ == "__main__":
    main()
