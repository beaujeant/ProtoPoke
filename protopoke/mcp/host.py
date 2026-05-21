"""
MCPHost — embedded MCP server lifecycle manager.

Wraps a FastMCP server bound to a :class:`~protopoke.api.ProtoPokeAPI` instance
and runs it as a background asyncio task, so the MCP endpoint can live inside
the Textual UI process alongside the proxy engines it exposes.

Key features:

* **Rebindable**: the API reference is stored in a closure cell that can be
  swapped via :meth:`rebind`, so project reloads (which rebuild
  ``ProtoPokeAPI``) do not require tearing down the HTTP listener. AI clients
  stay connected across project changes.

* **Opt-in**: the host is constructed disabled by default. :meth:`start` is a
  no-op unless :attr:`settings.enabled` is ``True``. No port is opened without
  explicit user action.

* **Settings-driven restart**: :meth:`apply` diff-checks new settings and
  restarts the server only when the listening host/port or enabled flag
  changes.

* **Transport**: uses MCP ``streamable-http``. The endpoint is served at
  ``http://<host>:<port>/mcp``. Clients that support HTTP MCP directly
  (Claude Code, Cursor, mcp-inspector) connect to that URL. Stdio-only
  clients (the standard Claude Desktop, ChatGPT Desktop, several agents)
  go through the ``protopoke-mcp`` stdio bridge — see
  :mod:`protopoke.mcp.stdio_bridge`.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, replace
from typing import Any, Callable, Optional, Union

from ..api import ProtoPokeAPI

logger = logging.getLogger(__name__)


APIProvider = Union[ProtoPokeAPI, Callable[[], ProtoPokeAPI]]

# How long to wait for uvicorn's graceful shutdown before hard-cancelling.
_GRACEFUL_SHUTDOWN_TIMEOUT = 5.0


def mcp_available() -> bool:
    """Return ``True`` if the optional ``mcp`` package can be imported.

    The embedded MCP server depends on ``mcp.server.fastmcp.FastMCP``, which is
    only present when ProtoPoke is installed with the ``[mcp]`` extra. Callers
    use this to keep the server disabled (with a warning) instead of crashing
    when the dependency is missing.
    """
    try:
        from mcp.server.fastmcp import FastMCP  # noqa: F401
    except ImportError:
        return False
    return True


@dataclass
class MCPSettings:
    """User-facing configuration for the embedded MCP server."""

    enabled: bool = False
    host:    str  = "127.0.0.1"
    port:    int  = 7878
    name:    str  = "ProtoPoke"
    profile: str  = "full"

    def url(self) -> str:
        return f"http://{self.host}:{self.port}/mcp"

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "host":    self.host,
            "port":    self.port,
            "name":    self.name,
            "profile": self.profile,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MCPSettings":
        profile = str(data.get("profile", "full"))
        if profile not in ("full", "analysis"):
            profile = "full"
        return cls(
            enabled=bool(data.get("enabled", False)),
            host=str(data.get("host", "127.0.0.1")),
            port=int(data.get("port", 7878)),
            name=str(data.get("name", "ProtoPoke")),
            profile=profile,
        )


class MCPHost:
    """
    Embedded MCP server bound to a ProtoPokeAPI instance.

    The host owns one FastMCP server and one asyncio Task that runs it. The
    bound API is stored behind an indirection (a closure cell inside
    ``build_mcp_server``) so it can be rebinded via :meth:`rebind` without
    tearing down the task.

    Typical usage inside the Textual app::

        host = MCPHost(lambda: self.api, settings=MCPSettings(enabled=True))
        await host.start()
        # later, when the project changes:
        host.rebind(self.api)
        # on shutdown:
        await host.stop()
    """

    def __init__(
        self,
        api_provider: APIProvider,
        settings: Optional[MCPSettings] = None,
    ) -> None:
        self._initial_provider = api_provider
        self._settings: MCPSettings = replace(settings) if settings else MCPSettings()
        self._server: Any = None
        # The uvicorn.Server driving the FastMCP app. Owned here (rather than
        # hidden inside FastMCP.run_streamable_http_async) so stop() can request
        # a graceful shutdown that closes the listening socket.
        self._uvicorn: Any = None
        self._task: Optional[asyncio.Task] = None
        self._current_api: Optional[ProtoPokeAPI] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def settings(self) -> MCPSettings:
        return self._settings

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the MCP server task if enabled and not already running."""
        if not self._settings.enabled:
            logger.debug("MCPHost.start: disabled, not starting")
            return
        if self.is_running:
            logger.debug("MCPHost.start: already running")
            return

        if not mcp_available():
            logger.warning(
                "MCP server is enabled but the optional 'mcp' package is not "
                "installed; keeping MCP disabled. Install it with: "
                "pip install protopoke[mcp]"
            )
            self._settings = replace(self._settings, enabled=False)
            return

        try:
            from .server import build_mcp_server
        except ImportError as exc:
            logger.error("MCPHost.start: failed to import build_mcp_server: %s", exc)
            raise

        # Resolve the initial API instance.
        api = self._resolve_api()
        self._current_api = api

        self._server = build_mcp_server(
            api, name=self._settings.name, profile=self._settings.profile
        )

        # FastMCP configures host/port via its settings object.
        self._server.settings.host = self._settings.host
        self._server.settings.port = self._settings.port

        logging.getLogger("mcp.server.streamable_http_manager").setLevel(logging.WARNING)

        # Build (but don't yet serve) the uvicorn server here so we own a
        # handle to it before the task runs. stop() needs that handle to drive
        # a graceful shutdown; building it synchronously avoids a start/stop
        # race where the handle isn't set yet. The socket is only bound once
        # serve() runs inside _run_server.
        import uvicorn

        app = self._server.streamable_http_app()
        config = uvicorn.Config(
            app,
            host=self._settings.host,
            port=self._settings.port,
            log_level=self._server.settings.log_level.lower(),
        )
        self._uvicorn = uvicorn.Server(config)

        logger.info(
            "MCP server starting on %s (transport=streamable-http)",
            self._settings.url(),
        )
        self._task = asyncio.create_task(
            self._run_server(),
            name="protopoke-mcp-server",
        )

    async def stop(self) -> None:
        """Stop the running MCP server and wait for it to exit.

        Prefer a *graceful* shutdown (set uvicorn's ``should_exit`` flag) over a
        hard task cancel: a cancelled ``serve()`` skips uvicorn's ``shutdown()``
        and leaks the listening socket, so an immediate restart on the same
        host/port fails to bind. Falls back to cancelling the task if the
        graceful shutdown does not finish in time.
        """
        if self._task is None:
            return
        task = self._task
        uvicorn_server = self._uvicorn
        self._task = None
        self._server = None
        self._uvicorn = None
        self._current_api = None

        if not task.done():
            if uvicorn_server is not None:
                # Ask uvicorn to wind down: it stops accepting connections and
                # closes its listening socket, freeing the port so a restart on
                # the same host/port can rebind.
                uvicorn_server.should_exit = True
            try:
                await asyncio.wait_for(task, timeout=_GRACEFUL_SHUTDOWN_TIMEOUT)
            except asyncio.TimeoutError:
                logger.warning(
                    "MCPHost.stop: graceful shutdown timed out; task cancelled"
                )
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception("MCPHost.stop: server task raised on shutdown")

        logger.info("MCP server stopped")

    async def apply(self, new_settings: MCPSettings) -> None:
        """
        Replace the current settings. Restart the server if the transport-
        visible settings (enabled / host / port) or the tool ``profile``
        changed (the profile is baked in at build time).

        If applying fails (e.g. the optional ``mcp`` package is not
        installed and :meth:`start` raises ``ImportError``), the stored
        settings are rolled back so future ``apply`` diffs compare against
        the real state, not the failed attempt.
        """
        old = self._settings
        self._settings = replace(new_settings)

        transport_changed = (
            old.enabled != new_settings.enabled
            or old.host  != new_settings.host
            or old.port  != new_settings.port
            or old.profile != new_settings.profile
        )
        logger.debug(
            "MCPHost.apply: enabled=%s transport_changed=%s",
            new_settings.enabled, transport_changed,
        )
        if not transport_changed:
            return

        try:
            if self.is_running:
                await self.stop()
            if new_settings.enabled:
                await self.start()
        except Exception:
            self._settings = old
            raise

    # ------------------------------------------------------------------
    # Rebinding
    # ------------------------------------------------------------------

    def rebind(self, new_api: ProtoPokeAPI) -> None:
        """
        Swap the API reference inside the running server.

        The FastMCP server and its HTTP listener keep running; only the
        closure cell holding the API pointer is updated. AI clients do not
        need to reconnect.

        If the server is not running, this simply updates the provider so
        the new API is used the next time :meth:`start` is called.
        """
        self._current_api = new_api
        if self._server is None:
            # Not running: update the stashed provider so a later start() picks
            # up the new API.
            self._initial_provider = new_api
            return

        rebind_fn = getattr(self._server, "_protopoke_rebind", None)
        if rebind_fn is None:
            logger.warning(
                "MCPHost.rebind: server has no _protopoke_rebind hook; "
                "API reference not updated",
            )
            return
        rebind_fn(new_api)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _run_server(self) -> None:
        try:
            await self._uvicorn.serve()
        except asyncio.CancelledError:
            raise
        except (SystemExit, Exception):
            # uvicorn calls ``sys.exit(1)`` when it cannot bind its listening
            # socket (e.g. the port is still in use). That raises ``SystemExit``,
            # which is a ``BaseException`` — if it escaped this task it would
            # tear down the whole host application with no traceback or message.
            # Log it and let the task finish instead, leaving MCP simply not
            # running.
            logger.exception("MCP server task crashed")

    def _resolve_api(self) -> ProtoPokeAPI:
        p = self._initial_provider
        if isinstance(p, ProtoPokeAPI):
            return p
        if callable(p):
            resolved = p()
            if not isinstance(resolved, ProtoPokeAPI):
                raise TypeError(
                    f"api_provider returned {type(resolved).__name__}, "
                    f"expected ProtoPokeAPI"
                )
            return resolved
        raise TypeError(
            f"api_provider must be a ProtoPokeAPI instance or a callable "
            f"returning one; got {type(p).__name__}"
        )
