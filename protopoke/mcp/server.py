"""FastMCP server wrapping ProxyAPI.

All tools return JSON-serialisable dicts.  Bytes fields are hex-encoded strings.
Tools are grouped by concern:

    Proxy lifecycle         : proxy_status, proxy_start, proxy_stop
    Session management      : list_sessions, get_session, get_frames, decode_frames
    Interception control    : intercept_status, intercept_toggle,
                              list_intercepted, intercept_forward, intercept_drop,
                              intercept_modify_and_forward
    Replace rules           : list_replace_rules, add_replace_rule, remove_replace_rule
    Intercept rules         : list_intercept_rules, add_intercept_rule, remove_intercept_rule
    Repeater / send         : send_frame
    Replay                  : replay_session
    Config                  : get_config, set_config
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def build_mcp_server(api: "ProxyAPI", name: str = "ProtoPoke") -> "FastMCP":  # type: ignore[name-defined]
    """
    Construct and return a FastMCP server bound to *api*.

    Args:
        api:  A :class:`~protopoke.api.ProxyAPI` instance.  The server does
              **not** call ``start()`` — the caller is responsible for lifecycle.
        name: Human-readable name for the MCP server (shown to AI clients).

    Returns:
        A configured :class:`mcp.server.fastmcp.FastMCP` instance.
        Call ``mcp.run()`` (synchronous) or ``await mcp.run_async()`` to serve.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise ImportError(
            "The 'mcp' package is required for MCP support. "
            "Install it with: pip install mcp"
        ) from exc

    from protopoke.models import Direction
    from protopoke.rules.rule import ReplaceRule, InterceptRule, RuleAction

    mcp = FastMCP(name)

    # ------------------------------------------------------------------ #
    # Proxy lifecycle                                                       #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def proxy_status() -> dict:
        """Return current proxy status: running state, config summary, counts."""
        sessions = api.list_sessions()
        active = api.list_active_sessions()
        return {
            "running": api.engine.is_running if hasattr(api.engine, "is_running") else None,
            "intercept_enabled": api.intercept_enabled,
            "pending_intercept_count": api.pending_count(),
            "total_sessions": len(sessions),
            "active_sessions": len(active),
            "listen": f"{api.config.listen_host}:{api.config.listen_port}",
            "upstream": f"{api.config.upstream_host}:{api.config.upstream_port}",
            "framer": api.config.framer_name,
        }

    @mcp.tool()
    async def proxy_start() -> dict:
        """Start the proxy listener. No-op if already running."""
        try:
            await api.start()
            return {"ok": True, "message": "Proxy started"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    async def proxy_stop() -> dict:
        """Stop the proxy and release all resources."""
        try:
            await api.stop()
            return {"ok": True, "message": "Proxy stopped"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ------------------------------------------------------------------ #
    # Session management                                                    #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def list_sessions() -> list[dict]:
        """List all captured sessions (active and closed)."""
        return [s.info.to_dict() for s in api.list_sessions()]

    @mcp.tool()
    def get_session(session_id: str) -> Optional[dict]:
        """
        Get details for a specific session.

        Args:
            session_id: The session UUID to look up.

        Returns:
            Session info dict, or None if not found.
        """
        session = api.get_session(session_id)
        if session is None:
            return None
        return session.info.to_dict()

    @mcp.tool()
    def get_frames(session_id: str, direction: Optional[str] = None) -> list[dict]:
        """
        Get captured frames for a session.

        Args:
            session_id: Session UUID.
            direction:  Optional filter — "client_to_server" or "server_to_client".

        Returns:
            List of frame dicts with raw_bytes as hex strings.
        """
        dir_enum = None
        if direction is not None:
            try:
                dir_enum = Direction(direction)
            except ValueError:
                return [{"error": f"Invalid direction '{direction}'. Use 'client_to_server' or 'server_to_client'."}]
        frames = api.get_frames(session_id, dir_enum)
        return [f.to_dict() for f in frames]

    @mcp.tool()
    def decode_frames(session_id: str, direction: Optional[str] = None) -> list[dict]:
        """
        Decode frames for a session using the attached protocol decoder.

        Args:
            session_id: Session UUID.
            direction:  Optional filter — "client_to_server" or "server_to_client".

        Returns:
            List of ParsedMessage dicts with structured fields.
        """
        dir_enum = None
        if direction is not None:
            try:
                dir_enum = Direction(direction)
            except ValueError:
                return [{"error": f"Invalid direction '{direction}'."}]
        messages = api.decode_session_frames(session_id, dir_enum)
        return [m.to_dict() for m in messages]

    # ------------------------------------------------------------------ #
    # Interception control                                                  #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def intercept_status() -> dict:
        """Return interception state: enabled flag and pending queue size."""
        return {
            "intercept_enabled": api.intercept_enabled,
            "pending_count": api.pending_count(),
            "direction_filter": (
                api.intercept_direction_filter.value
                if api.intercept_direction_filter is not None
                else None
            ),
            "session_filter": (
                list(api.intercept_session_filter)
                if api.intercept_session_filter is not None
                else None
            ),
        }

    @mcp.tool()
    def intercept_toggle(enabled: bool) -> dict:
        """
        Enable or disable interception at runtime.

        Args:
            enabled: True to enable, False to disable (forward all pending frames).
        """
        api.intercept_enabled = enabled
        return {"intercept_enabled": api.intercept_enabled}

    @mcp.tool()
    def list_intercepted() -> list[dict]:
        """
        Return all frames currently waiting in the intercept queue.

        Each entry includes the frame's raw bytes as a hex string and the
        unit ID needed to forward/drop/modify it.
        """
        return [u.to_dict() for u in api.list_intercepted()]

    @mcp.tool()
    def intercept_forward(unit_id: str) -> dict:
        """
        Forward an intercepted frame as-is.

        Args:
            unit_id: The intercepted unit ID (from list_intercepted).
        """
        ok = api.forward(unit_id)
        return {"ok": ok, "unit_id": unit_id}

    @mcp.tool()
    def intercept_drop(unit_id: str) -> dict:
        """
        Drop an intercepted frame (do not forward it to the peer).

        Args:
            unit_id: The intercepted unit ID (from list_intercepted).
        """
        ok = api.drop(unit_id)
        return {"ok": ok, "unit_id": unit_id}

    @mcp.tool()
    def intercept_modify_and_forward(unit_id: str, new_bytes_hex: str) -> dict:
        """
        Replace an intercepted frame's payload and forward it.

        Args:
            unit_id:       The intercepted unit ID (from list_intercepted).
            new_bytes_hex: Replacement bytes as a hex string (e.g. "deadbeef").
        """
        try:
            new_data = bytes.fromhex(new_bytes_hex)
        except ValueError as exc:
            return {"ok": False, "error": f"Invalid hex: {exc}"}
        ok = api.modify_and_forward(unit_id, new_data)
        return {"ok": ok, "unit_id": unit_id}

    @mcp.tool()
    def intercept_forward_all() -> dict:
        """Forward all currently pending intercepted frames."""
        count = api.forward_all()
        return {"forwarded": count}

    @mcp.tool()
    def intercept_set_direction_filter(direction: Optional[str]) -> dict:
        """
        Restrict interception to one traffic direction.

        Args:
            direction: "client_to_server", "server_to_client", or null to clear.
        """
        if direction is None:
            api.intercept_direction_filter = None
            return {"direction_filter": None}
        try:
            api.intercept_direction_filter = Direction(direction)
            return {"direction_filter": direction}
        except ValueError as exc:
            return {"error": str(exc)}

    @mcp.tool()
    def intercept_set_session_filter(session_ids: Optional[list[str]]) -> dict:
        """
        Restrict interception to specific sessions.

        Args:
            session_ids: List of session UUIDs to intercept, or null to clear.
        """
        if session_ids is None:
            api.intercept_session_filter = None
            return {"session_filter": None}
        api.intercept_session_filter = set(session_ids)
        return {"session_filter": session_ids}

    # ------------------------------------------------------------------ #
    # Replace rules                                                         #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def list_replace_rules() -> list[dict]:
        """List all active replace rules in order."""
        return [r.to_dict() for r in api.list_replace_rules()]

    @mcp.tool()
    def add_replace_rule(
        label:            str,
        pattern:          str,
        replacement_hex:  str,
        direction:        Optional[str] = None,
        enabled:          bool          = True,
    ) -> dict:
        """
        Add a binary replace rule.

        Args:
            label:           Human-readable name.
            pattern:         Binary pattern string, e.g. "01 02 ??" or "[00-0F]".
            replacement_hex: Replacement bytes as hex string.
            direction:       Optional "client_to_server" or "server_to_client".
            enabled:         Whether the rule is active immediately.

        Returns:
            The new rule dict including its generated ID.
        """
        try:
            replacement = bytes.fromhex(replacement_hex)
        except ValueError as exc:
            return {"ok": False, "error": f"Invalid replacement hex: {exc}"}

        dir_enum = None
        if direction is not None:
            try:
                dir_enum = Direction(direction)
            except ValueError as exc:
                return {"ok": False, "error": str(exc)}

        try:
            rule = ReplaceRule.create(label, pattern, replacement, direction=dir_enum, enabled=enabled)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

        api.add_replace_rule(rule)
        return {"ok": True, "rule": rule.to_dict()}

    @mcp.tool()
    def remove_replace_rule(rule_id: str) -> dict:
        """
        Remove a replace rule by its ID.

        Args:
            rule_id: Rule UUID from list_replace_rules.
        """
        ok = api.remove_replace_rule(rule_id)
        return {"ok": ok, "rule_id": rule_id}

    # ------------------------------------------------------------------ #
    # Intercept rules                                                       #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def list_intercept_rules() -> list[dict]:
        """List all active intercept filter rules in order."""
        return [r.to_dict() for r in api.list_intercept_rules()]

    @mcp.tool()
    def add_intercept_rule(
        label:      str,
        pattern:    str,
        action:     str,
        direction:  Optional[str]       = None,
        session_ids: Optional[list[str]] = None,
        enabled:    bool                = True,
    ) -> dict:
        """
        Add an intercept filter rule.

        Args:
            label:       Human-readable name.
            pattern:     Binary pattern string (empty = match all).
            action:      "intercept" or "forward".
            direction:   Optional "client_to_server" or "server_to_client".
            session_ids: Optional list of session UUIDs this rule applies to.
            enabled:     Whether the rule is active immediately.

        Returns:
            The new rule dict including its generated ID.
        """
        try:
            action_enum = RuleAction(action)
        except ValueError:
            return {"ok": False, "error": f"Invalid action '{action}'. Use 'intercept' or 'forward'."}

        dir_enum = None
        if direction is not None:
            try:
                dir_enum = Direction(direction)
            except ValueError as exc:
                return {"ok": False, "error": str(exc)}

        sids = set(session_ids) if session_ids else None

        try:
            rule = InterceptRule.create(
                label, pattern, action_enum,
                direction=dir_enum,
                session_ids=sids,
                enabled=enabled,
            )
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

        api.add_intercept_rule(rule)
        return {"ok": True, "rule": rule.to_dict()}

    @mcp.tool()
    def remove_intercept_rule(rule_id: str) -> dict:
        """
        Remove an intercept filter rule by its ID.

        Args:
            rule_id: Rule UUID from list_intercept_rules.
        """
        ok = api.remove_intercept_rule(rule_id)
        return {"ok": ok, "rule_id": rule_id}

    # ------------------------------------------------------------------ #
    # Repeater / direct send                                                #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    async def send_frame(
        data_hex:        str,
        host:            str,
        port:            int,
        tls:             bool           = False,
        connect_timeout: Optional[float] = None,
    ) -> dict:
        """
        Send raw bytes directly to host:port and return the response.

        Opens a direct TCP connection (bypassing the proxy listener), sends the
        bytes, reads the response, and closes the connection.

        Args:
            data_hex:        Bytes to send as a hex string (e.g. "deadbeef01").
            host:            Target hostname or IP address.
            port:            Target TCP port.
            tls:             Wrap the connection in TLS (no cert verification).
            connect_timeout: Optional override for the default connect timeout.

        Returns:
            SendRecord dict: sent_bytes_hex, received_bytes_hex, success, error.
        """
        try:
            data = bytes.fromhex(data_hex)
        except ValueError as exc:
            return {"ok": False, "error": f"Invalid data hex: {exc}"}

        record = await api.send_frame(
            data=data,
            host=host,
            port=port,
            tls=tls,
            connect_timeout=connect_timeout,
        )
        return record.to_dict()

    # ------------------------------------------------------------------ #
    # Replay                                                                #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    async def replay_session(
        session_id:     str,
        server_host:    Optional[str]  = None,
        server_port:    Optional[int]  = None,
        frame_delay:    float          = 0.0,
        direction:      str            = "client_to_server",
        frame_selector: Optional[str]  = None,
    ) -> dict:
        """
        Replay a captured session against the upstream server.

        Args:
            session_id:     Session UUID to replay.
            server_host:    Override target host (default: original server host).
            server_port:    Override target port (default: original server port).
            frame_delay:    Seconds to wait between sending each frame.
            direction:      Which direction to replay: "client_to_server" (default)
                            or "server_to_client".
            frame_selector: Comma/range selector for specific frames, e.g.
                            "0,2,4-6" or "3". None means all frames.

        Returns:
            ReplayResult dict with replayed_session_id, success, frame counts, etc.
        """
        try:
            dir_enum = Direction(direction)
        except ValueError:
            return {"ok": False, "error": f"Invalid direction '{direction}'."}

        result = await api.replay_session(
            session_id=session_id,
            server_host=server_host,
            server_port=server_port,
            frame_delay=frame_delay,
            direction=dir_enum,
            frame_selector=frame_selector,
        )
        return result.to_dict()

    # ------------------------------------------------------------------ #
    # Config                                                                #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def get_config() -> dict:
        """Return the current ProxyConfig as a JSON-serialisable dict."""
        return api.config.to_dict()

    @mcp.tool()
    def set_config(
        listen_host:     Optional[str]  = None,
        listen_port:     Optional[int]  = None,
        upstream_host:   Optional[str]  = None,
        upstream_port:   Optional[int]  = None,
        tls_listen:      Optional[bool] = None,
        tls_upstream:    Optional[bool] = None,
        intercept_enabled: Optional[bool] = None,
        framer_name:     Optional[str]  = None,
    ) -> dict:
        """
        Update one or more ProxyConfig fields.

        Only the provided (non-null) fields are changed; all others keep their
        current values.  Changes take effect for new connections; existing
        connections are not affected.

        Args:
            listen_host:       Bind address for the proxy listener.
            listen_port:       Port for the proxy listener.
            upstream_host:     Default upstream host to forward to.
            upstream_port:     Default upstream port to forward to.
            tls_listen:        Terminate TLS on the listening side.
            tls_upstream:      Use TLS when connecting upstream.
            intercept_enabled: Master intercept on/off switch in config.
            framer_name:       Framer to use: "raw", "line", "delimiter", etc.

        Returns:
            The updated config dict.
        """
        if listen_host     is not None: api.config.listen_host       = listen_host
        if listen_port     is not None: api.config.listen_port       = listen_port
        if upstream_host   is not None: api.config.upstream_host     = upstream_host
        if upstream_port   is not None: api.config.upstream_port     = upstream_port
        if tls_listen      is not None: api.config.tls_listen        = tls_listen
        if tls_upstream    is not None: api.config.tls_upstream      = tls_upstream
        if intercept_enabled is not None: api.config.intercept_enabled = intercept_enabled
        if framer_name     is not None: api.config.framer_name       = framer_name

        return api.config.to_dict()

    return mcp
