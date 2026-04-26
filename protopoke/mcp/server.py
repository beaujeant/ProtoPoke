"""FastMCP server wrapping ProxyAPI.

All tools return JSON-serialisable dicts.  Bytes fields are hex-encoded strings.
Tools are grouped by concern:

    Proxy lifecycle         : proxy_status, proxy_start, proxy_stop
    Forwarder management    : list_forwarders, start_forwarder, stop_forwarder,
                              update_forwarder_config
    Session management      : list_sessions, get_session, get_frames,
                              get_frame, get_session_summary, decode_frames,
                              decode_frame_by_id, search_frames,
                              terminate_session, delete_session, export_session
    Protocol management     : set_protocol_file, set_protocol_dict,
                              get_protocol_info
    Tamper control          : tamper_status, tamper_toggle,
                              list_intercepted, tamper_decode_pending,
                              tamper_forward, tamper_drop,
                              tamper_modify_and_forward,
                              tamper_modify_field_and_forward,
                              tamper_forward_all,
                              tamper_set_direction_filter,
                              tamper_set_session_filter
    Global replace rules    : list_replace_rules, add_replace_rule,
                              update_replace_rule, remove_replace_rule,
                              reorder_replace_rule, clear_replace_rules
    Intercept rules         : list_intercept_rules, add_intercept_rule,
                              update_intercept_rule, remove_intercept_rule,
                              reorder_intercept_rule, clear_intercept_rules
    Forge / direct send     : send_frame, open_forge_session,
                              send_on_forge_session,
                              inject_to_server, inject_to_client
    Playbook management     : list_playbooks, create_playbook, get_playbook,
                              update_playbook, delete_playbook,
                              run_playbook, frame_to_forge
    Replay                  : forge_session, replay_with_field_edits
    Framing                 : set_framer
    Variables               : get_variables, set_variable, clear_variables
    TLS / CA                : get_ca_cert
    Fuzzing                 : fuzz_start, fuzz_status, fuzz_results,
                              fuzz_stop, list_campaigns
    Config                  : get_config, set_config
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def build_mcp_server(api: "ProtoPokeAPI", name: str = "ProtoPoke") -> "FastMCP":  # type: ignore[name-defined]
    """
    Construct and return a FastMCP server bound to *api*.

    The bound API is held in a closure cell so it can be swapped without
    tearing down the server. The returned server exposes a
    ``_protopoke_rebind(new_api)`` attribute that callers (typically
    :class:`~protopoke.mcp.host.MCPHost`) invoke when the UI rebuilds the
    underlying :class:`~protopoke.api.ProtoPokeAPI` (e.g. after a project
    reload). Every tool closure reads the current ``api`` from the enclosing
    scope, so rebinding is a one-line pointer swap and AI clients do not have
    to reconnect.

    Args:
        api:  A :class:`~protopoke.api.ProtoPokeAPI` instance.  The server does
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
    from protopoke.forge.models import Playbook, PlaybookFrame, PlaybookRun, TrafficEntry

    def _rebind(new_api: "ProtoPokeAPI") -> None:
        """Swap the api bound to all tool closures. Called by MCPHost."""
        nonlocal api
        api = new_api

    mcp = FastMCP(name)

    # In-memory playbook store (MCP-side, mirrors UI Forge tab)
    _playbooks: dict[str, Playbook] = {}

    # ------------------------------------------------------------------ #
    # Proxy lifecycle                                                       #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def proxy_status() -> dict:
        """Return current proxy status: running state, config summary, counts."""
        sessions = api.list_sessions()
        active = api.list_active_sessions()
        running = api.list_running()
        cfg = api.config
        return {
            "running": bool(running),
            "running_forwarders": running,
            "tamper_enabled": api.tamper_enabled,
            "pending_tamper_count": api.pending_count(),
            "total_sessions": len(sessions),
            "active_sessions": len(active),
            "listen": f"{cfg.listen_host}:{cfg.listen_port}",
            "upstream": f"{cfg.upstream_host}:{cfg.upstream_port}",
            "framer": cfg.framer_name,
            "tls_listen": cfg.tls_listen,
            "tls_upstream": cfg.tls_upstream,
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
    # Forwarder management                                                  #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def list_forwarders() -> list[dict]:
        """
        List all configured forwarders with their running state and config.

        Each forwarder entry includes its name, enabled flag, running state,
        and full ProxyConfig.  Useful when multiple forwarders are configured
        (e.g. separate listeners for different protocols or ports).

        Returns:
            List of forwarder dicts with keys: name, enabled, running, config.
        """
        running = set(api.list_running())
        result = []
        for fwd in api.forwarders:
            result.append({
                "name":    fwd.name,
                "enabled": fwd.enabled,
                "running": fwd.name in running,
                "config":  fwd.config.to_dict(),
            })
        return result

    @mcp.tool()
    async def start_forwarder(name: str) -> dict:
        """
        Start a specific named forwarder.

        Use list_forwarders() to get the available forwarder names.
        The protocol definition (if configured) is auto-loaded on start.

        Args:
            name: Forwarder name from list_forwarders.

        Returns:
            {"ok": True} on success, {"ok": False, "error": ...} on failure.
        """
        try:
            await api.start_forwarder(name)
            return {"ok": True, "name": name}
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    async def stop_forwarder(name: str) -> dict:
        """
        Stop a specific named forwarder without affecting others.

        Existing sessions on this forwarder are closed; their frames remain
        in the session registry for inspection.

        Args:
            name: Forwarder name from list_forwarders.

        Returns:
            {"ok": True} on success, {"ok": False, "error": ...} on failure.
        """
        try:
            await api.stop_forwarder(name)
            return {"ok": True, "name": name}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ------------------------------------------------------------------ #
    # Session management                                                    #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def list_sessions() -> list[dict]:
        """
        List all captured sessions (active and closed).

        Returns session metadata: id, client/server host:port, state, timestamps.
        Use get_frames() to retrieve the actual communication data.
        """
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
    def get_session_summary(session_id: str) -> Optional[dict]:
        """
        Get a comprehensive summary for a session, including frame counts,
        byte totals per direction, duration, and per-direction breakdown.

        Args:
            session_id: The session UUID to summarise.

        Returns:
            Summary dict with stats, or None if session not found.
        """
        session = api.get_session(session_id)
        if session is None:
            return None

        info = session.info.to_dict()
        frames = session.frames

        client_frames = [f for f in frames if f.direction.value == "client_to_server"]
        server_frames = [f for f in frames if f.direction.value == "server_to_client"]

        client_bytes = sum(len(f.raw_bytes) for f in client_frames)
        server_bytes = sum(len(f.raw_bytes) for f in server_frames)

        duration: Optional[float] = None
        if info["closed_at"] is not None:
            duration = info["closed_at"] - info["created_at"]
        elif frames:
            duration = frames[-1].timestamp - info["created_at"]

        return {
            **info,
            "total_frames": len(frames),
            "client_to_server_frames": len(client_frames),
            "server_to_client_frames": len(server_frames),
            "client_to_server_bytes": client_bytes,
            "server_to_client_bytes": server_bytes,
            "total_bytes": client_bytes + server_bytes,
            "duration_seconds": duration,
            "first_frame_at": frames[0].timestamp if frames else None,
            "last_frame_at": frames[-1].timestamp if frames else None,
        }

    @mcp.tool()
    def get_frames(session_id: str, direction: Optional[str] = None) -> list[dict]:
        """
        Get all captured frames for a session, including raw bytes.

        Args:
            session_id: Session UUID.
            direction:  Optional filter — "client_to_server" or "server_to_client".

        Returns:
            List of frame dicts. raw_bytes is hex-encoded. Frames are in
            capture order with sequence numbers and timestamps.
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
    def get_frame(session_id: str, frame_id: str) -> Optional[dict]:
        """
        Get a single specific frame by its ID within a session.

        Args:
            session_id: Session UUID.
            frame_id:   Frame UUID to retrieve.

        Returns:
            Frame dict (raw_bytes as hex), or None if not found.
        """
        session = api.get_session(session_id)
        if session is None:
            return None
        for f in session.frames:
            if f.id == frame_id:
                return f.to_dict()
        return None

    @mcp.tool()
    def decode_frames(session_id: str, direction: Optional[str] = None) -> list[dict]:
        """
        Decode all frames for a session using the attached protocol decoder.

        Requires a protocol definition to be loaded via set_protocol_file().
        Returns passthrough (hex-only) results if no decoder is configured.

        Args:
            session_id: Session UUID.
            direction:  Optional filter — "client_to_server" or "server_to_client".

        Returns:
            List of ParsedMessage dicts with structured fields, message_type,
            and per-field offset/size metadata.
        """
        dir_enum = None
        if direction is not None:
            try:
                dir_enum = Direction(direction)
            except ValueError:
                return [{"error": f"Invalid direction '{direction}'."}]
        messages = api.decode_session_frames(session_id, dir_enum)
        return [m.to_dict() for m in messages]

    @mcp.tool()
    def decode_frame_by_id(session_id: str, frame_id: str) -> Optional[dict]:
        """
        Decode a single frame by its ID using the attached protocol decoder.

        Args:
            session_id: Session UUID.
            frame_id:   Frame UUID to decode.

        Returns:
            ParsedMessage dict with structured fields, or None if frame not found.
        """
        session = api.get_session(session_id)
        if session is None:
            return None
        for f in session.frames:
            if f.id == frame_id:
                return api.decode_frame(f).to_dict()
        return None

    @mcp.tool()
    def search_frames(
        pattern:    str,
        session_id: Optional[str] = None,
        direction:  Optional[str] = None,
        max_results: int = 100,
    ) -> list[dict]:
        """
        Search for a binary pattern across captured frames.

        Uses the same binary hex pattern syntax as rules:
          "01 02 ??"  — literal bytes with a wildcard
          "FF [03-09]" — byte range
          "(01|02) 00" — alternation

        Args:
            pattern:     Binary hex pattern to search for.
            session_id:  Limit search to a specific session (None = all sessions).
            direction:   Limit to "client_to_server" or "server_to_client" (None = both).
            max_results: Maximum number of matching frames to return (default 100).

        Returns:
            List of frame dicts for all frames that match the pattern.
        """
        import re as _re
        from protopoke.rules.rule import compile_binary_pattern, PatternError

        try:
            compiled = compile_binary_pattern(pattern)
        except PatternError as exc:
            return [{"error": f"Invalid pattern: {exc}"}]

        dir_enum = None
        if direction is not None:
            try:
                dir_enum = Direction(direction)
            except ValueError:
                return [{"error": f"Invalid direction '{direction}'."}]

        sessions = (
            [api.get_session(session_id)]
            if session_id
            else api.list_sessions()
        )

        results: list[dict] = []
        for session in sessions:
            if session is None:
                continue
            for frame in session.frames:
                if dir_enum is not None and frame.direction is not dir_enum:
                    continue
                if compiled.search(frame.raw_bytes):
                    results.append(frame.to_dict())
                    if len(results) >= max_results:
                        return results
        return results

    @mcp.tool()
    async def terminate_session(session_id: str) -> dict:
        """
        Forcefully close an active session's TCP connections.

        Cancels the relay task for the session, closing both the client and
        server TCP connections and marking the session CLOSED.  If the session
        is already closed (or not found) this is a no-op.

        Useful during reverse engineering to cleanly cut a session after
        capturing what you need, or to test server reconnect behaviour.

        Args:
            session_id: UUID of the session to terminate.

        Returns:
            {"ok": True} if terminated, {"ok": False} if already closed or not found.
        """
        ok = await api.terminate_session(session_id)
        return {"ok": ok, "session_id": session_id}

    @mcp.tool()
    def delete_session(session_id: str) -> dict:
        """
        Permanently remove a session and all its frames from the registry.

        This only removes the in-memory record; it does **not** close the
        underlying connection.  Call terminate_session() first if the session
        is still active.

        Useful for cleaning up uninteresting sessions to keep the view focused
        on the traffic that matters for reverse engineering.

        Args:
            session_id: UUID of the session to delete.

        Returns:
            {"ok": True} if deleted, {"ok": False} if not found.
        """
        ok = api.delete_session(session_id)
        return {"ok": ok, "session_id": session_id}

    @mcp.tool()
    def export_session(session_id: str) -> Optional[dict]:
        """
        Export a full session including all captured frames as a serialisable dict.

        Returns the complete session record (info + all frames with raw bytes
        as hex strings).  Useful for saving or transferring captured traffic
        for offline analysis or sharing with collaborators.

        Args:
            session_id: UUID of the session to export.

        Returns:
            Full session dict (info + frames), or None if not found.
        """
        session = api.get_session(session_id)
        if session is None:
            return None
        return api.session_to_dict(session)

    # ------------------------------------------------------------------ #
    # Protocol management                                                   #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def set_protocol_file(path: str) -> dict:
        """
        Load a protocol definition from a YAML or JSON file.

        Protocol definitions describe message types, fields, byte offsets,
        and data types so that frames can be decoded into structured fields
        (visible via decode_frames / decode_frame_by_id).

        Args:
            path: Path to a .yaml, .yml, or .json protocol definition file.

        Returns:
            {"ok": True, "protocol_name": "..."} on success.
        """
        try:
            api.set_protocol_file(path)
            return {"ok": True, "protocol_name": api._decoder.protocol_name}
        except FileNotFoundError as exc:
            return {"ok": False, "error": f"File not found: {exc}"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    def set_protocol_dict(definition: dict) -> dict:
        """
        Load a protocol definition from a dict (same schema as the YAML format).

        Useful for defining simple inline protocols without a file.

        Example definition::

            {
              "name": "MyProto",
              "messages": [
                {
                  "name": "Login",
                  "match": {"magic": "01 00"},
                  "fields": [
                    {"name": "msg_type", "type": "uint8"},
                    {"name": "username_len", "type": "uint8"},
                    {"name": "username", "type": "string", "length": "{username_len}"}
                  ]
                }
              ]
            }

        Args:
            definition: Protocol definition dict.

        Returns:
            {"ok": True, "protocol_name": "..."} on success.
        """
        try:
            api.set_protocol_dict(definition)
            return {"ok": True, "protocol_name": api._decoder.protocol_name}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    def get_protocol_info() -> dict:
        """
        Return information about the currently loaded protocol decoder.

        Returns:
            Dict with protocol_name and whether a decoder/encoder is active.
        """
        from protopoke.protocol.base import PassthroughDecoder
        decoder = api._decoder
        has_definition = not isinstance(decoder, PassthroughDecoder)
        return {
            "protocol_name": decoder.protocol_name,
            "has_definition": has_definition,
            "has_encoder": api._encoder is not None,
        }

    # ------------------------------------------------------------------ #
    # Tamper control                                                        #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def tamper_status() -> dict:
        """Return tamper state: enabled flag, pending queue size, and filters."""
        return {
            "tamper_enabled": api.tamper_enabled,
            "pending_count": api.pending_count(),
            "direction_filter": (
                api.tamper_direction_filter.value
                if api.tamper_direction_filter is not None
                else None
            ),
            "session_filter": (
                list(api.tamper_session_filter)
                if api.tamper_session_filter is not None
                else None
            ),
        }

    @mcp.tool()
    def tamper_toggle(enabled: bool) -> dict:
        """
        Enable or disable tamper at runtime.

        When disabled, all pending frames are immediately forwarded.
        When enabled, subsequent frames matching intercept rules are held.

        Args:
            enabled: True to enable, False to disable.
        """
        api.tamper_enabled = enabled
        return {"tamper_enabled": api.tamper_enabled}

    @mcp.tool()
    def list_intercepted() -> list[dict]:
        """
        Return all frames currently waiting in the tamper queue.

        Each entry includes the frame's raw bytes as a hex string, the unit
        ID needed to forward/drop/modify it, and the current action verdict.
        """
        return [u.to_dict() for u in api.list_intercepted()]

    @mcp.tool()
    def tamper_decode_pending() -> list[dict]:
        """
        Return all pending tampered frames with their protocol-decoded views.

        Like list_intercepted() but each entry also includes a ``parsed``
        field with the structured ParsedMessage for that frame. Requires a
        protocol definition to be loaded via set_protocol_file() for useful output.

        Returns:
            List of dicts, each with "unit" (TamperedUnit) and "parsed"
            (ParsedMessage) sub-dicts.
        """
        results = []
        for unit in api.list_intercepted():
            parsed = api.decode_frame(unit.frame)
            results.append({
                "unit": unit.to_dict(),
                "parsed": parsed.to_dict(),
            })
        return results

    @mcp.tool()
    def tamper_forward(unit_id: str) -> dict:
        """
        Forward a tampered frame as-is (no modifications).

        Args:
            unit_id: The tampered unit ID (from list_intercepted).
        """
        ok = api.forward(unit_id)
        return {"ok": ok, "unit_id": unit_id}

    @mcp.tool()
    def tamper_drop(unit_id: str) -> dict:
        """
        Drop a tampered frame (do not forward it to the peer).

        Args:
            unit_id: The tampered unit ID (from list_intercepted).
        """
        ok = api.drop(unit_id)
        return {"ok": ok, "unit_id": unit_id}

    @mcp.tool()
    def tamper_modify_and_forward(unit_id: str, new_bytes_hex: str) -> dict:
        """
        Replace a tampered frame's payload with raw bytes and forward it.

        Use this for raw binary edits. For protocol-aware field-level edits,
        use tamper_modify_field_and_forward() instead.

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
    def tamper_modify_field_and_forward(
        unit_id:     str,
        field_edits: dict[str, Any],
    ) -> dict:
        """
        Re-encode a tampered frame with protocol field edits, then forward it.

        Requires a protocol definition to be loaded via set_protocol_file().
        The frame is decoded, the specified fields are replaced, the message
        is re-encoded (with length fields automatically recomputed), and the
        result is forwarded.

        Args:
            unit_id:     The tampered unit ID (from list_intercepted).
            field_edits: Dict of field_name → new_value. Values are typed
                         according to the protocol definition (int, str, bytes-as-hex).

        Example::

            tamper_modify_field_and_forward(
                unit_id="abc-123",
                field_edits={"username": "admin", "msg_type": 2}
            )

        Returns:
            {"ok": True/False, "unit_id": ...}
        """
        ok = api.modify_field_and_forward(unit_id, field_edits)
        if not ok:
            # Check if it failed because no encoder is loaded
            if api._encoder is None:
                return {
                    "ok": False,
                    "unit_id": unit_id,
                    "error": "No protocol encoder loaded. Call set_protocol_file() first.",
                }
        return {"ok": ok, "unit_id": unit_id}

    @mcp.tool()
    def tamper_forward_all() -> dict:
        """Forward all currently pending tampered frames without modification."""
        count = api.forward_all()
        return {"forwarded": count}

    @mcp.tool()
    def tamper_set_direction_filter(direction: Optional[str]) -> dict:
        """
        Restrict tampering to one traffic direction.

        Args:
            direction: "client_to_server", "server_to_client", or null to clear.
        """
        if direction is None:
            api.tamper_direction_filter = None
            return {"direction_filter": None}
        try:
            api.tamper_direction_filter = Direction(direction)
            return {"direction_filter": direction}
        except ValueError as exc:
            return {"error": str(exc)}

    @mcp.tool()
    def tamper_set_session_filter(session_ids: Optional[list[str]]) -> dict:
        """
        Restrict tampering to specific sessions.

        Args:
            session_ids: List of session UUIDs to tamper, or null to clear.
        """
        if session_ids is None:
            api.tamper_session_filter = None
            return {"session_filter": None}
        api.tamper_session_filter = set(session_ids)
        return {"session_filter": session_ids}

    # ------------------------------------------------------------------ #
    # Replace rules                                                         #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def list_replace_rules() -> list[dict]:
        """List all active replace rules in order. Rules are applied sequentially."""
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
        Add a binary find-and-replace rule applied to all matching frames.

        Replace rules are applied to frame bytes automatically before forwarding.
        Multiple rules stack: the output of rule N becomes the input to rule N+1.

        Args:
            label:           Human-readable name.
            pattern:         Binary pattern string, e.g. "01 02 ??" or "[00-0F]".
            replacement_hex: Replacement bytes as hex string (e.g. "deadbeef").
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
    def update_replace_rule(
        rule_id: str,
        label:   Optional[str]  = None,
        enabled: Optional[bool] = None,
    ) -> dict:
        """
        Update a replace rule's label or enabled state.

        Use this to toggle a rule on/off without removing it, or to rename it.

        Args:
            rule_id: Rule UUID from list_replace_rules.
            label:   New human-readable name (or null to keep current).
            enabled: True to enable, False to disable (or null to keep current).

        Returns:
            Updated rule dict, or {"ok": False} if not found.
        """
        rule = api.rules_engine.get_rule(rule_id)
        if rule is None:
            return {"ok": False, "error": f"Rule '{rule_id}' not found."}
        if label is not None:
            rule.label = label
        if enabled is not None:
            rule.enabled = enabled
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

    @mcp.tool()
    def reorder_replace_rule(rule_id: str, new_index: int) -> dict:
        """
        Move a replace rule to a different position in the evaluation order.

        Rules are applied in order; position 0 is evaluated first.

        Args:
            rule_id:   Rule UUID from list_replace_rules.
            new_index: Zero-based target position (0 = top/first).

        Returns:
            {"ok": True} on success, or {"ok": False} if rule not found.
        """
        ok = api.rules_engine.move_rule(rule_id, new_index)
        return {"ok": ok, "rule_id": rule_id, "new_index": new_index}

    @mcp.tool()
    def clear_replace_rules() -> dict:
        """Remove all replace rules."""
        api.rules_engine.clear()
        return {"ok": True, "message": "All replace rules cleared."}

    # ------------------------------------------------------------------ #
    # Intercept rules                                                       #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def list_intercept_rules() -> list[dict]:
        """
        List all active intercept filter rules in order.

        Rules use first-match semantics: the first matching rule's action wins.
        When no rules are configured, all frames are intercepted.
        When rules are configured but none match, frames are auto-forwarded.
        """
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

        Intercept rules use first-match semantics and decide whether a frame
        is held for inspection or automatically forwarded.

        Args:
            label:       Human-readable name.
            pattern:     Binary pattern string (empty string = match all frames).
            action:      "intercept" (hold for review) or "forward" (auto-forward).
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
    def update_intercept_rule(
        rule_id: str,
        label:   Optional[str]  = None,
        action:  Optional[str]  = None,
        enabled: Optional[bool] = None,
    ) -> dict:
        """
        Update an intercept rule's label, action, or enabled state.

        Use this to flip a rule between intercept/forward, toggle it on/off,
        or rename it, without removing and re-adding it.

        Args:
            rule_id: Rule UUID from list_intercept_rules.
            label:   New name (or null to keep current).
            action:  "intercept" or "forward" (or null to keep current).
            enabled: True/False (or null to keep current).

        Returns:
            Updated rule dict, or {"ok": False} if not found.
        """
        rule = api.intercept_filter.get_rule(rule_id)
        if rule is None:
            return {"ok": False, "error": f"Rule '{rule_id}' not found."}
        if label is not None:
            rule.label = label
        if enabled is not None:
            rule.enabled = enabled
        if action is not None:
            try:
                rule.action = RuleAction(action)
            except ValueError:
                return {"ok": False, "error": f"Invalid action '{action}'. Use 'intercept' or 'forward'."}
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

    @mcp.tool()
    def reorder_intercept_rule(rule_id: str, new_index: int) -> dict:
        """
        Move an intercept rule to a different position in the evaluation order.

        Rules are evaluated top-to-bottom; the first match wins.
        Position 0 is evaluated first (highest priority).

        Args:
            rule_id:   Rule UUID from list_intercept_rules.
            new_index: Zero-based target position (0 = top/highest priority).

        Returns:
            {"ok": True} on success, or {"ok": False} if rule not found.
        """
        ok = api.intercept_filter.move_rule(rule_id, new_index)
        return {"ok": ok, "rule_id": rule_id, "new_index": new_index}

    @mcp.tool()
    def clear_intercept_rules() -> dict:
        """
        Remove all intercept filter rules.

        After clearing, the default behaviour resumes: all frames are intercepted
        (when tamper_enabled is True).
        """
        api.intercept_filter.clear()
        return {"ok": True, "message": "All intercept rules cleared."}

    # ------------------------------------------------------------------ #
    # Forge / direct send                                                   #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    async def send_frame(
        data_hex:        str,
        host:            str,
        port:            int,
        tls:             bool           = False,
        connect_timeout: Optional[float] = None,
        receive_timeout: Optional[float] = None,
    ) -> dict:
        """
        Send raw bytes directly to host:port and return the response.

        Opens a direct TCP connection (bypassing the proxy listener), sends
        the bytes, reads the response, and closes the connection. This is
        a one-shot send — for named reusable requests use the forge tools.

        Args:
            data_hex:        Bytes to send as a hex string (e.g. "deadbeef01").
            host:            Target hostname or IP address.
            port:            Target TCP port.
            tls:             Wrap the connection in TLS (no cert verification).
            connect_timeout: Optional override for the default connect timeout.
            receive_timeout: Seconds to wait for the server response before
                             returning bytes received so far.  Defaults to the
                             connect timeout.

        Returns:
            SendResult dict: sent_bytes_hex, received_bytes_hex, success, error.
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
            receive_timeout=receive_timeout,
        )
        return record.to_dict()

    @mcp.tool()
    async def open_forge_session(
        host: str,
        port: int,
        tls:  bool = False,
    ) -> dict:
        """
        Open a persistent TCP connection for interactive Forge sends.

        Unlike send_frame() which opens and closes a connection per send,
        this creates a named session that stays open so you can send multiple
        requests sequentially (e.g. to maintain authentication state or test
        multi-step protocols).

        The connection appears in the Traffic tab as a regular session so
        all frames sent and received are captured for analysis.

        Use send_on_forge_session() to send data through the returned session.
        The session is automatically marked CLOSED when the server drops it.

        Args:
            host: Target hostname or IP address.
            port: Target TCP port.
            tls:  Wrap the connection in TLS (no cert verification).

        Returns:
            {"ok": True, "session_id": "<uuid>"} on success.
        """
        try:
            session_id = await api.open_forge_session(host, port, tls)
            return {"ok": True, "session_id": session_id}
        except ConnectionError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    async def send_on_forge_session(
        session_id:      str,
        data_hex:        str,
        receive_timeout: Optional[float] = None,
    ) -> dict:
        """
        Send bytes through an existing persistent forge session.

        The session must have been opened with open_forge_session().
        All sent and received frames are captured in the session's frame log
        so they can be inspected with get_frames() / decode_frames().

        Args:
            session_id:      Session ID returned by open_forge_session.
            data_hex:        Bytes to send as a hex string (e.g. "deadbeef01").
            receive_timeout: Seconds to wait for a response.  Defaults to the
                             proxy's configured connect_timeout.

        Returns:
            SendResult dict: sent_bytes_hex, received_bytes_hex, response_packets,
            success, error.
        """
        try:
            data = bytes.fromhex(data_hex)
        except ValueError as exc:
            return {"ok": False, "error": f"Invalid data hex: {exc}"}

        try:
            result = await api.send_on_forge_session(
                session_id=session_id,
                data=data,
                receive_timeout=receive_timeout,
            )
            return result.to_dict()
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    async def inject_to_server(session_id: str, data_hex: str) -> dict:
        """
        Inject bytes directly into the upstream (server) side of an active session.

        The bytes are sent on the same TCP connection that the real client is
        using, so the server sees them as part of the established session.
        The server's response flows back through the relay to the original
        client and is captured as normal session frames.

        This is the primary tool for mid-session injection during reverse
        engineering: modify in-flight requests to test server behaviour without
        re-establishing the full connection.

        Args:
            session_id: UUID of an active (not closed) session.
            data_hex:   Bytes to inject as a hex string (e.g. "deadbeef").

        Returns:
            {"ok": True} on success, {"ok": False, "error": ...} if the session
            is not active or the write failed (use send_frame as fallback).
        """
        try:
            data = bytes.fromhex(data_hex)
        except ValueError as exc:
            return {"ok": False, "error": f"Invalid data hex: {exc}"}

        ok = await api.inject_to_server(session_id, data)
        return {"ok": ok, "session_id": session_id}

    @mcp.tool()
    async def inject_to_client(session_id: str, data_hex: str) -> dict:
        """
        Inject bytes directly into the client side of an active session.

        The bytes arrive on the same TCP connection the real server is using,
        so the client sees them as if they came from the server.  Useful for
        injecting server-to-client traffic to probe client-side parsing during
        reverse engineering.

        Args:
            session_id: UUID of an active (not closed) session.
            data_hex:   Bytes to inject as a hex string (e.g. "deadbeef").

        Returns:
            {"ok": True} on success, {"ok": False} if session is not active.
        """
        try:
            data = bytes.fromhex(data_hex)
        except ValueError as exc:
            return {"ok": False, "error": f"Invalid data hex: {exc}"}

        ok = await api.inject_to_client(session_id, data)
        return {"ok": ok, "session_id": session_id}

    # ------------------------------------------------------------------ #
    # Playbook management                                                #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def list_playbooks() -> list[dict]:
        """
        List all forge playbooks.

        Returns:
            List of playbook dicts (without full run history).
        """
        result = []
        for pb in _playbooks.values():
            d = pb.to_dict()
            d["run_count"] = len(pb.runs)
            d.pop("runs", None)
            result.append(d)
        return result

    @mcp.tool()
    def create_playbook(
        label:             str,
        host:              str,
        port:              int,
        data_hex:          str           = "",
        tls:               bool          = False,
        source_session_id: Optional[str] = None,
        response_window:   float         = 1.0,
    ) -> dict:
        """
        Create a new playbook with a single frame.

        Args:
            label:             Human-readable name.
            host:              Target hostname or IP address.
            port:              Target TCP port.
            data_hex:          Frame bytes as hex string.
            tls:               Whether to use TLS.
            source_session_id: Optional session ID to inject into.
            response_window:   Seconds to wait for server response per frame.

        Returns:
            The new playbook dict including its generated ID.
        """
        try:
            frame_bytes = bytes.fromhex(data_hex) if data_hex else b""
        except ValueError as exc:
            return {"ok": False, "error": f"Invalid data hex: {exc}"}

        pb = Playbook.create(
            label=label,
            host=host,
            port=port,
            tls=tls,
            source_session_id=source_session_id,
            response_window=response_window,
        )
        if frame_bytes:
            hex_str = " ".join(frame_bytes.hex()[i:i+2] for i in range(0, len(frame_bytes.hex()), 2))
            pb.frames.append(PlaybookFrame.create(label="frame-1", raw_hex=hex_str))
        _playbooks[pb.id] = pb
        return {"ok": True, "playbook": pb.to_dict()}

    @mcp.tool()
    def get_playbook(playbook_id: str) -> Optional[dict]:
        """
        Get a playbook including its full run history.

        Args:
            playbook_id: The playbook UUID from list_playbooks.

        Returns:
            Full playbook dict with runs, or None if not found.
        """
        pb = _playbooks.get(playbook_id)
        return pb.to_dict() if pb is not None else None

    @mcp.tool()
    def update_playbook(
        playbook_id: str,
        label:       Optional[str]  = None,
        host:        Optional[str]  = None,
        port:        Optional[int]  = None,
        tls:         Optional[bool] = None,
        data_hex:    Optional[str]  = None,
    ) -> dict:
        """
        Update a playbook's connection config and/or the first frame's bytes.

        Args:
            playbook_id: The playbook UUID.
            label:       New name (or null to keep current).
            host:        New target host (or null to keep current).
            port:        New target port (or null to keep current).
            tls:         New TLS setting (or null to keep current).
            data_hex:    New bytes for the first frame as hex (or null to keep current).

        Returns:
            Updated playbook dict, or {"ok": False} if not found.
        """
        pb = _playbooks.get(playbook_id)
        if pb is None:
            return {"ok": False, "error": f"Playbook '{playbook_id}' not found."}
        if label is not None: pb.label = label
        if host  is not None: pb.host  = host
        if port  is not None: pb.port  = port
        if tls   is not None: pb.tls   = tls
        if data_hex is not None:
            try:
                frame_bytes = bytes.fromhex(data_hex)
            except ValueError as exc:
                return {"ok": False, "error": f"Invalid data hex: {exc}"}
            hex_str = " ".join(frame_bytes.hex()[i:i+2] for i in range(0, len(frame_bytes.hex()), 2))
            if pb.frames:
                pb.frames[0].raw_hex = hex_str
            else:
                pb.frames.append(PlaybookFrame.create(label="frame-1", raw_hex=hex_str))
        return {"ok": True, "playbook": pb.to_dict()}

    @mcp.tool()
    def delete_playbook(playbook_id: str) -> dict:
        """
        Delete a playbook and its run history.

        Args:
            playbook_id: The playbook UUID to delete.
        """
        if playbook_id not in _playbooks:
            return {"ok": False, "error": f"Playbook '{playbook_id}' not found."}
        del _playbooks[playbook_id]
        return {"ok": True, "playbook_id": playbook_id}

    @mcp.tool()
    async def run_playbook(playbook_id: str) -> dict:
        """
        Execute all frames in a playbook and record the run.

        Args:
            playbook_id: The playbook UUID from list_playbooks.

        Returns:
            The PlaybookRun dict including all traffic entries.
        """
        pb = _playbooks.get(playbook_id)
        if pb is None:
            return {"ok": False, "error": f"Playbook '{playbook_id}' not found."}
        if not pb.frames:
            return {"ok": False, "error": "Playbook has no frames."}

        try:
            run = await api.run_playbook(pb)
            pb.runs.append(run)
            return {"ok": True, "run": run.to_dict()}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    def frame_to_forge(
        session_id: str,
        frame_id:   str,
        label:      Optional[str] = None,
    ) -> dict:
        """
        Create a playbook pre-loaded with a captured frame's bytes.

        This is the MCP equivalent of Ctrl+R "Send to Forge" in the UI.

        Args:
            session_id: Session UUID containing the frame.
            frame_id:   Frame UUID to load into the playbook.
            label:      Name for the new playbook (default: "From <session_id[:8]>").

        Returns:
            The new playbook dict.
        """
        session = api.get_session(session_id)
        if session is None:
            return {"ok": False, "error": f"Session '{session_id}' not found."}

        frame = next((f for f in session.frames if f.id == frame_id), None)
        if frame is None:
            return {"ok": False, "error": f"Frame '{frame_id}' not found in session."}

        from protopoke.models import Direction as _Dir
        direction = (
            "client_to_server"
            if frame.direction is _Dir.CLIENT_TO_SERVER
            else "server_to_client"
        )
        fwd_name = session.info.forwarder_name
        fwd = next((f for f in api.forwarders if f.name == fwd_name), None) if fwd_name else None
        tls_upstream = fwd.config.tls_upstream if fwd else api.config.tls_upstream
        pb = Playbook.create(
            label=label or f"From {session_id[:8]}",
            host=session.info.server_host,
            port=session.info.server_port,
            tls=tls_upstream,
            source_session_id=session_id if session.is_active() else None,
        )
        hex_str = " ".join(frame.raw_bytes.hex()[i:i+2] for i in range(0, len(frame.raw_bytes.hex()), 2))
        pb.frames.append(PlaybookFrame.create(label=f"frame-{frame.sequence_number}", raw_hex=hex_str, direction=direction))
        _playbooks[pb.id] = pb
        return {"ok": True, "playbook": pb.to_dict()}

    # ------------------------------------------------------------------ #
    # Replay                                                                #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    async def forge_session(
        session_id:     str,
        server_host:    Optional[str]  = None,
        server_port:    Optional[int]  = None,
        frame_delay:    float          = 0.0,
        direction:      str            = "client_to_server",
        frame_selector: Optional[str]  = None,
    ) -> dict:
        """
        Replay a captured session against the upstream server.

        Replays the captured frames (in the selected direction) to the server.
        Useful for reproducing observed traffic, regression testing, or fuzzing.

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
            ForgeResult dict with replayed_session_id, success, frame counts, etc.
        """
        try:
            dir_enum = Direction(direction)
        except ValueError:
            return {"ok": False, "error": f"Invalid direction '{direction}'."}

        result = await api.forge_session(
            session_id=session_id,
            server_host=server_host,
            server_port=server_port,
            frame_delay=frame_delay,
            direction=dir_enum,
            frame_selector=frame_selector,
        )
        return result.to_dict()

    @mcp.tool()
    async def replay_with_field_edits(
        session_id:     str,
        field_edits:    dict[str, dict[str, Any]],
        server_host:    Optional[str]  = None,
        server_port:    Optional[int]  = None,
        frame_delay:    float          = 0.0,
        direction:      str            = "client_to_server",
        frame_selector: Optional[str]  = None,
    ) -> dict:
        """
        Replay a captured session with protocol field-level edits applied.

        Requires a protocol definition to be loaded via set_protocol_file().
        Each message type can have specific fields overridden. The encoder
        automatically recomputes length fields after edits.

        Args:
            session_id:     Session UUID to replay.
            field_edits:    Dict of message_type_name → {field_name → new_value}.
                            Example:
                              {
                                "LoginRequest": {
                                  "username": "admin2",
                                  "session_token": 99
                                }
                              }
            server_host:    Override target host (default: original server host).
            server_port:    Override target port (default: original server port).
            frame_delay:    Seconds between frames.
            direction:      "client_to_server" (default) or "server_to_client".
            frame_selector: Selector string for specific frames (e.g. "0,2,4-6").

        Returns:
            ForgeResult dict. Falls back to original bytes for frames whose
            message type is not in field_edits or whose encoding fails.
        """
        if api._encoder is None:
            return {
                "ok": False,
                "error": (
                    "No protocol encoder loaded. "
                    "Call set_protocol_file() first to enable field-level replay."
                ),
            }

        try:
            dir_enum = Direction(direction)
        except ValueError:
            return {"ok": False, "error": f"Invalid direction '{direction}'."}

        try:
            result = await api.forge_session_with_field_edits(
                session_id=session_id,
                field_edits=field_edits,
                server_host=server_host,
                server_port=server_port,
                frame_delay=frame_delay,
                direction=dir_enum,
                frame_selector=frame_selector,
            )
        except RuntimeError as exc:
            return {"ok": False, "error": str(exc)}

        return result.to_dict()

    # ------------------------------------------------------------------ #
    # TLS / CA                                                              #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def get_ca_cert() -> dict:
        """
        Return the proxy's TLS CA certificate in PEM format.

        Install this certificate in your client application or OS trust store
        so that the client trusts the proxy's per-session certificates during
        TLS interception.

        Returns:
            {"pem": "<certificate PEM string>"} or an error if TLS is not
            configured or the CA has not been initialised.
        """
        ca = api.ca
        if ca is None:
            return {
                "ok": False,
                "error": (
                    "TLS CA not initialised. "
                    "Ensure tls_listen=True in config and start the proxy."
                ),
            }
        try:
            pem = ca.cert_pem.decode("utf-8")
            return {"ok": True, "pem": pem}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ------------------------------------------------------------------ #
    # Fuzzing                                                               #
    # ------------------------------------------------------------------ #

    # In-process campaign registry: campaign_id -> (FuzzCampaign, asyncio.Task | None)
    _campaigns: dict[str, tuple] = {}

    def _build_mutators(mutator_specs: list[dict]) -> tuple[list, Optional[str]]:
        """
        Instantiate FrameMutator objects from JSON-friendly spec dicts.

        Each spec must have a ``"name"`` key.  Additional keys are optional
        per-mutator parameters (see fuzz_start docstring for the full list).

        Returns ``(mutators, None)`` on success or ``([], error_message)`` on failure.
        """
        from protopoke.fuzzing.mutators import (
            BitFlipMutator,
            ByteDeleteMutator,
            ByteInsertMutator,
            ChainMutator,
            FieldBoundaryMutator,
            FieldOverflowMutator,
            KnownBadMutator,
            LengthMangleMutator,
            NullByteMutator,
            RadamsaMutator,
        )

        encoder = api._encoder
        mutators = []

        for spec in mutator_specs:
            name = spec.get("name", "")
            if name == "bit_flip":
                mutators.append(BitFlipMutator(count=spec.get("count", 1)))
            elif name == "byte_insert":
                mutators.append(ByteInsertMutator(count=spec.get("count", 4)))
            elif name == "byte_delete":
                mutators.append(ByteDeleteMutator(max_count=spec.get("max_count", 4)))
            elif name == "known_bad":
                mutators.append(KnownBadMutator())
            elif name == "radamsa":
                mutators.append(
                    RadamsaMutator(
                        radamsa_path=spec.get("radamsa_path", "radamsa"),
                        timeout=spec.get("timeout", 5.0),
                    )
                )
            elif name == "field_boundary":
                if encoder is None:
                    return [], "field_boundary requires a protocol definition to be loaded (set protocol_definition_path in config)"
                mutators.append(FieldBoundaryMutator(encoder))
            elif name == "field_overflow":
                if encoder is None:
                    return [], "field_overflow requires a protocol definition to be loaded"
                mutators.append(FieldOverflowMutator(encoder, lengths=spec.get("lengths", [256, 1024, 4096])))
            elif name == "null_byte":
                if encoder is None:
                    return [], "null_byte requires a protocol definition to be loaded"
                mutators.append(NullByteMutator(encoder))
            elif name == "length_mangle":
                if encoder is None:
                    return [], "length_mangle requires a protocol definition to be loaded"
                mutators.append(LengthMangleMutator(encoder))
            else:
                valid = "bit_flip, byte_insert, byte_delete, known_bad, radamsa, field_boundary, field_overflow, null_byte, length_mangle"
                return [], f"Unknown mutator '{name}'. Valid names: {valid}"

        return mutators, None

    @mcp.tool()
    async def fuzz_start(
        session_id:       str,
        mutators:         list[dict],
        iterations:       int           = 50,
        frame_selector:   Optional[str] = None,
        stop_on_crash:    bool          = True,
        server_host:      Optional[str] = None,
        server_port:      Optional[int] = None,
        response_timeout: float         = 10.0,
    ) -> dict:
        """
        Start a fuzzing campaign in the background and return immediately.

        Mutators are specified as a list of objects, each with a ``"name"`` field
        and optional parameters:

        - ``{"name": "bit_flip"}``                          — flip random bits
        - ``{"name": "bit_flip", "count": 4}``             — flip 4 bits per frame
        - ``{"name": "byte_insert"}``                       — insert random bytes
        - ``{"name": "byte_delete"}``                       — delete random bytes
        - ``{"name": "known_bad"}``                         — known-bad payloads (overflows, SQL, fmt strings)
        - ``{"name": "radamsa"}``                           — radamsa (must be on PATH)
        - ``{"name": "radamsa", "radamsa_path": "/path"}``  — radamsa at a custom path
        - ``{"name": "field_boundary"}``                    — integer boundary values (protocol-aware)
        - ``{"name": "field_overflow", "lengths": [256]}``  — string/bytes overflow (protocol-aware)
        - ``{"name": "null_byte"}``                         — null-byte injection (protocol-aware)
        - ``{"name": "length_mangle"}``                     — corrupt length fields (protocol-aware)

        Protocol-aware mutators (field_*) require a protocol definition to be loaded.

        The campaign runs as an asyncio background task.  Poll with
        ``fuzz_status`` and retrieve results with ``fuzz_results``.

        Args:
            session_id:       Template session UUID (must be a captured session).
            mutators:         List of mutator spec objects (see above).
            iterations:       Total number of mutations to send (default: 50).
            frame_selector:   Comma/range spec, e.g. ``"0,2-4"``. None = all frames.
            stop_on_crash:    Stop on first TCP connection reset.
            server_host:      Override target host (default: session's original server).
            server_port:      Override target port.
            response_timeout: Per-iteration read timeout in seconds.

        Returns:
            ``{"ok": true, "campaign_id": "<uuid>", "status": "running"}``
        """
        from protopoke.fuzzing.models import FuzzCampaign

        built, err = _build_mutators(mutators)
        if err:
            return {"ok": False, "error": err}
        if not built:
            return {"ok": False, "error": "No mutators specified."}

        campaign = FuzzCampaign.create(
            session_id=session_id,
            mutators=built,
            iterations=iterations,
            frame_selector=frame_selector,
            stop_on_crash=stop_on_crash,
        )

        engine = api._get_fuzzer_engine()
        engine._decoder = api._decoder

        task = asyncio.get_event_loop().create_task(
            engine.run_campaign(
                campaign=campaign,
                mutators=built,
                server_host=server_host,
                server_port=server_port,
                response_timeout=response_timeout,
            )
        )
        _campaigns[campaign.id] = (campaign, task)
        return {"ok": True, "campaign_id": campaign.id, "status": campaign.status.value}

    @mcp.tool()
    def fuzz_status(campaign_id: str) -> dict:
        """
        Return the current status and summary of a fuzzing campaign.

        Useful for polling a running campaign started with ``fuzz_start``.

        Args:
            campaign_id: Campaign UUID returned by ``fuzz_start``.

        Returns:
            Campaign summary dict (no per-result details; use ``fuzz_results`` for those).
        """
        entry = _campaigns.get(campaign_id)
        if entry is None:
            return {"ok": False, "error": f"Campaign '{campaign_id}' not found."}
        campaign, task = entry
        return {
            "ok":                     True,
            "id":                     campaign.id,
            "session_id":             campaign.session_id,
            "status":                 campaign.status.value,
            "mutator_names":          campaign.mutator_names,
            "iterations":             campaign.iterations,
            "completed_iterations":   campaign.completed_iterations,
            "interesting_count":      len(campaign.interesting_results),
            "crash_count":            len(campaign.crash_results),
            "baseline_response_size": campaign.baseline_response_size,
            "started_at":             campaign.started_at,
            "completed_at":           campaign.completed_at,
            "task_done":              task.done() if task else None,
        }

    @mcp.tool()
    def fuzz_results(campaign_id: str, interesting_only: bool = False) -> dict:
        """
        Return per-iteration results for a fuzzing campaign.

        Each result includes the mutated bytes (hex), response bytes (hex),
        response time, connection reset flag, timeout flag, and the
        ``interesting`` heuristic flag.

        Args:
            campaign_id:     Campaign UUID returned by ``fuzz_start``.
            interesting_only: If True, return only results flagged as interesting
                              (connection reset, timeout, or response size anomaly).

        Returns:
            ``{"ok": true, "id": "...", "status": "...", "results": [...]}``
        """
        entry = _campaigns.get(campaign_id)
        if entry is None:
            return {"ok": False, "error": f"Campaign '{campaign_id}' not found."}
        campaign, _ = entry
        results = campaign.interesting_results if interesting_only else campaign.results
        return {
            "ok":     True,
            "id":     campaign.id,
            "status": campaign.status.value,
            "results": [r.to_dict() for r in results],
        }

    @mcp.tool()
    def fuzz_stop(campaign_id: str) -> dict:
        """
        Request early termination of a running campaign.

        Sets the campaign's status to ``"stopped"``; the engine will finish
        the current iteration and then exit gracefully.  Has no effect if the
        campaign is already done or stopped.

        Args:
            campaign_id: Campaign UUID returned by ``fuzz_start``.

        Returns:
            ``{"ok": true, "status": "stopped"}``
        """
        entry = _campaigns.get(campaign_id)
        if entry is None:
            return {"ok": False, "error": f"Campaign '{campaign_id}' not found."}
        campaign, _ = entry
        from protopoke.fuzzing.models import CampaignStatus
        if campaign.status is CampaignStatus.RUNNING:
            campaign.status = CampaignStatus.STOPPED
        return {"ok": True, "status": campaign.status.value}

    @mcp.tool()
    def list_campaigns() -> list[dict]:
        """
        List all fuzzing campaigns (running and completed) with summary info.

        To retrieve per-iteration details call ``fuzz_results`` with the
        campaign ID.

        Returns:
            List of campaign summary dicts ordered by insertion time (oldest first).
        """
        return [
            {
                "id":                   c.id,
                "session_id":           c.session_id,
                "status":               c.status.value,
                "mutator_names":        c.mutator_names,
                "iterations":           c.iterations,
                "completed_iterations": c.completed_iterations,
                "interesting_count":    len(c.interesting_results),
                "crash_count":          len(c.crash_results),
                "started_at":           c.started_at,
                "completed_at":         c.completed_at,
            }
            for c, _ in _campaigns.values()
        ]

    # ------------------------------------------------------------------ #
    # Framing                                                               #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def set_framer(
        framer_name:        str,
        framer_kwargs:      Optional[dict] = None,
        custom_framer_path: Optional[str]  = None,
        forwarder_name:     Optional[str]  = None,
    ) -> dict:
        """
        Hot-swap the active framer on running sessions without restarting.

        The framer determines how the raw TCP byte stream is segmented into
        discrete frames for capture and display.  Choosing the right framer
        is often one of the first steps in reverse engineering an unknown
        binary protocol.

        Available built-in framers:
          - "raw"            — Each read() chunk = one frame. Use as a starting point.
          - "delimiter"      — Split on a byte sequence (e.g. \\r\\n for line protocols).
                               Requires framer_kwargs={"delimiter": "<hex>"}, where
                               the delimiter is provided as a hex string
                               (e.g. "0d0a" for CRLF).
          - "length_prefix"  — Fixed-size integer length header before each frame.
                               Requires framer_kwargs={"length_size": 2} (bytes).
                               Optional: {"byte_order": "big"} (default "big") and
                               {"includes_header": false} (default false).
          - "line"           — Split on \\r\\n or \\n (shorthand for delimiter framer).
          - "custom"         — Load a custom Framer subclass from a Python file.
                               Requires custom_framer_path.

        Args:
            framer_name:        Framer key (see above).
            framer_kwargs:      Extra options for the framer (see above).
                                Bytes values should be provided as hex strings.
            custom_framer_path: Path to a Python file with a custom Framer subclass.
                                Required when framer_name == "custom".
            forwarder_name:     If set, only update sessions on this forwarder.
                                None (default) = update all forwarders.

        Returns:
            {"ok": True, "swapped_sessions": <count>} — number of active sessions
            whose framer was hot-swapped.
        """
        kwargs: dict = {}
        if framer_kwargs:
            for k, v in framer_kwargs.items():
                if isinstance(v, str) and framer_name in ("delimiter",):
                    try:
                        kwargs[k] = bytes.fromhex(v)
                    except ValueError:
                        kwargs[k] = v
                else:
                    kwargs[k] = v

        try:
            count = api.set_framer(
                framer_name=framer_name,
                framer_kwargs=kwargs or None,
                custom_framer_path=custom_framer_path,
                forwarder_name=forwarder_name,
            )
            return {"ok": True, "framer_name": framer_name, "swapped_sessions": count}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    def update_forwarder_config(
        forwarder_name:          str,
        new_name:                Optional[str]  = None,
        framer_name:             Optional[str]  = None,
        framer_kwargs:           Optional[dict] = None,
        custom_framer_path:      Optional[str]  = None,
        protocol_definition_path: Optional[str] = None,
    ) -> dict:
        """
        Hot-swap name, framing, and/or protocol definition on a running
        forwarder without restarting it.

        This is the preferred way to change a forwarder's configuration
        while it is running.  Changes take effect immediately:

        - **Name**: the forwarder and all its existing sessions are
          relabelled.
        - **Framing**: the framer is swapped on every active session so
          new data is segmented with the updated strategy.
        - **Protocol definition**: the decoder/encoder are replaced so
          subsequent ``decode_frame()`` calls use the new definition.

        Args:
            forwarder_name:          Current name of the forwarder to update.
            new_name:                Rename the forwarder (must be unique).
            framer_name:             New framer key ("raw", "delimiter",
                                     "length_prefix", "line", or "custom").
            framer_kwargs:           Extra options for the framer. Byte values
                                     should be hex strings (e.g. "0d0a").
            custom_framer_path:      Path to a custom framer Python file
                                     (required when framer_name == "custom").
            protocol_definition_path: Path to a .yaml/.json protocol
                                     definition, or "" to clear.

        Returns:
            {"ok": True, "renamed": bool, "sessions_reframed": int,
             "protocol_set": bool}
        """
        kwargs: dict = {}
        if framer_kwargs:
            for k, v in framer_kwargs.items():
                if isinstance(v, str) and framer_name in ("delimiter",):
                    try:
                        kwargs[k] = bytes.fromhex(v)
                    except ValueError:
                        kwargs[k] = v
                else:
                    kwargs[k] = v

        try:
            result = api.update_forwarder_config(
                forwarder_name,
                new_name=new_name,
                framer_name=framer_name,
                framer_kwargs=kwargs or None,
                custom_framer_path=custom_framer_path,
                protocol_definition_path=protocol_definition_path,
            )
            return {"ok": True, **result}
        except KeyError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ------------------------------------------------------------------ #
    # Variables                                                             #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def get_variables() -> dict:
        """
        Return the global variable store used by replace rules and playbooks.

        Variables are hex-encoded byte strings (e.g. {"SEQ": "00000001"}).
        They can be read and written by script-type replace rules and are
        shared across all pipelines (intercept, forge, sequence/playbook).

        Useful during reverse engineering to track session state such as
        sequence numbers, session tokens, or checksums extracted from
        captured frames.

        Returns:
            Dict of variable_name → hex_value_string.
        """
        return dict(api.variables)

    @mcp.tool()
    def set_variable(name: str, value_hex: str) -> dict:
        """
        Set a variable in the global variable store.

        Variables are used as {{VAR}} placeholders in playbook frames and
        by script-type replace rules.  Setting a variable here updates it
        immediately for all subsequent forge/playbook sends.

        Args:
            name:      Variable name (case-sensitive, e.g. "SEQ" or "TOKEN").
            value_hex: Value as a hex string (e.g. "deadbeef" or "00000001").

        Returns:
            {"ok": True, "name": ..., "value_hex": ...}
        """
        try:
            bytes.fromhex(value_hex)
        except ValueError as exc:
            return {"ok": False, "error": f"Invalid hex value: {exc}"}
        api.variables[name] = value_hex
        return {"ok": True, "name": name, "value_hex": value_hex}

    @mcp.tool()
    def clear_variables() -> dict:
        """
        Clear all variables from the global variable store.

        Returns:
            {"ok": True, "cleared": <count>}
        """
        count = len(api.variables)
        api.variables.clear()
        return {"ok": True, "cleared": count}

    # ------------------------------------------------------------------ #
    # Config                                                                #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def get_config() -> dict:
        """Return the current ProxyConfig as a JSON-serialisable dict."""
        return api.config.to_dict()

    @mcp.tool()
    def set_config(
        listen_host:              Optional[str]   = None,
        listen_port:              Optional[int]   = None,
        upstream_host:            Optional[str]   = None,
        upstream_port:            Optional[int]   = None,
        tls_listen:               Optional[bool]  = None,
        tls_upstream:             Optional[bool]  = None,
        tamper_enabled:           Optional[bool]  = None,
        framer_name:              Optional[str]   = None,
        framer_kwargs:            Optional[dict]  = None,
        protocol_definition_path: Optional[str]   = None,
        connect_timeout:          Optional[float] = None,
        read_buffer_size:         Optional[int]   = None,
        max_sessions:             Optional[int]   = None,
    ) -> dict:
        """
        Update one or more ProxyConfig fields.

        Only the provided (non-null) fields are changed; all others keep their
        current values.  Changes to network/framing settings take effect for
        new connections; use set_framer() to hot-swap the framer on live sessions.

        Upstream TLS certificate verification is always disabled — this tool
        is for reverse engineering and accepts any certificate unconditionally.

        Args:
            listen_host:              Bind address for the proxy listener.
            listen_port:              Port for the proxy listener.
            upstream_host:            Default upstream host to forward to.
            upstream_port:            Default upstream port to forward to.
            tls_listen:               Terminate TLS on the listening side (MITM).
            tls_upstream:             Use TLS when connecting to upstream.
            tamper_enabled:           Master intercept on/off switch.
            framer_name:              Framer: "raw", "delimiter", "length_prefix", "line".
            framer_kwargs:            Extra options for the framer (e.g.
                                      {"delimiter": "0d0a"} — hex for delimiter framer,
                                      {"length_size": 4} for length_prefix framer).
                                      Byte values should be hex strings.
            protocol_definition_path: Path to a .yaml/.json protocol definition file.
            connect_timeout:          Seconds to wait when connecting upstream.
            read_buffer_size:         Bytes per read() call (affects relay wake-up rate).
            max_sessions:             Max concurrent sessions (0 = unlimited).

        Returns:
            The updated config dict.
        """
        cfg = api.config
        if listen_host              is not None: cfg.listen_host              = listen_host
        if listen_port              is not None: cfg.listen_port              = listen_port
        if upstream_host            is not None: cfg.upstream_host            = upstream_host
        if upstream_port            is not None: cfg.upstream_port            = upstream_port
        if tls_listen               is not None: cfg.tls_listen               = tls_listen
        if tls_upstream             is not None: cfg.tls_upstream             = tls_upstream
        if tamper_enabled           is not None: cfg.tamper_enabled           = tamper_enabled
        if framer_name              is not None: cfg.framer_name              = framer_name
        if connect_timeout          is not None: cfg.connect_timeout          = connect_timeout
        if read_buffer_size         is not None: cfg.read_buffer_size         = read_buffer_size
        if max_sessions             is not None: cfg.max_sessions             = max_sessions
        if protocol_definition_path is not None: cfg.protocol_definition_path = protocol_definition_path
        if framer_kwargs is not None:
            decoded: dict = {}
            for k, v in framer_kwargs.items():
                if isinstance(v, str):
                    try:
                        decoded[k] = bytes.fromhex(v)
                    except ValueError:
                        decoded[k] = v
                else:
                    decoded[k] = v
            cfg.framer_kwargs = decoded

        return cfg.to_dict()

    # Expose the rebind hook so MCPHost can swap the bound API without
    # tearing down the server task.
    mcp._protopoke_rebind = _rebind
    return mcp
