"""FastMCP server wrapping ProxyAPI.

All tools return JSON-serialisable dicts.  Bytes fields are hex-encoded strings.
Tools are grouped by concern:

    Proxy lifecycle         : proxy_status, proxy_start, proxy_stop
    Session management      : list_sessions, get_session, get_frames,
                              get_frame, get_session_summary, decode_frames,
                              decode_frame_by_id, search_frames
    Interception control    : intercept_status, intercept_toggle,
                              list_intercepted, intercept_forward, intercept_drop,
                              intercept_modify_and_forward
    Replace rules           : list_replace_rules, add_replace_rule, remove_replace_rule
    Intercept rules         : list_intercept_rules, add_intercept_rule, remove_intercept_rule
    Repeater / send         : send_frame
    Replay                  : forge_session
    Fuzzing                 : fuzz_start, fuzz_status, fuzz_results, fuzz_stop, list_campaigns
                              list_intercepted, intercept_decode_pending,
                              intercept_forward, intercept_drop,
                              intercept_modify_and_forward,
                              intercept_modify_field_and_forward,
                              intercept_forward_all,
                              intercept_set_direction_filter,
                              intercept_set_session_filter
    Replace rules           : list_replace_rules, add_replace_rule,
                              update_replace_rule, remove_replace_rule,
                              reorder_replace_rule, clear_replace_rules
    Intercept rules         : list_intercept_rules, add_intercept_rule,
                              update_intercept_rule, remove_intercept_rule,
                              reorder_intercept_rule, clear_intercept_rules
    Protocol management     : set_protocol_file, set_protocol_dict,
                              get_protocol_info
    Repeater / send         : send_frame, list_forge_requests,
                              create_forge_request, get_forge_request,
                              update_forge_request, delete_forge_request,
                              send_forge_request, frame_to_repeater
    Replay                  : forge_session, replay_with_field_edits
    TLS / CA                : get_ca_cert
    Config                  : get_config, set_config
"""

from __future__ import annotations

import asyncio
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
    from protopoke.rules.rule import ReplaceRule, TamperRule, RuleAction
    from protopoke.forge.models import ForgeRequest, ForgeRecord

    mcp = FastMCP(name)

    # In-memory repeater request store (MCP-side, mirrors UI repeater tabs)
    _forge_requests: dict[str, ForgeRequest] = {}

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
            "tamper_enabled": api.tamper_enabled,
            "pending_intercept_count": api.pending_count(),
            "total_sessions": len(sessions),
            "active_sessions": len(active),
            "listen": f"{api.config.listen_host}:{api.config.listen_port}",
            "upstream": f"{api.config.upstream_host}:{api.config.upstream_port}",
            "framer": api.config.framer_name,
            "tls_listen": api.config.tls_listen,
            "tls_upstream": api.config.tls_upstream,
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
    # Interception control                                                  #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def intercept_status() -> dict:
        """Return interception state: enabled flag, pending queue size, and filters."""
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
    def intercept_toggle(enabled: bool) -> dict:
        """
        Enable or disable interception at runtime.

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
        Return all frames currently waiting in the intercept queue.

        Each entry includes the frame's raw bytes as a hex string, the unit
        ID needed to forward/drop/modify it, and the current action verdict.
        """
        return [u.to_dict() for u in api.list_intercepted()]

    @mcp.tool()
    def intercept_decode_pending() -> list[dict]:
        """
        Return all pending intercepted frames with their protocol-decoded views.

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
    def intercept_forward(unit_id: str) -> dict:
        """
        Forward an intercepted frame as-is (no modifications).

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
        Replace an intercepted frame's payload with raw bytes and forward it.

        Use this for raw binary edits. For protocol-aware field-level edits,
        use intercept_modify_field_and_forward() instead.

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
    def intercept_modify_field_and_forward(
        unit_id:     str,
        field_edits: dict[str, Any],
    ) -> dict:
        """
        Re-encode an intercepted frame with protocol field edits, then forward it.

        Requires a protocol definition to be loaded via set_protocol_file().
        The frame is decoded, the specified fields are replaced, the message
        is re-encoded (with length fields automatically recomputed), and the
        result is forwarded.

        Args:
            unit_id:     The intercepted unit ID (from list_intercepted).
            field_edits: Dict of field_name → new_value. Values are typed
                         according to the protocol definition (int, str, bytes-as-hex).

        Example::

            intercept_modify_field_and_forward(
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
    def intercept_forward_all() -> dict:
        """Forward all currently pending intercepted frames without modification."""
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
            api.tamper_direction_filter = None
            return {"direction_filter": None}
        try:
            api.tamper_direction_filter = Direction(direction)
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
            rule = TamperRule.create(
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
        rule = api.tamper_filter.get_rule(rule_id)
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
        ok = api.tamper_filter.move_rule(rule_id, new_index)
        return {"ok": ok, "rule_id": rule_id, "new_index": new_index}

    @mcp.tool()
    def clear_intercept_rules() -> dict:
        """
        Remove all intercept filter rules.

        After clearing, the default behaviour resumes: all frames are intercepted
        (when tamper_enabled is True).
        """
        api.tamper_filter.clear()
        return {"ok": True, "message": "All intercept rules cleared."}

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
        receive_timeout: Optional[float] = None,
    ) -> dict:
        """
        Send raw bytes directly to host:port and return the response.

        Opens a direct TCP connection (bypassing the proxy listener), sends
        the bytes, reads the response, and closes the connection. This is
        a one-shot send — for named reusable requests use the repeater tools.

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
            ForgeRecord dict: sent_bytes_hex, received_bytes_hex, success, error.
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

    # ------------------------------------------------------------------ #
    # Repeater request management                                           #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def list_forge_requests() -> list[dict]:
        """
        List all repeater request tabs.

        Repeater requests are named, reusable send configurations — analogous
        to Burp Suite's Repeater tabs. Each has editable bytes, a target, and
        a history of sends.

        Returns:
            List of repeater request dicts (without full history).
        """
        result = []
        for req in _forge_requests.values():
            d = req.to_dict()
            d["history_count"] = len(req.history)
            d.pop("history", None)  # Omit full history from list view
            result.append(d)
        return result

    @mcp.tool()
    def create_forge_request(
        label:             str,
        host:              str,
        port:              int,
        data_hex:          str            = "",
        tls:               bool           = False,
        source_session_id: Optional[str]  = None,
    ) -> dict:
        """
        Create a new repeater request tab.

        Args:
            label:             Human-readable name for this request tab.
            host:              Target hostname or IP address.
            port:              Target TCP port.
            data_hex:          Initial bytes to send, as hex string.
            tls:               Whether to use TLS.
            source_session_id: Optional session ID to associate with this request.

        Returns:
            The new repeater request dict including its generated ID.
        """
        try:
            current_bytes = bytes.fromhex(data_hex) if data_hex else b""
        except ValueError as exc:
            return {"ok": False, "error": f"Invalid data hex: {exc}"}

        req = ForgeRequest.create(
            label=label,
            host=host,
            port=port,
            tls=tls,
            current_bytes=current_bytes,
            source_session_id=source_session_id,
        )
        _forge_requests[req.id] = req
        return {"ok": True, "request": req.to_dict()}

    @mcp.tool()
    def get_forge_request(request_id: str) -> Optional[dict]:
        """
        Get a repeater request tab, including its full send history.

        Args:
            request_id: The repeater request UUID from list_forge_requests.

        Returns:
            Full repeater request dict with history, or None if not found.
        """
        req = _forge_requests.get(request_id)
        if req is None:
            return None
        return req.to_dict()

    @mcp.tool()
    def update_forge_request(
        request_id: str,
        label:      Optional[str]  = None,
        host:       Optional[str]  = None,
        port:       Optional[int]  = None,
        data_hex:   Optional[str]  = None,
        tls:        Optional[bool] = None,
    ) -> dict:
        """
        Update a repeater request tab's settings or payload bytes.

        Args:
            request_id: The repeater request UUID.
            label:      New name (or null to keep current).
            host:       New target host (or null to keep current).
            port:       New target port (or null to keep current).
            data_hex:   New payload bytes as hex (or null to keep current).
            tls:        New TLS setting (or null to keep current).

        Returns:
            Updated request dict, or {"ok": False} if not found.
        """
        req = _forge_requests.get(request_id)
        if req is None:
            return {"ok": False, "error": f"Request '{request_id}' not found."}
        if label    is not None: req.label = label
        if host     is not None: req.host  = host
        if port     is not None: req.port  = port
        if tls      is not None: req.tls   = tls
        if data_hex is not None:
            try:
                req.current_bytes = bytes.fromhex(data_hex)
            except ValueError as exc:
                return {"ok": False, "error": f"Invalid data hex: {exc}"}
        return {"ok": True, "request": req.to_dict()}

    @mcp.tool()
    def delete_forge_request(request_id: str) -> dict:
        """
        Delete a repeater request tab and its history.

        Args:
            request_id: The repeater request UUID to delete.
        """
        if request_id not in _forge_requests:
            return {"ok": False, "error": f"Request '{request_id}' not found."}
        del _forge_requests[request_id]
        return {"ok": True, "request_id": request_id}

    @mcp.tool()
    async def send_forge_request(request_id: str) -> dict:
        """
        Send the current bytes of a repeater request to its target.

        Records the send+response in the request's history. Retrieve the
        full history via get_forge_request().

        Args:
            request_id: The repeater request UUID from list_forge_requests.

        Returns:
            The ForgeRecord dict for this send, including received bytes.
        """
        req = _forge_requests.get(request_id)
        if req is None:
            return {"ok": False, "error": f"Request '{request_id}' not found."}
        if not req.current_bytes:
            return {"ok": False, "error": "Request has no bytes to send. Update it via update_forge_request()."}

        record = await api.send_frame(
            data=req.current_bytes,
            host=req.host,
            port=req.port,
            tls=req.tls,
        )
        req.add_record(record)
        return {"ok": True, "record": record.to_dict()}

    @mcp.tool()
    def frame_to_repeater(
        session_id: str,
        frame_id:   str,
        label:      Optional[str] = None,
    ) -> dict:
        """
        Create a repeater request tab pre-loaded with a captured frame's bytes.

        This is the MCP equivalent of "Send to Repeater" in the UI. The new
        tab targets the same server the session was talking to.

        Args:
            session_id: Session UUID containing the frame.
            frame_id:   Frame UUID to load into the repeater.
            label:      Name for the new tab (default: "From <session_id[:8]>").

        Returns:
            The new repeater request dict.
        """
        session = api.get_session(session_id)
        if session is None:
            return {"ok": False, "error": f"Session '{session_id}' not found."}

        frame = next((f for f in session.frames if f.id == frame_id), None)
        if frame is None:
            return {"ok": False, "error": f"Frame '{frame_id}' not found in session."}

        req = ForgeRequest.create(
            label=label or f"From {session_id[:8]}",
            host=session.info.server_host,
            port=session.info.server_port,
            tls=api.config.tls_upstream,
            current_bytes=frame.raw_bytes,
            source_session_id=session_id,
        )
        _forge_requests[req.id] = req
        return {"ok": True, "request": req.to_dict()}

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
    # Config                                                                #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def get_config() -> dict:
        """Return the current ProxyConfig as a JSON-serialisable dict."""
        return api.config.to_dict()

    @mcp.tool()
    def set_config(
        listen_host:        Optional[str]  = None,
        listen_port:        Optional[int]  = None,
        upstream_host:      Optional[str]  = None,
        upstream_port:      Optional[int]  = None,
        tls_listen:         Optional[bool] = None,
        tls_upstream:       Optional[bool] = None,
        tamper_enabled:  Optional[bool] = None,
        framer_name:        Optional[str]  = None,
        protocol_definition_path: Optional[str] = None,
    ) -> dict:
        """
        Update one or more ProxyConfig fields.

        Only the provided (non-null) fields are changed; all others keep their
        current values. Changes take effect for new connections; existing
        connections are not affected.

        Upstream TLS certificate verification is always disabled — this tool
        is for reverse engineering and accepts any certificate unconditionally.

        Args:
            listen_host:              Bind address for the proxy listener.
            listen_port:              Port for the proxy listener.
            upstream_host:            Default upstream host to forward to.
            upstream_port:            Default upstream port to forward to.
            tls_listen:               Terminate TLS on the listening side.
            tls_upstream:             Use TLS when connecting upstream.
            tamper_enabled:        Master intercept on/off switch.
            framer_name:              Framer: "raw", "delimiter", "length_prefix".
            protocol_definition_path: Path to a protocol .yaml/.json file.

        Returns:
            The updated config dict.
        """
        if listen_host        is not None: api.config.listen_host       = listen_host
        if listen_port        is not None: api.config.listen_port       = listen_port
        if upstream_host      is not None: api.config.upstream_host     = upstream_host
        if upstream_port      is not None: api.config.upstream_port     = upstream_port
        if tls_listen         is not None: api.config.tls_listen        = tls_listen
        if tls_upstream       is not None: api.config.tls_upstream      = tls_upstream
        if tamper_enabled  is not None: api.config.tamper_enabled = tamper_enabled
        if framer_name        is not None: api.config.framer_name       = framer_name
        if protocol_definition_path is not None:
            api.config.protocol_definition_path = protocol_definition_path

        return api.config.to_dict()

    return mcp
