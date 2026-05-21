"""FastMCP server wrapping ProtoPokeAPI.

All tools return JSON-serialisable dicts.  Bytes fields are hex-encoded strings.
Tools are grouped by concern:

    Proxy lifecycle         : proxy_status, proxy_start, proxy_stop
    Forwarder management    : list_forwarders, add_forwarder, remove_forwarder,
                              start_forwarder, stop_forwarder, update_forwarder,
                              update_forwarder_config
    Session management      : list_sessions, get_session, get_frames,
                              get_frame, get_session_summary, decode_frames,
                              decode_frame_by_id, search_frames,
                              terminate_session, delete_session, export_session
    Protocol management     : get_protocol_info (read-only)
    Protocol definition     : get_protocol_definition,
                              get_protocol_definition_schema (read-only —
                              the AI emits YAML in chat for the user to
                              load manually; no MCP write path).
    Knowledge base          : list_findings, get_finding, add_finding,
                              update_finding, remove_finding,
                              list_notes, get_note, add_note,
                              update_note, remove_note
                              (AI may only update/remove entries it
                              authored AND that the user has not locked
                              from the TUI.)
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
    Framing                 : set_framer, list_framers
    Variables               : get_variables, set_variable, delete_variable,
                              clear_variables
    TLS / CA                : get_ca_cert
    Fuzzing                 : fuzz_start, fuzz_status, fuzz_results,
                              fuzz_stop, list_campaigns, list_mutators
    Analysis                : list_field_types, get_frame_stats, entropy_map,
                              cluster_frames, filter_frames, decode_field,
                              compare_frames, diff_frames_in_bucket,
                              analyze_byte_ranges, find_length_fields,
                              offset_correlations, find_constant_byte_sequences,
                              align_frames, extract_strings, detect_tlv,
                              detect_checksums_crcs, detect_timestamps,
                              detect_compression_encryption, echo_detection,
                              analyze_field_correlation, bruteforce_numeric_layout,
                              group_by_field_value, diff_frames,
                              bisect_field_meaning, export_session_csv,
                              detect_periodic_streams
    Authoring guides        : list_authoring_guides, get_authoring_guide,
                              get_script_load_instructions
                              (guides also exposed as ``protopoke://guides``
                              and ``protopoke://guides/<slug>`` MCP resources)
    Workflow recipes        : list_workflow_recipes, get_workflow_recipe
                              (also exposed as ``protopoke://recipes`` and
                              ``protopoke://recipes/<slug>`` MCP resources)
    Tool index              : ``protopoke://tools`` MCP resource — a
                              curated cheat-sheet of every tool grouped
                              by concern, useful for client discovery.
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

    from importlib import resources as _pkg_resources

    from protopoke import analysis
    from protopoke.models import Direction
    from protopoke.rules.rule import ReplaceRule, InterceptRule, RuleAction
    from protopoke.forge.models import Playbook, PlaybookFrame
    from protopoke.mcp.guides import (
        GUIDES,
        build_index as build_guides_index,
        load_guide,
    )
    from protopoke.mcp.recipes import (
        RECIPES,
        build_index as build_recipes_index,
        load_recipe,
    )

    def _rebind(new_api: "ProtoPokeAPI") -> None:
        """Swap the api bound to all tool closures. Called by MCPHost."""
        nonlocal api
        api = new_api

    instructions = (
        "ProtoPoke is a TCP/UDP interception proxy for reverse-engineering "
        "binary network protocols, with session capture, frame inspection, "
        "replay (forge), and tampering.\n"
        "\n"
        "Start every session by reading the existing knowledge base before "
        "re-running analysis: call list_findings(protocol_name=...) (or scope "
        "with forwarder_id=...) to recover what prior sessions already "
        "established, and list_notes() for cross-cutting context. Build on "
        "that prior state instead of rediscovering it.\n"
        "\n"
        "Record what you learn as you go: use findings for concrete, scoped "
        "claims about the protocol (a field's meaning, a message layout, a "
        "length/CRC relationship — each with a status and supporting frame "
        "IDs), and use notes for cross-cutting context that does not fit one "
        "field or message (open questions, test-setup reminders, overall "
        "hypotheses about the protocol)."
    )

    mcp = FastMCP(name, instructions=instructions)

    # ------------------------------------------------------------------ #
    # Authoring guides                                                      #
    # ------------------------------------------------------------------ #
    # Expose the protopoke/mcp/guides/*.md documents both as MCP resources
    # (preferred — surfaced in the client's resource picker) and as a tool
    # (fallback — works on clients that ignore resources).

    @mcp.resource(
        "protopoke://guides",
        name="protopoke_guides_index",
        description="Index of authoring guides for ProtoPoke extension points.",
        mime_type="text/markdown",
    )
    def _guides_index() -> str:
        return build_guides_index()

    def _register_guide(slug: str, title: str, description: str) -> None:
        @mcp.resource(
            f"protopoke://guides/{slug}",
            name=f"protopoke_guide_{slug.replace('-', '_')}",
            description=description,
            mime_type="text/markdown",
        )
        def _guide_body() -> str:
            return load_guide(slug)

    for _slug, (_filename, _title, _desc) in GUIDES.items():
        _register_guide(_slug, _title, _desc)

    @mcp.tool()
    def list_authoring_guides() -> list[dict]:
        """
        List authoring guides shipped with the MCP server.

        Each guide explains how to write a ProtoPoke extension point
        (custom framer, protocol definition YAML, custom replace script).
        Read a guide with ``get_authoring_guide(slug)``, or fetch the same
        content as the MCP resource ``protopoke://guides/<slug>``.
        """
        return [
            {"slug": slug, "title": title, "description": desc,
             "uri": f"protopoke://guides/{slug}"}
            for slug, (_, title, desc) in GUIDES.items()
        ]

    @mcp.tool()
    def get_authoring_guide(slug: str) -> dict:
        """
        Return the markdown body of one of the authoring guides.

        Valid slugs come from ``list_authoring_guides()`` (e.g. ``"framers"``,
        ``"protocol-definitions"``, ``"replace-scripts"``). Use this when
        you are about to write a custom framer, a protocol definition, or
        a script replace rule and want the authoritative format spec.
        """
        if slug not in GUIDES:
            return {"error": f"Unknown guide {slug!r}",
                    "available": list(GUIDES.keys())}
        return {"slug": slug, "content": load_guide(slug)}

    @mcp.tool()
    def get_script_load_instructions() -> dict:
        """
        Return the operator-facing steps to load a custom replace script.

        ProtoPoke does not expose any MCP tool to persist a script file or
        register a script-type replace rule — script rules execute arbitrary
        Python in the proxy process, so the operator must be the one to
        accept the code.  Call this tool after generating an ``apply()``
        script so you can quote the exact click-path back to the user.

        Returns a dict with ``steps`` (ordered list of plain-text
        instructions), ``ui_path`` (a short breadcrumb), and ``notes``
        (caveats worth mentioning in the hand-off).
        """
        return {
            "ui_path": "Tamper tab (F3) → Global Replace Rules → Add",
            "steps": [
                "Save the script shown above to a readable path on disk, "
                "for example ./scripts/<descriptive_name>.py.",
                "In ProtoPoke, switch to the Tamper tab (press F3).",
                "In the Global Replace Rules pane, press the Add button.",
                "Set Mechanism to 'Script'.",
                "Click Browse next to 'Script path' and select the file you "
                "just saved (or paste the absolute path).",
                "Give the rule a Label, pick the Direction "
                "(client_to_server / server_to_client / leave blank for both), "
                "and tick the Scope checkboxes you want "
                "(Traffic / Tamper / Forge).",
                "Press Save.  The rule appears in the table and is applied "
                "to every matching frame from this point on.",
            ],
            "notes": [
                "Auto-reload: if you edit the script file later, the next "
                "frame that hits the rule reloads the module from disk "
                "automatically — no need to remove and re-add the rule.",
                "If the script raises, ProtoPoke logs the error (Logs tab), "
                "clears the cached module, and passes the original frame "
                "through unchanged.  Use the Reset button on the rules table "
                "to force a reload without waiting for an error.",
                "Script rules execute arbitrary Python in the proxy process. "
                "Read the file before saving it and only load scripts you "
                "trust.",
            ],
        }

    # ------------------------------------------------------------------ #
    # Workflow recipes                                                      #
    # ------------------------------------------------------------------ #
    # End-to-end task walkthroughs that chain several tools together.
    # Same dual exposure as guides: MCP resources + tool fallback.

    @mcp.resource(
        "protopoke://recipes",
        name="protopoke_recipes_index",
        description="Index of workflow recipes for ProtoPoke end-to-end tasks.",
        mime_type="text/markdown",
    )
    def _recipes_index() -> str:
        return build_recipes_index()

    def _register_recipe(slug: str, title: str, description: str) -> None:
        @mcp.resource(
            f"protopoke://recipes/{slug}",
            name=f"protopoke_recipe_{slug.replace('-', '_')}",
            description=description,
            mime_type="text/markdown",
        )
        def _recipe_body() -> str:
            return load_recipe(slug)

    for _slug, (_filename, _title, _desc) in RECIPES.items():
        _register_recipe(_slug, _title, _desc)

    @mcp.tool()
    def list_workflow_recipes() -> list[dict]:
        """
        List workflow recipes shipped with the MCP server.

        Each recipe walks through an end-to-end task by chaining several
        ProtoPoke MCP tools together (reverse-engineering an unknown
        protocol, replaying with mutation, intercepting and rewriting).
        Read a recipe with ``get_workflow_recipe(slug)``, or fetch the
        same content as the MCP resource ``protopoke://recipes/<slug>``.
        """
        return [
            {"slug": slug, "title": title, "description": desc,
             "uri": f"protopoke://recipes/{slug}"}
            for slug, (_, title, desc) in RECIPES.items()
        ]

    @mcp.tool()
    def get_workflow_recipe(slug: str) -> dict:
        """
        Return the markdown body of one of the workflow recipes.

        Valid slugs come from ``list_workflow_recipes()`` (e.g.
        ``"reverse-engineer-unknown-protocol"``, ``"replay-with-mutation"``,
        ``"intercept-and-rewrite"``). Use this when you are about to drive
        an end-to-end task and want a tool-by-tool walkthrough.
        """
        if slug not in RECIPES:
            return {"error": f"Unknown recipe {slug!r}",
                    "available": list(RECIPES.keys())}
        return {"slug": slug, "content": load_recipe(slug)}

    # ------------------------------------------------------------------ #
    # Tool index (cheat-sheet)                                              #
    # ------------------------------------------------------------------ #
    # A single curated markdown document listing every MCP tool grouped
    # by concern, with cross-references to guides and recipes. Resource
    # only — clients without resource support can still discover tools
    # via the various ``list_*`` tools.

    @mcp.resource(
        "protopoke://tools",
        name="protopoke_tool_index",
        description="Curated cheat-sheet of every ProtoPoke MCP tool grouped by concern.",
        mime_type="text/markdown",
    )
    def _tool_index() -> str:
        return _pkg_resources.files("protopoke.mcp").joinpath(
            "cheatsheet.md"
        ).read_text(encoding="utf-8")

    # In-memory playbook store (MCP-side, mirrors UI Forge tab)
    _playbooks: dict[str, Playbook] = {}

    # ------------------------------------------------------------------ #
    # Proxy lifecycle                                                       #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def proxy_status() -> dict:
        """Return current proxy status: running forwarders, session and tamper counts."""
        sessions = api.list_sessions()
        active = api.list_active_sessions()
        running = api.list_running()
        return {
            "running": bool(running),
            "running_forwarders": running,
            "configured_forwarders": [f.name for f in api.forwarders],
            "tamper_enabled": api.tamper_enabled,
            "pending_tamper_count": api.pending_count(),
            "total_sessions": len(sessions),
            "active_sessions": len(active),
            "protocol_name": api._decoder.protocol_name,
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
        List all configured forwarders with their running state and full config.

        Each entry includes the forwarder's name, enabled flag, running state,
        and the complete ForwarderConfig dict.  Useful when multiple
        forwarders are configured (e.g. separate listeners for different
        protocols or ports).

        Returns:
            List of dicts with keys: name, enabled, running, config.
        """
        running = set(api.list_running())
        return [
            {
                "name":    fwd.name,
                "enabled": fwd.enabled,
                "running": fwd.name in running,
                "config":  fwd.to_dict(),
            }
            for fwd in api.forwarders
        ]

    @mcp.tool()
    async def add_forwarder(config: dict) -> dict:
        """
        Add a new forwarder from a ForwarderConfig dict.

        The dict must include a unique ``name`` and may set any
        ForwarderConfig field (listen_host, listen_port, upstream_host,
        upstream_port, forwarder_type "tcp"/"udp"/"socks5", tls_listen,
        tls_upstream, tamper_enabled, framer_name, framer_kwargs,
        protocol_definition_path, custom_framer_path, …).

        The new forwarder is added in stopped state — call ``start_forwarder``
        to begin listening.

        Returns:
            ``{"ok": True, "name": <name>}`` on success, or
            ``{"ok": False, "error": ...}``.
        """
        from ..config import ForwarderConfig
        try:
            new_fwd = ForwarderConfig.from_dict(config)
        except Exception as exc:
            return {"ok": False, "error": f"Invalid config: {exc}"}

        if any(f.name == new_fwd.name for f in api.forwarders):
            return {"ok": False, "error": f"Forwarder named {new_fwd.name!r} already exists"}

        api.update_forwarders([*api.forwarders, new_fwd])
        return {"ok": True, "name": new_fwd.name}

    @mcp.tool()
    async def remove_forwarder(name: str) -> dict:
        """
        Remove a forwarder by name.

        If the forwarder is currently running it is stopped first.  Captured
        sessions remain in the registry for inspection.

        Returns:
            ``{"ok": True, "name": <name>}`` on success, or
            ``{"ok": False, "error": ...}`` if not found.
        """
        if not any(f.name == name for f in api.forwarders):
            return {"ok": False, "error": f"Forwarder {name!r} not found"}
        if api.is_running(name):
            await api.stop_forwarder(name)
        api.update_forwarders([f for f in api.forwarders if f.name != name])
        return {"ok": True, "name": name}

    @mcp.tool()
    async def update_forwarder(name: str, fields: dict) -> dict:
        """
        Update arbitrary fields on a forwarder.

        ``fields`` is a partial ForwarderConfig dict: any field present on
        :class:`~protopoke.config.ForwarderConfig` (e.g. ``listen_port``,
        ``upstream_host``, ``tls_listen``, ``tamper_enabled``,
        ``forwarder_type``, ``socks_auth_username``, ``connect_timeout``, …)
        may be set.

        Network-level changes (host/port/transport/tls) only take effect
        after the forwarder is restarted: if the forwarder is currently
        running it is stopped and started again so the new settings apply.
        Framing and protocol-definition changes are applied in-place on
        live sessions.

        Use ``update_forwarder_config`` for hot-swap-only changes (name,
        framer, protocol) without a restart.

        Returns:
            ``{"ok": True, "config": <new ForwarderConfig dict>}``.
        """
        fwd = next((f for f in api.forwarders if f.name == name), None)
        if fwd is None:
            return {"ok": False, "error": f"Forwarder {name!r} not found"}

        from ..config import ForwarderConfig, ForwarderType
        valid_fields = set(ForwarderConfig.__dataclass_fields__)
        unknown = set(fields) - valid_fields
        if unknown:
            return {"ok": False, "error": f"Unknown field(s): {sorted(unknown)}"}

        was_running = api.is_running(name)

        # Decode any bytes-as-hex framer_kwargs values, coerce enums.
        for key, value in fields.items():
            if key == "forwarder_type" and isinstance(value, str):
                value = ForwarderType(value)
            elif key == "framer_kwargs" and isinstance(value, dict):
                decoded: dict = {}
                for k, v in value.items():
                    if isinstance(v, str):
                        try:
                            decoded[k] = bytes.fromhex(v)
                        except ValueError:
                            decoded[k] = v
                    else:
                        decoded[k] = v
                value = decoded
            setattr(fwd, key, value)

        try:
            fwd.__post_init__()
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}

        # Rebuild the engine so the new networking/transport settings apply.
        api.update_forwarders(api.forwarders)
        if was_running:
            await api.stop_forwarder(name)
            await api.start_forwarder(name)

        return {"ok": True, "config": fwd.to_dict()}

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

        Requires a protocol definition to be loaded (configured on a forwarder or set by the operator from the TUI).
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
    # Protocol management (read-only)                                       #
    # ------------------------------------------------------------------ #
    # The AI is intentionally NOT allowed to load, create, edit, or save
    # protocol definitions through the MCP server.  The user is the only
    # one who can change which definition is active (via the TUI or by
    # pointing a ForwarderConfig at a YAML file).  The AI's job is to
    # gather evidence (analysis tools), record what it learns (findings
    # / notes), and — when the user asks — emit a YAML definition in
    # chat for the user to paste/load manually.
    #
    # Use ``get_protocol_definition_schema`` to retrieve the exact YAML
    # schema for that hand-off.

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
        protocol definition to be loaded (configured on a forwarder or set by the operator from the TUI) for useful output.

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

        Requires a protocol definition to be loaded (configured on a forwarder or set by the operator from the TUI).
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
                    "error": "No protocol encoder loaded — ask the operator to load a protocol definition.",
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
        data_hex:          str,
        host:              str             = "",
        port:              int             = 0,
        tls:               bool            = False,
        connect_timeout:   Optional[float] = None,
        receive_timeout:   Optional[float] = None,
        transport:         str             = "tcp",
        source_session_id: Optional[str]   = None,
        direction:         str             = "client_to_server",
    ) -> dict:
        """
        Send raw bytes and return the response.

        Three modes:

        * **One-shot** (default, ``source_session_id`` omitted): opens a
          fresh ``transport`` connection to ``host:port``, sends the bytes,
          reads the response, then closes.
        * **Forge session reuse** (``source_session_id`` is a live forge
          session): sends over its persistent socket. Works for TCP/UDP.
          ``direction`` is ignored (forge sessions are client→server).
        * **Proxy session injection** (``source_session_id`` is a live
          proxy session): injects into the existing forwarder session and
          collects frames captured for ``receive_timeout`` seconds. Use
          ``direction="server_to_client"`` to push toward the client.

        When ``source_session_id`` is set, ``host``/``port``/``tls`` are
        taken from the bound session and the corresponding arguments are
        ignored; ``transport`` (if given) must match the session.

        Args:
            data_hex:          Bytes to send as a hex string.
            host:              Target host (one-shot mode only).
            port:              Target port (one-shot mode only).
            tls:               Wrap connection in TLS (one-shot TCP only).
            connect_timeout:   Override the default connect timeout.
            receive_timeout:   Seconds to wait for the response.
            transport:         "tcp" (default) or "udp".
            source_session_id: Reuse this existing forge or proxy session
                               instead of opening a new connection.
            direction:         "client_to_server" (default) or
                               "server_to_client" — only used for proxy
                               session injection.

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
            transport=transport,
            source_session_id=source_session_id,
            direction=direction,
        )
        return record.to_dict()

    @mcp.tool()
    async def open_forge_session(
        host: str,
        port: int,
        tls:  bool = False,
        transport: str = "tcp",
    ) -> dict:
        """
        Open a persistent connection for interactive Forge sends.

        Unlike send_frame() which opens and closes a connection per send,
        this creates a named session that stays open so you can send multiple
        requests sequentially (e.g. to maintain authentication state or test
        multi-step protocols).

        The connection appears in the Traffic tab as a regular session so
        all frames sent and received are captured for analysis.

        Use send_on_forge_session() to send data through the returned session.
        For TCP the session is marked CLOSED when the server drops it; for
        UDP the session stays open until you call ``terminate_session``.

        Args:
            host:      Target hostname or IP address.
            port:      Target port.
            tls:       Wrap the connection in TLS (TCP only; no cert verification).
            transport: ``"tcp"`` (default) or ``"udp"``.

        Returns:
            {"ok": True, "session_id": "<uuid>"} on success.
        """
        try:
            session_id = await api.open_forge_session(host, port, tls, transport=transport)
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
        transport:         str           = "tcp",
        source_session_id: Optional[str] = None,
        response_window:   float         = 1.0,
    ) -> dict:
        """
        Create a new playbook with a single frame.

        Args:
            label:             Human-readable name.
            host:              Target hostname or IP address.
            port:              Target port.
            data_hex:          Frame bytes as hex string.
            tls:               Whether to use TLS (TCP only).
            transport:         ``"tcp"`` (default) or ``"udp"``.
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
            transport=transport,
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
        transport:   Optional[str]  = None,
        data_hex:    Optional[str]  = None,
        response_window: Optional[float] = None,
    ) -> dict:
        """
        Update a playbook's connection config and/or the first frame's bytes.

        Args:
            playbook_id:     The playbook UUID.
            label:           New name (or null to keep current).
            host:            New target host (or null to keep current).
            port:            New target port (or null to keep current).
            tls:             New TLS setting (or null to keep current).
            transport:       ``"tcp"`` or ``"udp"`` (or null to keep current).
            data_hex:        New bytes for the first frame as hex (or null to keep current).
            response_window: Seconds to wait per frame (or null to keep current).

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
        if transport is not None: pb.transport = transport
        if response_window is not None: pb.response_window = response_window
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
        tls_upstream = fwd.tls_upstream if fwd else False
        transport = getattr(session.info, "transport", "tcp") or "tcp"
        pb = Playbook.create(
            label=label or f"From {session_id[:8]}",
            host=session.info.server_host,
            port=session.info.server_port,
            tls=tls_upstream,
            transport=transport,
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
        session_id:      str,
        server_host:     Optional[str]            = None,
        server_port:     Optional[int]            = None,
        frame_delay:     float                    = 0.0,
        direction:       str                      = "client_to_server",
        frame_selector:  Optional[str]            = None,
        modified_frames: Optional[dict[str, str]] = None,
    ) -> dict:
        """
        Replay a captured session against the upstream server.

        Replays the captured frames (in the selected direction) to the server.
        Useful for reproducing observed traffic, regression testing, or fuzzing.

        Args:
            session_id:      Session UUID to replay.
            server_host:     Override target host (default: original server host).
            server_port:     Override target port (default: original server port).
            frame_delay:     Seconds to wait between sending each frame.
            direction:       Which direction to replay: "client_to_server" (default)
                             or "server_to_client".
            frame_selector:  Comma/range selector for specific frames, e.g.
                             "0,2,4-6" or "3". None means all frames.
            modified_frames: Optional dict of ``frame_id → replacement_hex`` for
                             byte-level overrides on specific frames. Frames not
                             listed use their original bytes. Use
                             ``replay_with_field_edits`` for protocol field edits.

        Returns:
            ForgeResult dict with replayed_session_id, success, frame counts, etc.
        """
        try:
            dir_enum = Direction(direction)
        except ValueError:
            return {"ok": False, "error": f"Invalid direction '{direction}'."}

        decoded_mods: Optional[dict[str, bytes]] = None
        if modified_frames:
            decoded_mods = {}
            for fid, hex_str in modified_frames.items():
                try:
                    decoded_mods[fid] = bytes.fromhex(hex_str)
                except ValueError as exc:
                    return {"ok": False, "error": f"Invalid hex for frame {fid}: {exc}"}

        result = await api.forge_session(
            session_id=session_id,
            server_host=server_host,
            server_port=server_port,
            frame_delay=frame_delay,
            direction=dir_enum,
            frame_selector=frame_selector,
            modified_frames=decoded_mods,
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

        Requires a protocol definition to be loaded (configured on a forwarder or set by the operator from the TUI).
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
                    "Ask the operator to load a protocol definition to enable field-level replay."
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
    def delete_variable(name: str) -> dict:
        """
        Remove a single variable from the global variable store.

        Args:
            name: Variable name to remove.

        Returns:
            {"ok": True, "name": ...} if it existed, {"ok": False, "error": ...} otherwise.
        """
        if name not in api.variables:
            return {"ok": False, "error": f"Variable {name!r} not found."}
        del api.variables[name]
        return {"ok": True, "name": name}

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
    # Framers / mutators introspection                                      #
    # ------------------------------------------------------------------ #

    @mcp.tool()
    def list_framers() -> list[str]:
        """
        List the built-in framer names available to ``set_framer`` and
        ``update_forwarder_config``.

        Returns the keys of ``FRAMER_REGISTRY``. The pseudo-name ``"custom"``
        is always accepted as well — supply ``custom_framer_path`` to point
        at a Python file implementing :class:`~protopoke.framing.base.Framer`.
        """
        from protopoke.framing import FRAMER_REGISTRY
        return sorted(FRAMER_REGISTRY)

    @mcp.tool()
    def list_mutators() -> list[dict]:
        """
        List the fuzzing mutators available to ``fuzz_start``.

        Each entry has ``name`` (the spec key), ``parameters`` (optional
        kwargs and their defaults), and ``requires_protocol`` (True for
        protocol-aware mutators that need a protocol definition to be loaded
        first).
        """
        return [
            {"name": "bit_flip",       "parameters": {"count": 1},                       "requires_protocol": False},
            {"name": "byte_insert",    "parameters": {"count": 4},                       "requires_protocol": False},
            {"name": "byte_delete",    "parameters": {"max_count": 4},                   "requires_protocol": False},
            {"name": "known_bad",      "parameters": {},                                 "requires_protocol": False},
            {"name": "radamsa",        "parameters": {"radamsa_path": "radamsa", "timeout": 5.0}, "requires_protocol": False},
            {"name": "field_boundary", "parameters": {},                                 "requires_protocol": True},
            {"name": "field_overflow", "parameters": {"lengths": [256, 1024, 4096]},     "requires_protocol": True},
            {"name": "null_byte",      "parameters": {},                                 "requires_protocol": True},
            {"name": "length_mangle",  "parameters": {},                                 "requires_protocol": True},
        ]

    # ------------------------------------------------------------------ #
    # Analytical helpers (binary protocol reversing)                        #
    # ------------------------------------------------------------------ #

    def _parse_direction(d: Optional[str]) -> Optional[Direction]:
        if d is None:
            return None
        try:
            return Direction(d)
        except ValueError:
            raise ValueError(
                f"Invalid direction {d!r}; use 'client_to_server' or 'server_to_client'."
            )

    def _select_session_frames(
        session_id:    str,
        direction:     Optional[str],
        size_bytes:    Optional[int],
        min_size:      Optional[int],
        max_size:      Optional[int],
        byte_patterns: Optional[list[dict]],
    ) -> list:
        """Common selection step used by every analysis tool."""
        dir_enum = _parse_direction(direction)
        all_frames = api.get_frames(session_id, dir_enum)
        return analysis.select_frames(
            all_frames,
            direction=None,  # already applied via api.get_frames
            size_bytes=size_bytes,
            min_size=min_size,
            max_size=max_size,
            byte_patterns=byte_patterns,
        )

    @mcp.tool()
    def list_field_types() -> list[str]:
        """
        Return the field-type names accepted by ``decode_field`` /
        ``offset_correlations``.

        Numeric types come in explicit endianness variants (e.g. ``uint16_le``,
        ``float32_be``).  Non-numeric helpers: ``ascii`` (printable rendering),
        ``bytes`` (hex string), ``cstring`` (NUL-terminated UTF-8).
        """
        return analysis.supported_field_types()

    @mcp.tool()
    def get_frame_stats(
        session_id:     str,
        direction:      Optional[str] = None,
        size_bytes:     Optional[int] = None,
        bucket_prefix_len: int        = 2,
        max_bucket_offsets: int       = 256,
    ) -> dict:
        """
        Summary statistics for a session's frames.

        Buckets frames by ``(first-N-byte prefix, frame length)`` — the
        natural shape of "packet types" in most binary protocols — then for
        each bucket with ≥3 frames reports per-offset change-rate, distinct-
        value count, and Shannon entropy.  Also returns the size distribution,
        prefix distributions for 1/2/4-byte prefixes, and the timestamp range.

        Args:
            session_id:         Session UUID.
            direction:          Optional direction filter.
            size_bytes:         If set, only consider frames of this exact size.
            bucket_prefix_len:  How many leading bytes define a "packet type"
                                bucket (default 2 — covers most opcodes).
            max_bucket_offsets: Cap per-offset stats per bucket (default 256).
        """
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, None, None, None
            )
        except ValueError as exc:
            return {"error": str(exc)}
        return analysis.frame_stats(
            frames,
            bucket_prefix_len=bucket_prefix_len,
            max_bucket_offsets=max_bucket_offsets,
        )

    @mcp.tool()
    def entropy_map(
        session_id:    str,
        direction:     Optional[str] = None,
        size_bytes:    Optional[int] = None,
        byte_patterns: Optional[list[dict]] = None,
    ) -> dict:
        """
        Per-offset Shannon entropy across a bucket of same-size frames.

        Useful for quickly spotting constant padding (entropy ≈ 0),
        encrypted/compressed regions (entropy near 8), and structured fields
        (somewhere in between).

        All selected frames MUST be the same size.  Use ``size_bytes`` and/or
        ``byte_patterns`` to scope to a single packet type.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, None, None, byte_patterns
            )
        except ValueError as exc:
            return {"error": str(exc)}
        return analysis.entropy_map(frames)

    @mcp.tool()
    def cluster_frames(
        session_id: str,
        direction:  Optional[str] = None,
        prefix_len: int           = 2,
    ) -> dict:
        """
        Auto-discover packet-type clusters by ``(first-N-bytes, length)``.

        Cheap alternative to guessing prefix lengths manually.  Returns one
        entry per cluster with count, sequence-number range, and a sample
        hex dump of the first frame in the cluster.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, None, None, None, None
            )
        except ValueError as exc:
            return {"error": str(exc)}
        return analysis.cluster_frames(frames, prefix_len=prefix_len)

    @mcp.tool()
    def filter_frames(
        session_id:    str,
        direction:     Optional[str]        = None,
        size_bytes:    Optional[int]        = None,
        min_size:      Optional[int]        = None,
        max_size:      Optional[int]        = None,
        byte_patterns: Optional[list[dict]] = None,
        limit:         int                  = 50,
        offset_cursor: int                  = 0,
    ) -> dict:
        """
        Return a filtered, paginated slice of a session's frames.

        Replaces the "dump everything to disk and grep" workflow.  All filters
        are ANDed.  ``byte_patterns`` is a list of ``{"offset": int,
        "hex": "6d76"}`` dicts; every pattern must match its exact offset.

        Returns ``{total_matching, returned, next_cursor, frames: [...]}``.
        ``frames`` uses the same schema as ``get_frames``.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, min_size, max_size, byte_patterns
            )
        except ValueError as exc:
            return {"error": str(exc)}
        page, next_cursor = analysis.paginate(frames, limit, offset_cursor)
        return {
            "total_matching": len(frames),
            "returned":       len(page),
            "next_cursor":    next_cursor,
            "frames":         [f.to_dict() for f in page],
        }

    @mcp.tool()
    def decode_field(
        session_id:        str,
        offset:            int,
        size:              int,
        type:              str,
        direction:         Optional[str]        = None,
        size_bytes:        Optional[int]        = None,
        byte_patterns:     Optional[list[dict]] = None,
        deduplicate:       bool                 = False,
        include_timestamps: bool                = True,
        limit:             int                  = 500,
    ) -> dict:
        """
        Decode ``raw_bytes[offset:offset+size]`` as ``type`` in every selected
        frame.

        Use ``list_field_types`` for the full type list (e.g. ``uint16_le``,
        ``float32_be``, ``int8``, ``ascii``, ``cstring``).

        ``deduplicate=True`` only emits a row when the decoded value changes
        — the single highest-leverage primitive for spotting state changes
        in a long capture.  Combine with ``size_bytes`` and/or
        ``byte_patterns`` to scope to one packet type.

        Returns ``{total_returned, truncated, rows}``.  ``rows`` may be
        truncated to ``limit``; the truncation flag tells you to refine the
        filter rather than raise the limit.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, None, None, byte_patterns
            )
        except ValueError as exc:
            return {"error": str(exc)}
        try:
            rows = analysis.decode_field(
                frames,
                offset=offset,
                size=size,
                type_name=type,
                deduplicate=deduplicate,
                include_timestamps=include_timestamps,
            )
        except ValueError as exc:
            return {"error": str(exc)}
        truncated = len(rows) > limit
        return {
            "total_returned": min(len(rows), limit),
            "truncated":      truncated,
            "rows":           rows[:limit],
        }

    @mcp.tool()
    def compare_frames(
        session_id:  str,
        frame_id_a:  str,
        frame_id_b:  str,
    ) -> dict:
        """
        Byte-level diff between two specific frames.

        Returns a coalesced list of differing byte runs (with offsets and an
        integer delta where it makes sense), the common prefix / suffix
        length, and a 16-byte-row side-by-side hex view.
        """
        session = api.get_session(session_id)
        if session is None:
            return {"error": f"Session {session_id} not found"}
        fa = next((f for f in session.frames if f.id == frame_id_a), None)
        fb = next((f for f in session.frames if f.id == frame_id_b), None)
        if fa is None:
            return {"error": f"frame_id_a={frame_id_a} not found in session"}
        if fb is None:
            return {"error": f"frame_id_b={frame_id_b} not found in session"}
        return analysis.compare_two_frames(fa, fb)

    @mcp.tool()
    def diff_frames_in_bucket(
        session_id:    str,
        direction:     Optional[str]        = None,
        size_bytes:    Optional[int]        = None,
        byte_patterns: Optional[list[dict]] = None,
        max_offsets:   int                  = 64,
    ) -> dict:
        """
        Column-by-column diff matrix across all selected frames.

        All selected frames must be the same size.  Returns the offsets whose
        values vary at least once, sorted by most-varying first, each as a
        single hex string of one byte per frame in capture order.  Cheap way
        to find which offsets actually carry information in a packet type.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, None, None, byte_patterns
            )
        except ValueError as exc:
            return {"error": str(exc)}
        return analysis.diff_bucket(frames, max_offsets=max_offsets)

    @mcp.tool()
    def analyze_byte_ranges(
        session_id:    str,
        direction:     Optional[str]        = None,
        size_bytes:    Optional[int]        = None,
        byte_patterns: Optional[list[dict]] = None,
    ) -> dict:
        """
        Per-offset + per-range heuristics across a bucket of same-size frames.

        For each contiguous run of varying offsets, scores candidate types
        (uint/int LE/BE at 1/2/4/8 bytes, plus float32 LE/BE for 4-byte
        widths) and flags generic patterns:

          - ``looks_like_length``: value == frame_size - C for all frames.
          - ``looks_like_counter``: values are (mostly) monotonic.
          - ``looks_like_ascii_run``: ≥80% printable ASCII bytes.

        No domain-specific value-range checks.  All selected frames must be
        the same size; use ``size_bytes`` and/or ``byte_patterns`` to scope.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, None, None, byte_patterns
            )
        except ValueError as exc:
            return {"error": str(exc)}
        return analysis.analyze_byte_ranges(frames)

    @mcp.tool()
    def find_length_fields(
        session_id:    str,
        direction:     Optional[str]        = None,
        byte_patterns: Optional[list[dict]] = None,
    ) -> dict:
        """
        Find offsets whose integer value tracks frame length.

        Works across MIXED-size frames in the bucket — most generic length-
        prefix detection happens by correlating ``value`` with ``len(frame)``
        across frames of different sizes.  Reports every offset/width/
        byteorder combination where ``value == len(frame) - constant`` for
        the SAME constant across every selected frame.

        Heads up: a length field at offset 0 will produce both a "true"
        candidate and several lower-confidence ones if the protocol packs a
        type byte next to it — review the constants.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, None, None, None, byte_patterns
            )
        except ValueError as exc:
            return {"error": str(exc)}
        return analysis.find_length_field_candidates(frames)

    @mcp.tool()
    def offset_correlations(
        session_id:    str,
        offset_a:      int,
        offset_b:      int,
        type_a:        str                  = "uint8",
        type_b:        str                  = "uint8",
        direction:     Optional[str]        = None,
        size_bytes:    Optional[int]        = None,
        byte_patterns: Optional[list[dict]] = None,
    ) -> dict:
        """
        Pearson correlation between values at two offsets across the bucket.

        Useful for detecting paired fields (paired counters, related flags)
        without baking in domain assumptions.  Also returns ``change_pairing``:
        the fraction of consecutive frames where A and B both changed (or both
        stayed put).  High values → tightly coupled.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, None, None, byte_patterns
            )
        except ValueError as exc:
            return {"error": str(exc)}
        try:
            return analysis.offset_correlations(
                frames,
                offset_a=offset_a,
                offset_b=offset_b,
                type_a=type_a,
                type_b=type_b,
            )
        except ValueError as exc:
            return {"error": str(exc)}

    @mcp.tool()
    def find_constant_byte_sequences(
        session_id:    str,
        direction:     Optional[str]        = None,
        size_bytes:    Optional[int]        = None,
        byte_patterns: Optional[list[dict]] = None,
        min_length:    int                  = 2,
        max_length:    int                  = 8,
        min_coverage:  float                = 0.8,
        max_results:   int                  = 50,
    ) -> dict:
        """
        Find byte n-grams that appear in at least ``min_coverage`` of the
        selected frames, regardless of offset.

        Surfaces magic markers, version stamps, trailers, and recurring
        substrings that constant-offset stats miss.  Strict substrings of a
        longer hit with the same coverage are suppressed — the longest
        distinct pattern wins.

        Each result includes up to three sample frames with the offset(s) at
        which the pattern occurs so the caller can pivot from "this exists"
        to "here is where".
        """
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, None, None, byte_patterns
            )
        except ValueError as exc:
            return {"error": str(exc)}
        return analysis.find_constant_byte_sequences(
            frames,
            min_length=min_length,
            max_length=max_length,
            min_coverage=min_coverage,
            max_results=max_results,
        )

    @mcp.tool()
    def align_frames(
        session_id:     str,
        direction:      Optional[str]        = None,
        size_bytes:     Optional[int]        = None,
        byte_patterns:  Optional[list[dict]] = None,
        max_frames:     int                  = 20,
        max_frame_size: int                  = 512,
    ) -> dict:
        """
        Needleman-Wunsch global alignment of mixed-size frames against the
        first selected frame.

        Draws field boundaries even when prefixes shift — for clusters that
        share structure but have different lengths (TLV chains, string
        bodies, variable headers).  Returns the aligned rows as hex strings
        with ``--`` for gaps, plus a consensus string (``xx`` where every
        row agrees, ``??`` where rows differ, ``--`` where any gap is
        present) and the list of variable regions for quick inspection.

        Inputs are capped: at most ``max_frames`` frames, each truncated to
        ``max_frame_size`` bytes for the alignment (cost is ``O(n*m)`` per
        pair).
        """
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, None, None, byte_patterns
            )
        except ValueError as exc:
            return {"error": str(exc)}
        return analysis.align_frames(
            frames,
            max_frames=max_frames,
            max_frame_size=max_frame_size,
        )

    @mcp.tool()
    def extract_strings(
        session_id:    str,
        direction:     Optional[str]        = None,
        size_bytes:    Optional[int]        = None,
        byte_patterns: Optional[list[dict]] = None,
        min_length:    int                  = 4,
        max_per_frame: int                  = 50,
        include_utf16_le: bool              = False,
    ) -> dict:
        """
        ``strings(1)`` for captured frames: report every printable-ASCII run
        of length ≥ ``min_length``, with its frame ID and offset.

        Stops a run at NUL or any non-printable byte.  If ``include_utf16_le``
        is True, also reports Windows-style UTF-16-LE strings (printable
        ASCII bytes interleaved with NUL bytes).

        The fastest way to spot embedded usernames, hostnames, paths, error
        messages, or any other human-readable content the protocol carries.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, None, None, byte_patterns
            )
        except ValueError as exc:
            return {"error": str(exc)}
        try:
            return analysis.extract_strings(
                frames,
                min_length=min_length,
                max_per_frame=max_per_frame,
                include_utf16_le=include_utf16_le,
            )
        except ValueError as exc:
            return {"error": str(exc)}

    @mcp.tool()
    def detect_tlv(
        session_id:    str,
        direction:     Optional[str]        = None,
        size_bytes:    Optional[int]        = None,
        byte_patterns: Optional[list[dict]] = None,
        start_offsets: Optional[list[int]]  = None,
        min_records:   int                  = 2,
        min_coverage:  float                = 0.6,
        max_results:   int                  = 10,
    ) -> dict:
        """
        Try Type-Length-Value layouts and score how well each one explains
        the selected frames.

        For every combination of ``(type_width in {1, 2}, length_width in
        {1, 2, 4}, length_byteorder, length_includes_header)`` and every
        starting offset in ``start_offsets`` (default ``[0]``), walk each
        frame as a TLV chain.  A frame "matches" a shape if the walk
        consumes the entire buffer (no leftover bytes) and produces at least
        ``min_records`` records.

        For each surviving candidate the response includes the most common
        type values seen, which often directly map to opcode / tag names
        in the spec.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, None, None, byte_patterns
            )
        except ValueError as exc:
            return {"error": str(exc)}
        offsets = tuple(start_offsets) if start_offsets else (0,)
        return analysis.detect_tlv(
            frames,
            start_offsets=offsets,
            min_records=min_records,
            min_coverage=min_coverage,
            max_results=max_results,
        )

    @mcp.tool()
    def detect_checksums_crcs(
        session_id:    str,
        direction:     Optional[str]        = None,
        size_bytes:    Optional[int]        = None,
        byte_patterns: Optional[list[dict]] = None,
        min_coverage:  float                = 0.9,
        max_results:   int                  = 20,
    ) -> dict:
        """
        Try standard checksum / CRC / Adler / Fletcher algorithms over each
        frame and report ``(offset, algorithm, byteorder, coverage)`` hits.

        Algorithms tried: ``sum8``, ``xor8``, ``sum16``, ``fletcher16``,
        ``crc16_ccitt`` (init 0xFFFF), ``crc16_xmodem`` (init 0),
        ``crc32_ieee`` (zlib), ``adler32`` (zlib).

        For each candidate offset+algorithm, the algorithm is computed over
        the frame's bytes *excluding* the candidate field.  If the stored
        value matches the computed value in at least ``min_coverage`` of
        frames, the candidate is reported.  For multi-byte algorithms, both
        little- and big-endian interpretations are tried.

        Reports the algorithm name, offset, byteorder, and coverage —
        enough to add the checksum as a field in the protocol definition
        and tag it for `tamper` probes.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, None, None, byte_patterns
            )
        except ValueError as exc:
            return {"error": str(exc)}
        return analysis.detect_checksums_crcs(
            frames,
            min_coverage=min_coverage,
            max_results=max_results,
        )

    @mcp.tool()
    def detect_timestamps(
        session_id:    str,
        direction:     Optional[str]        = None,
        size_bytes:    Optional[int]        = None,
        byte_patterns: Optional[list[dict]] = None,
        min_coverage:  float                = 0.8,
        max_results:   int                  = 20,
    ) -> dict:
        """
        Find offsets whose decoded unsigned integer value lies in a plausible
        real-world timestamp range across most selected frames.

        For each ``(offset, width in {4, 8}, byteorder in {little, big})``
        candidate, check the fraction of frames where the value falls inside
        each known epoch range — ``unix_seconds``, ``unix_milliseconds``,
        ``ntp_seconds``, ``windows_filetime``.  Each surviving candidate also
        reports the Pearson correlation between the decoded value and the
        frame's capture timestamp — a value near 1.0 strongly confirms it's
        a real timestamp rather than an integer that happens to be in range.

        Use the correlation to break ties between LE/BE candidates: the
        endianness with the higher ``pearson_r_with_capture_time`` is
        almost always the right one.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, None, None, byte_patterns
            )
        except ValueError as exc:
            return {"error": str(exc)}
        return analysis.detect_timestamps(
            frames,
            min_coverage=min_coverage,
            max_results=max_results,
        )

    @mcp.tool()
    def detect_compression_encryption(
        session_id:       str,
        direction:        Optional[str]        = None,
        size_bytes:       Optional[int]        = None,
        byte_patterns:    Optional[list[dict]] = None,
        high_entropy_min: float                = 7.5,
        window_size:      int                  = 64,
        window_step:      int                  = 16,
        max_per_frame:    int                  = 6,
    ) -> dict:
        """
        Per-frame detection of compressed/encrypted regions and known
        file/stream magic signatures.

        Two passes per frame:

        - **Signature scan** — every byte position is checked against a small
          catalogue of well-known magic strings (gzip, zlib, lz4, zstd, png,
          jpeg, zip, ELF, PE, ASN.1 SEQUENCE, TLS handshake records, SSH
          banners, …).
        - **Entropy windows** — a sliding ``window_size``-byte window
          (stepping by ``window_step``) is scored for Shannon entropy;
          windows at or above ``high_entropy_min`` bits are reported (capped
          at ``max_per_frame`` per frame).

        Useful for spotting embedded blobs (compressed payloads,
        ciphertext, nested protocols) you'd otherwise miss in a hex dump.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, None, None, byte_patterns
            )
        except ValueError as exc:
            return {"error": str(exc)}
        return analysis.detect_compression_encryption(
            frames,
            high_entropy_min=high_entropy_min,
            window_size=window_size,
            window_step=window_step,
            max_per_frame=max_per_frame,
        )

    @mcp.tool()
    def echo_detection(
        session_id:    str,
        size_bytes:    Optional[int]        = None,
        byte_patterns: Optional[list[dict]] = None,
        widths:        Optional[list[int]]  = None,
        max_distance:  int                  = 5,
        min_coverage:  float                = 0.5,
        max_results:   int                  = 20,
    ) -> dict:
        """
        Find values sent in one direction that reappear in the opposite
        direction shortly after — the classic transaction-ID / session-token /
        echo pattern.

        Walks the session's frames in capture order.  For every source
        frame F and each width in ``widths`` (default ``[2, 4, 8]``),
        slides a window over F; for each non-trivial value (rejects all-
        zero and all-same-byte values), looks in the next ``max_distance``
        frames in the OPPOSITE direction.  Triples
        ``(src_offset, dst_offset, width)`` that hit in at least
        ``min_coverage`` of opportunities are reported with a sample value
        — strong evidence the same field is being echoed.

        Note: both directions are needed, so this tool does not accept a
        ``direction`` filter.
        """
        # All frames, both directions
        try:
            frames = _select_session_frames(
                session_id, None, size_bytes, None, None, byte_patterns
            )
        except ValueError as exc:
            return {"error": str(exc)}
        w_tuple = tuple(widths) if widths else (2, 4, 8)
        return analysis.echo_detection(
            frames,
            widths=w_tuple,
            max_distance=max_distance,
            min_coverage=min_coverage,
            max_results=max_results,
        )

    # ------------------------------------------------------------------ #
    # Field-type bruteforce / time series                                  #
    # ------------------------------------------------------------------ #
    # Compact encoding names: u8, i8, u16_le/u16_be, i16_le/i16_be,
    # u32_le/u32_be, i32_le/i32_be, f32_le/f32_be, f64_le/f64_be.

    _FINDING_HINT = (
        "If this confirms a field interpretation, consider recording it as a "
        "finding via add_finding so it persists in the knowledge base."
    )

    @mcp.tool()
    def analyze_field_correlation(
        session_id:  str,
        byte_offset: int,
        byte_length: int,
        encoding:    str,
        direction:   Optional[str] = None,
        size_bytes:  Optional[int] = None,
    ) -> dict:
        """
        Decode one field as a time series across a session's frames.

        Pull ``raw_bytes[byte_offset:byte_offset+byte_length]`` from every
        matching frame and decode it with ``encoding`` (one of ``u8``, ``i8``,
        ``u16_le``, ``u16_be``, ``i16_le``, ``i16_be``, ``u32_le``, ``u32_be``,
        ``i32_le``, ``i32_be``, ``f32_le``, ``f32_be``, ``f64_le``, ``f64_be``).
        ``byte_length`` must equal the encoding width.

        Saves writing a throwaway script to test a field-type hypothesis: one
        row per frame with ``frame_id``, ``timestamp``, ``sequence_number`` and
        the decoded ``value``, in capture order.  Use ``direction`` and
        ``size_bytes`` to scope to one packet type.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, None, None, None
            )
        except ValueError as exc:
            return {"error": str(exc)}
        try:
            result = analysis.field_time_series(
                frames, byte_offset, byte_length, encoding
            )
        except ValueError as exc:
            return {"error": str(exc)}
        result["suggestion"] = _FINDING_HINT
        return result

    @mcp.tool()
    def bruteforce_numeric_layout(
        session_id: str,
        size_bytes: Optional[int] = None,
        direction:  Optional[str] = None,
        max_sample: int           = 200,
        top_n:      int           = 20,
    ) -> dict:
        """
        Score every numeric encoding at every offset to guess field types.

        Runs on a sample of frames from one packet-size bucket (the dominant
        size by default, or ``size_bytes`` if given) and tries each encoding
        (``u8`` … ``f64_be``) at every offset that fits.  Each ``(offset,
        encoding)`` pair is scored on:

        - **float validity** — float encodings with any NaN/Inf score 0;
        - **high-byte stability** — low entropy in the most-significant byte
          (real coordinates/counters don't span the full type range);
        - **smoothness / monotonicity** — small successive deltas between
          temporally adjacent frames.

        Constant offsets are skipped.  Returns the top ``top_n`` candidates
        sorted by score — the automated version of guessing field types by
        hand.  This is usually the fastest first pass on a new fixed-size
        packet type.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, None, None, None, None
            )
        except ValueError as exc:
            return {"error": str(exc)}
        result = analysis.bruteforce_numeric_layout(
            frames, size_bytes=size_bytes, max_sample=max_sample, top_n=top_n
        )
        if result.get("candidates"):
            result["suggestion"] = _FINDING_HINT
        return result

    @mcp.tool()
    def group_by_field_value(
        session_id:         str,
        ranges:             list[dict],
        direction:          Optional[str] = None,
        size_bytes:         Optional[int] = None,
        max_ids_per_bucket: int           = 1000,
    ) -> dict:
        """
        Bucket frames by the concatenated value at one or more byte ranges.

        ``ranges`` is a list of ``{"offset": int, "length": int}`` dicts; the
        raw bytes at all ranges are concatenated to form each frame's bucket
        key.  Surfaces flag fields and joint distributions across two offsets
        (e.g. a pair of input-axis bytes) that per-offset entropy can't show.

        Returns ``counts`` (``{key_hex: n}``) and ``groups``
        (``{key_hex: [frame_ids]}``), ordered by descending count.  Frames too
        short for a range are skipped.
        """
        norm: list[tuple[int, int]] = []
        for r in ranges:
            try:
                norm.append((int(r["offset"]), int(r["length"])))
            except (KeyError, TypeError, ValueError) as exc:
                return {"error": f"Invalid range {r!r}: {exc}"}
        try:
            frames = _select_session_frames(
                session_id, direction, size_bytes, None, None, None
            )
        except ValueError as exc:
            return {"error": str(exc)}
        try:
            result = analysis.group_by_field_value(
                frames, norm, max_ids_per_bucket=max_ids_per_bucket
            )
        except ValueError as exc:
            return {"error": str(exc)}
        result["suggestion"] = _FINDING_HINT
        return result

    @mcp.tool()
    def diff_frames(
        session_id:     str,
        frame_id_a:     str,
        frame_id_b:     str,
        field_decls:    Optional[list[dict]] = None,
        max_diff_bytes: int                  = 512,
    ) -> dict:
        """
        Per-byte diff of two frames, plus decoded deltas for declared fields.

        Returns every differing byte (offset + both hex values).  Optionally
        pass ``field_decls`` — a list of ``{"offset", "length", "encoding"}``
        dicts — to also get the decoded value in each frame and the delta for
        those fields (``encoding`` is one of ``u8`` … ``f64_be``).

        Answers "what changed between this frame and the next?" directly.
        """
        session = api.get_session(session_id)
        if session is None:
            return {"error": f"Session {session_id} not found"}
        fa = next((f for f in session.frames if f.id == frame_id_a), None)
        fb = next((f for f in session.frames if f.id == frame_id_b), None)
        if fa is None:
            return {"error": f"frame_id_a={frame_id_a} not found in session"}
        if fb is None:
            return {"error": f"frame_id_b={frame_id_b} not found in session"}
        try:
            result = analysis.diff_frames(
                fa, fb, field_decls=field_decls, max_diff_bytes=max_diff_bytes
            )
        except (ValueError, KeyError, TypeError) as exc:
            return {"error": f"Invalid field declaration: {exc}"}
        if result.get("field_deltas"):
            result["suggestion"] = _FINDING_HINT
        return result

    @mcp.tool()
    async def bisect_field_meaning(
        forge_session_id: str,
        base_frame_hex:   str,
        byte_offset:      int,
        byte_length:      int,
        encoding:         str,
        candidate_values: Optional[list[float]] = None,
        value_range:      Optional[dict]        = None,
        receive_timeout:  Optional[float]       = None,
    ) -> dict:
        """
        Sweep a field across candidate values and capture the server response.

        For each candidate, the field at ``byte_offset`` (``byte_length`` bytes,
        decoded with ``encoding`` — ``u8`` … ``f64_be``) in ``base_frame_hex``
        is overwritten and the resulting frame is sent over the persistent
        forge session ``forge_session_id`` (open one with
        ``open_forge_session``).  Confirms a field's meaning by observation
        rather than inference — the natural counterpart to
        ``replay_with_field_edits``.

        Provide candidates either as ``candidate_values`` (a list of numbers)
        or ``value_range`` (``{"start", "stop", "step"}``; ``step`` defaults to
        1, ``stop`` exclusive).  Capped at 256 candidates.

        Returns ``{ok, results: {candidate: response_bytes_hex}, errors:
        {candidate: message}}``.
        """
        try:
            base = bytes.fromhex(base_frame_hex)
        except ValueError as exc:
            return {"ok": False, "error": f"Invalid base_frame_hex: {exc}"}
        try:
            width = analysis.encoding_width(encoding)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        if byte_length != width:
            return {"ok": False, "error":
                    f"encoding {encoding!r} is {width} bytes wide but byte_length={byte_length}"}
        if byte_offset < 0 or byte_offset + width > len(base):
            return {"ok": False, "error": "field range is outside the base frame"}

        values: list = list(candidate_values or [])
        if value_range:
            try:
                start = value_range["start"]
                stop = value_range["stop"]
                step = value_range.get("step", 1)
            except (KeyError, TypeError) as exc:
                return {"ok": False, "error": f"Invalid value_range: {exc}"}
            if step == 0:
                return {"ok": False, "error": "value_range step must be non-zero"}
            v = start
            while (step > 0 and v < stop) or (step < 0 and v > stop):
                values.append(v)
                v += step
                if len(values) > 256:
                    break
        if not values:
            return {"ok": False, "error": "provide candidate_values or value_range"}
        if len(values) > 256:
            return {"ok": False, "error": f"too many candidates ({len(values)}); cap is 256"}

        results: dict[str, Optional[str]] = {}
        errors: dict[str, str] = {}
        for cv in values:
            key = str(cv)
            try:
                field_bytes = analysis.encode_value(cv, encoding)
            except ValueError as exc:
                errors[key] = f"encode failed: {exc}"
                continue
            mutated = base[:byte_offset] + field_bytes + base[byte_offset + width:]
            try:
                res = await api.send_on_forge_session(
                    session_id=forge_session_id,
                    data=mutated,
                    receive_timeout=receive_timeout,
                )
            except Exception as exc:
                errors[key] = str(exc)
                continue
            if res.success:
                results[key] = res.received_bytes.hex()
            else:
                results[key] = None
                errors[key] = res.error or "send failed"

        return {
            "ok":         True,
            "results":    results,
            "errors":     errors,
            "suggestion": _FINDING_HINT,
        }

    @mcp.tool()
    def export_session_csv(
        session_id: str,
        fields:     list[dict],
        direction:  Optional[str] = None,
    ) -> dict:
        """
        Flatten a session to CSV for external plotting / notebooks.

        ``fields`` is a list of declared columns, each
        ``{"name", "byte_offset", "byte_length", "encoding"}`` (encoding one of
        ``u8`` … ``f64_be``) with an optional ``"message_filter"`` byte pattern
        (``{"offset", "hex"}`` or a list of them) that restricts the column to
        matching frames.

        Returns ``{frame_count, rows, columns, csv}`` — one row per frame with
        ``frame_id, timestamp, sequence_number, direction, size`` followed by
        one column per declared field.  Cells are blank where a frame is too
        short or fails its ``message_filter``.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, None, None, None, None
            )
        except ValueError as exc:
            return {"error": str(exc)}
        try:
            return analysis.export_session_csv(frames, fields)
        except (ValueError, KeyError, TypeError) as exc:
            return {"error": f"Invalid field declaration: {exc}"}

    @mcp.tool()
    def detect_periodic_streams(
        session_id:        str,
        direction:         Optional[str] = None,
        bucket_prefix_len: int           = 2,
        cv_threshold:      float         = 0.2,
        min_count:         int           = 10,
    ) -> dict:
        """
        Flag packet-type buckets whose inter-arrival times look periodic.

        Groups frames by ``(prefix_hex, size_bytes)`` (same key as
        ``get_frame_stats``) and, for each bucket, reports the mean and
        standard deviation of the inter-arrival intervals, their coefficient of
        variation, and ``is_periodic`` (``cv < cv_threshold`` and
        ``count > min_count``).

        Surfaces heartbeats, position pings, and keepalives — usually the entry
        point to reverse-engineering a new protocol.
        """
        try:
            frames = _select_session_frames(
                session_id, direction, None, None, None, None
            )
        except ValueError as exc:
            return {"error": str(exc)}
        result = analysis.detect_periodic_streams(
            frames,
            bucket_prefix_len=bucket_prefix_len,
            cv_threshold=cv_threshold,
            min_count=min_count,
        )
        if result.get("periodic_count"):
            result["suggestion"] = _FINDING_HINT
        return result

    # ------------------------------------------------------------------ #
    # Protocol definition — READ-ONLY                                       #
    # ------------------------------------------------------------------ #
    # The AI can inspect the active definition (whatever the user loaded
    # into the running ProtoPoke instance) and ask for the YAML schema
    # so it can emit a hand-off definition in chat.  Writing or saving
    # definitions is not exposed — that remains a user action.

    @mcp.tool()
    def get_protocol_definition() -> dict:
        """
        Return the active ProtocolDefinition as a YAML-compatible dict.

        Returns the same dict shape the YAML loader accepts.  Useful for
        the AI to inspect what the operator has currently loaded so it
        can reason about it or extend it (in chat) without re-deriving
        the structure from scratch.

        Returns ``{"error": ...}`` if no definition-based protocol is
        loaded (the active decoder is the passthrough).
        """
        from protopoke.protocol.definition import protocol_to_dict
        from protopoke.protocol.parser import DefinitionBasedDecoder
        if not isinstance(api._decoder, DefinitionBasedDecoder):
            return {"error": "No protocol definition is loaded."}
        return protocol_to_dict(api._decoder._def)

    @mcp.tool()
    def get_protocol_definition_schema() -> dict:
        """
        Return the authoritative YAML schema for ProtocolDefinition files.

        Use this when the operator asks you to "create a protocol
        definition based on what you've learned".  The MCP layer does
        NOT save definitions to disk — emit the YAML in chat instead so
        the operator can review and load it themselves via the TUI.

        Returns a dict with:
            content:   the full markdown spec (field types, match rules,
                       expressions, examples).
            uri:       the MCP resource URI for the same content
                       (``protopoke://guides/protocol-definitions``).
            workflow:  one-line summary of the recommended hand-off flow.
        """
        return {
            "content":  load_guide("protocol-definitions"),
            "uri":      "protopoke://guides/protocol-definitions",
            "workflow": (
                "Compose the YAML in chat, show it to the user, and let "
                "them save and load it manually from the ProtoPoke UI."
            ),
        }

    # ------------------------------------------------------------------ #
    # Knowledge base — findings + notes (AI memory across sessions)         #
    # ------------------------------------------------------------------ #
    # AI clients can freely add findings and notes here; updates and
    # deletes are restricted to entries the AI authored AND that the user
    # has not locked from the UI.  See protopoke/knowledge/.

    from protopoke.knowledge import Finding, Note

    def _serialise_finding(finding: "Finding") -> dict:
        """Add the resolved forwarder display name to the finding dict."""
        d = finding.to_dict()
        d["forwarder_name"] = api.resolve_forwarder_name(finding.forwarder_id)
        return d

    def _ai_can_mutate(entry, kind: str) -> Optional[dict]:
        """Return an error dict if the AI may not mutate ``entry``.

        AI clients can only update or remove entries they authored AND
        that the user has not locked through the UI.  Returns None if
        the mutation is allowed.
        """
        if entry.author != "ai":
            return {
                "ok": False,
                "error": (
                    f"This {kind} was authored by {entry.author!r}; "
                    f"the AI may only edit/remove its own entries.  "
                    f"Add a counter-{kind} instead."
                ),
            }
        if entry.locked:
            return {
                "ok": False,
                "error": (
                    f"This {kind} was locked by the user via the UI; "
                    f"the AI may not modify it.  Add a counter-{kind} "
                    f"instead, or ask the user to unlock it."
                ),
            }
        return None

    # ---------- Findings ----------

    @mcp.tool()
    def list_findings(
        query:         Optional[str]       = None,
        status:        Optional[str]       = None,
        author:        Optional[str]       = None,
        protocol_name: Optional[str]       = None,
        message_name:  Optional[str]       = None,
        field_name:    Optional[str]       = None,
        forwarder_id:  Optional[str]       = None,
        tags:          Optional[list[str]] = None,
    ) -> list[dict]:
        """
        Return findings in the project's knowledge base, optionally filtered.

        Findings are structured claims the AI (or user) has recorded about
        the protocol under investigation — hypotheses, confirmed facts,
        ruled-out theories.  Use this on session start to recover what
        previous sessions discovered before re-running analysis.

        Args:
            query:         Case-insensitive substring match against title,
                           description, and tags.
            status:        ``hypothesis`` | ``confirmed`` | ``ruled_out`` |
                           ``needs_review``.
            author:        Filter by author (``"ai"`` or ``"user"``).
            protocol_name: Scope to one protocol name.
            message_name:  Scope to one message type.
            field_name:    Scope to one field within a message.
            forwarder_id:  Scope to one forwarder by its stable UUID
                           (use ``list_forwarders`` to look up IDs).
            tags:          AND match — all named tags must be present.

        Returns:
            List of finding dicts.  Each includes ``forwarder_name``
            resolved against the current forwarder list, so renames are
            transparent.
        """
        results = api.knowledge.list_findings(
            query=query, status=status, author=author,
            protocol_name=protocol_name, message_name=message_name,
            field_name=field_name, forwarder_id=forwarder_id, tags=tags,
        )
        return [_serialise_finding(f) for f in results]

    @mcp.tool()
    def get_finding(finding_id: str) -> dict:
        """Return one finding by ID, or ``{"error": ...}`` if not found."""
        finding = api.knowledge.get_finding(finding_id)
        if finding is None:
            return {"error": f"No finding with id {finding_id!r}"}
        return _serialise_finding(finding)

    @mcp.tool()
    def add_finding(
        title:        str,
        description:  str                 = "",
        status:       str                 = "hypothesis",
        confidence:   str                 = "medium",
        protocol_name: Optional[str]      = None,
        message_name:  Optional[str]      = None,
        field_name:    Optional[str]      = None,
        byte_offset:   Optional[int]      = None,
        byte_length:   Optional[int]      = None,
        direction:     Optional[str]      = None,
        forwarder_id:  Optional[str]      = None,
        evidence_frame_ids:         Optional[list[str]] = None,
        counter_evidence_frame_ids: Optional[list[str]] = None,
        tags:                       Optional[list[str]] = None,
    ) -> dict:
        """
        Record a new finding in the knowledge base.

        Use a **finding** (not a note) for a concrete, scoped claim about the
        protocol — something that is true or false about the bytes on the
        wire and that you can pin to a location and back with evidence.
        Examples: "byte 0 is a message-type tag", "bytes 4-5 are a big-endian
        length covering the payload", "the trailing 2 bytes are a CRC16 over
        the header".  Give it a ``status`` (hypothesis until you have
        evidence, then confirmed or ruled_out), a ``confidence``, the
        tightest scope you can (protocol / message / field / byte range), and
        the frame IDs that support or refute it.  For broad context that does
        not belong to one field or message — open questions, test-setup
        notes, overall protocol hypotheses — use ``add_note`` instead.

        The finding is always attributed to the AI (``author="ai"``) and
        starts unlocked.  Scope fields are optional — pin the finding at
        whatever level makes sense (protocol-wide, message-level,
        field-level, or a raw byte range when no field name exists yet).

        Args:
            title:        One-line summary (required).
            description:  Markdown body — reasoning, references, examples.
            status:       ``hypothesis`` (default) | ``confirmed`` |
                          ``ruled_out`` | ``needs_review``.
            confidence:   ``low`` | ``medium`` (default) | ``high``.
            protocol_name, message_name, field_name: Optional scope hints.
            byte_offset, byte_length: Pin to a raw byte range when no
                          field exists yet (e.g. "bytes 4-5 look like
                          a CRC16").
            direction:    ``client_to_server`` | ``server_to_client``.
            forwarder_id: Stable UUID of a forwarder (from
                          ``list_forwarders``).  Survives renames.
            evidence_frame_ids:         Supporting frame IDs.
            counter_evidence_frame_ids: Frames that would refute it.
            tags:         Free-form filtering tags.

        Returns the created finding dict.
        """
        try:
            finding = Finding.create(
                title=title, description=description,
                status=status, confidence=confidence,
                author="ai", locked=False,
                protocol_name=protocol_name, message_name=message_name,
                field_name=field_name, byte_offset=byte_offset,
                byte_length=byte_length, direction=direction,
                forwarder_id=forwarder_id,
                evidence_frame_ids=evidence_frame_ids,
                counter_evidence_frame_ids=counter_evidence_frame_ids,
                tags=tags,
            )
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        api.knowledge.add_finding(finding)
        return {"ok": True, "finding": _serialise_finding(finding)}

    @mcp.tool()
    def update_finding(
        finding_id:    str,
        title:         Optional[str]       = None,
        description:   Optional[str]       = None,
        status:        Optional[str]       = None,
        confidence:    Optional[str]       = None,
        protocol_name: Optional[str]       = None,
        message_name:  Optional[str]       = None,
        field_name:    Optional[str]       = None,
        byte_offset:   Optional[int]       = None,
        byte_length:   Optional[int]       = None,
        direction:     Optional[str]       = None,
        forwarder_id:  Optional[str]       = None,
        evidence_frame_ids:         Optional[list[str]] = None,
        counter_evidence_frame_ids: Optional[list[str]] = None,
        tags:                       Optional[list[str]] = None,
    ) -> dict:
        """
        Update one or more fields of an existing finding.

        AI clients may only update findings they authored AND that the
        user has not locked from the TUI.  When refused, the error
        message explains why; add a counter-finding instead.

        Only the kwargs that are not ``None`` are applied.  Validation
        of ``status`` / ``confidence`` mirrors :meth:`add_finding`.
        """
        finding = api.knowledge.get_finding(finding_id)
        if finding is None:
            return {"ok": False, "error": f"No finding with id {finding_id!r}"}
        refusal = _ai_can_mutate(finding, "finding")
        if refusal is not None:
            return refusal

        changes: dict = {}
        for key, value in {
            "title": title, "description": description,
            "status": status, "confidence": confidence,
            "protocol_name": protocol_name, "message_name": message_name,
            "field_name": field_name, "byte_offset": byte_offset,
            "byte_length": byte_length, "direction": direction,
            "forwarder_id": forwarder_id,
            "evidence_frame_ids": evidence_frame_ids,
            "counter_evidence_frame_ids": counter_evidence_frame_ids,
            "tags": tags,
        }.items():
            if value is not None:
                changes[key] = value

        # Validate status/confidence (the store does not).
        if "status" in changes:
            from protopoke.knowledge.models import FINDING_STATUSES
            if changes["status"] not in FINDING_STATUSES:
                return {"ok": False,
                        "error": f"Invalid status {changes['status']!r}; "
                                 f"expected one of {FINDING_STATUSES}"}
        if "confidence" in changes:
            from protopoke.knowledge.models import FINDING_CONFIDENCE
            if changes["confidence"] not in FINDING_CONFIDENCE:
                return {"ok": False,
                        "error": f"Invalid confidence {changes['confidence']!r}; "
                                 f"expected one of {FINDING_CONFIDENCE}"}

        try:
            updated = api.knowledge.update_finding(finding_id, **changes)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "finding": _serialise_finding(updated)}

    @mcp.tool()
    def remove_finding(finding_id: str) -> dict:
        """
        Remove a finding by ID.

        Same author / locked restrictions as :meth:`update_finding`.
        """
        finding = api.knowledge.get_finding(finding_id)
        if finding is None:
            return {"ok": False, "error": f"No finding with id {finding_id!r}"}
        refusal = _ai_can_mutate(finding, "finding")
        if refusal is not None:
            return refusal
        api.knowledge.remove_finding(finding_id)
        return {"ok": True, "finding_id": finding_id}

    # ---------- Notes ----------

    @mcp.tool()
    def list_notes(
        query:  Optional[str]       = None,
        author: Optional[str]       = None,
        tags:   Optional[list[str]] = None,
    ) -> list[dict]:
        """
        Return free-form notes in the project's knowledge base.

        Use notes for context that does not fit the structured Finding
        shape — open questions, design hypotheses about the whole
        protocol, test-setup reminders.

        Args:
            query:  Case-insensitive substring match against title,
                    body, and tags.
            author: Filter by author.
            tags:   AND match — all named tags must be present.
        """
        return [n.to_dict() for n in api.knowledge.list_notes(
            query=query, author=author, tags=tags,
        )]

    @mcp.tool()
    def get_note(note_id: str) -> dict:
        """Return one note by ID, or ``{"error": ...}`` if not found."""
        note = api.knowledge.get_note(note_id)
        if note is None:
            return {"error": f"No note with id {note_id!r}"}
        return note.to_dict()

    @mcp.tool()
    def add_note(
        title:   str,
        body_md: str                 = "",
        tags:    Optional[list[str]] = None,
    ) -> dict:
        """
        Record a new note in the knowledge base.

        Use a **note** (not a finding) for cross-cutting context that does not
        reduce to a single claim about a field, message, or byte range — open
        questions to revisit, test-setup reminders, working hypotheses about
        the protocol as a whole, or a narrative summary tying several findings
        together.  When you have a concrete, locatable claim you can back with
        evidence ("byte N means X", "this field is the length"), record it as
        a structured ``add_finding`` instead so it can be scoped, statused,
        and filtered.

        Always attributed to the AI (``author="ai"``) and starts unlocked.

        Args:
            title:   One-line label (required).
            body_md: Markdown body.
            tags:    Free-form filtering tags.
        """
        note = Note.create(title=title, body_md=body_md,
                           author="ai", locked=False, tags=tags)
        api.knowledge.add_note(note)
        return {"ok": True, "note": note.to_dict()}

    @mcp.tool()
    def update_note(
        note_id: str,
        title:   Optional[str]       = None,
        body_md: Optional[str]       = None,
        tags:    Optional[list[str]] = None,
    ) -> dict:
        """
        Update a note's title, body, or tags.

        Same author / locked restrictions as :meth:`update_finding`.
        Only non-``None`` kwargs are applied.
        """
        note = api.knowledge.get_note(note_id)
        if note is None:
            return {"ok": False, "error": f"No note with id {note_id!r}"}
        refusal = _ai_can_mutate(note, "note")
        if refusal is not None:
            return refusal
        changes: dict = {}
        for key, value in {"title": title, "body_md": body_md, "tags": tags}.items():
            if value is not None:
                changes[key] = value
        updated = api.knowledge.update_note(note_id, **changes)
        return {"ok": True, "note": updated.to_dict()}

    @mcp.tool()
    def remove_note(note_id: str) -> dict:
        """
        Remove a note by ID.

        Same author / locked restrictions as :meth:`update_note`.
        """
        note = api.knowledge.get_note(note_id)
        if note is None:
            return {"ok": False, "error": f"No note with id {note_id!r}"}
        refusal = _ai_can_mutate(note, "note")
        if refusal is not None:
            return refusal
        api.knowledge.remove_note(note_id)
        return {"ok": True, "note_id": note_id}

    # Expose the rebind hook so MCPHost can swap the bound API without
    # tearing down the server task.
    mcp._protopoke_rebind = _rebind
    return mcp
