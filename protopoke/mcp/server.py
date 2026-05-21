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
        """List authoring guides for ProtoPoke extension points (custom framer,
        protocol definition YAML, custom replace script). Read one with
        get_authoring_guide(slug)."""
        return [
            {"slug": slug, "title": title, "description": desc,
             "uri": f"protopoke://guides/{slug}"}
            for slug, (_, title, desc) in GUIDES.items()
        ]

    @mcp.tool()
    def get_authoring_guide(slug: str) -> dict:
        """Return the markdown body of one authoring guide. Valid slugs come
        from list_authoring_guides() (e.g. "framers", "protocol-definitions",
        "replace-scripts")."""
        if slug not in GUIDES:
            return {"error": f"Unknown guide {slug!r}",
                    "available": list(GUIDES.keys())}
        return {"slug": slug, "content": load_guide(slug)}

    @mcp.tool()
    def get_script_load_instructions() -> dict:
        """Operator-facing steps to load a custom replace script (script rules
        run arbitrary Python, so only the operator can register them). Call
        after generating an apply() script to quote the click-path to the user.
        Returns steps, ui_path, notes."""
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
        """List end-to-end workflow recipes (chains of ProtoPoke tools). Read one with get_workflow_recipe(slug)."""
        return [
            {"slug": slug, "title": title, "description": desc,
             "uri": f"protopoke://recipes/{slug}"}
            for slug, (_, title, desc) in RECIPES.items()
        ]

    @mcp.tool()
    def get_workflow_recipe(slug: str) -> dict:
        """Return the markdown body of one workflow recipe. Valid slugs from list_workflow_recipes() (e.g. "reverse-engineer-unknown-protocol", "replay-with-mutation", "intercept-and-rewrite")."""
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
        """List configured forwarders with running state. Each entry: name, enabled, running, config (ForwarderConfig dict)."""
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
        """Add a forwarder from a ForwarderConfig dict (needs a unique 'name'; any ForwarderConfig field allowed). Added stopped — call start_forwarder."""
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
        """Remove a forwarder by name (stopped first if running). Captured sessions are kept."""
        if not any(f.name == name for f in api.forwarders):
            return {"ok": False, "error": f"Forwarder {name!r} not found"}
        if api.is_running(name):
            await api.stop_forwarder(name)
        api.update_forwarders([f for f in api.forwarders if f.name != name])
        return {"ok": True, "name": name}

    @mcp.tool()
    async def update_forwarder(name: str, fields: dict) -> dict:
        """Update fields on a forwarder. fields: partial ForwarderConfig dict. Network changes (host/port/transport/tls) take effect after an automatic restart; framing/protocol changes apply in-place. Use update_forwarder_config for restart-free name/framer/protocol swaps."""
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
        """Start a named forwarder (auto-loads its protocol definition if configured). name: from list_forwarders."""
        try:
            await api.start_forwarder(name)
            return {"ok": True, "name": name}
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    async def stop_forwarder(name: str) -> dict:
        """Stop a named forwarder. Its sessions close; frames are kept for inspection. name: from list_forwarders."""
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
        """List all captured sessions (metadata only: id, client/server host:port, state, timestamps). Use get_frames() for the data."""
        return [s.info.to_dict() for s in api.list_sessions()]

    @mcp.tool()
    def get_session(session_id: str) -> Optional[dict]:
        """Return one session's info dict by UUID, or None."""
        session = api.get_session(session_id)
        if session is None:
            return None
        return session.info.to_dict()

    @mcp.tool()
    def get_session_summary(session_id: str) -> Optional[dict]:
        """Return a session summary: frame/byte counts per direction, duration, first/last frame times. None if not found."""
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
        """Return all captured frames for a session (raw_bytes hex), in capture order. direction: optional "client_to_server"/"server_to_client" filter. Large for big sessions."""
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
        """Return one frame by ID (raw_bytes hex), or None."""
        session = api.get_session(session_id)
        if session is None:
            return None
        for f in session.frames:
            if f.id == frame_id:
                return f.to_dict()
        return None

    @mcp.tool()
    def decode_frames(session_id: str, direction: Optional[str] = None) -> list[dict]:
        """Decode all frames in a session with the loaded protocol decoder (passthrough/hex if none). Returns ParsedMessage dicts with fields and per-field offset/size. direction: optional filter."""
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
        """Decode one frame by ID with the loaded decoder. Returns a ParsedMessage dict, or None."""
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
        """Search frames for a binary pattern (rule syntax: "01 02 ??" wildcard, "FF [03-09]" range, "(01|02) 00" alternation). session_id/direction: optional scope (None = all). max_results: cap (default 100)."""
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
        """Force-close an active session's connections and mark it CLOSED. No-op if already closed/not found."""
        ok = await api.terminate_session(session_id)
        return {"ok": ok, "session_id": session_id}

    @mcp.tool()
    def delete_session(session_id: str) -> dict:
        """Remove a session and its frames from the registry (in-memory only; does not close the connection — call terminate_session first if active)."""
        ok = api.delete_session(session_id)
        return {"ok": ok, "session_id": session_id}

    @mcp.tool()
    def export_session(session_id: str) -> Optional[dict]:
        """Export a full session (info + all frames, raw_bytes hex) as a dict, or None. Large for big sessions."""
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
        """Return info about the loaded protocol decoder: protocol_name, has_definition, has_encoder."""
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
        """Enable/disable tamper at runtime. Disabling immediately forwards all pending frames. enabled: True/False."""
        api.tamper_enabled = enabled
        return {"tamper_enabled": api.tamper_enabled}

    @mcp.tool()
    def list_intercepted() -> list[dict]:
        """Return frames waiting in the tamper queue. Each entry has raw_bytes (hex), the unit_id for forward/drop/modify, and the current verdict."""
        return [u.to_dict() for u in api.list_intercepted()]

    @mcp.tool()
    def tamper_decode_pending() -> list[dict]:
        """Like list_intercepted but each entry also has a 'parsed' ParsedMessage (needs a loaded protocol definition). Returns dicts with 'unit' and 'parsed'."""
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
        """Forward a queued frame unchanged. unit_id: from list_intercepted."""
        ok = api.forward(unit_id)
        return {"ok": ok, "unit_id": unit_id}

    @mcp.tool()
    def tamper_drop(unit_id: str) -> dict:
        """Drop a queued frame (do not forward). unit_id: from list_intercepted."""
        ok = api.drop(unit_id)
        return {"ok": ok, "unit_id": unit_id}

    @mcp.tool()
    def tamper_modify_and_forward(unit_id: str, new_bytes_hex: str) -> dict:
        """Replace a queued frame's bytes and forward. unit_id: from list_intercepted; new_bytes_hex: replacement hex. For field edits use tamper_modify_field_and_forward."""
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
        """Re-encode a queued frame with protocol field edits and forward (needs a loaded definition; length fields recomputed). unit_id: from list_intercepted; field_edits: {field_name: new_value} (typed per definition; bytes as hex)."""
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
        """Restrict tampering to one direction. direction: "client_to_server", "server_to_client", or null to clear."""
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
        """Restrict tampering to specific sessions. session_ids: list of session UUIDs, or null to clear."""
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
        """Add a binary find-and-replace rule applied to matching frames before forwarding (rules stack in order). pattern: binary pattern ("01 02 ??", "[00-0F]"); replacement_hex: replacement bytes; direction: optional. Returns the new rule dict with its id."""
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
        """Update a replace rule's label or enabled state (null to keep). rule_id: from list_replace_rules. Returns the updated rule."""
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
        """Remove a replace rule by id."""
        ok = api.remove_replace_rule(rule_id)
        return {"ok": ok, "rule_id": rule_id}

    @mcp.tool()
    def reorder_replace_rule(rule_id: str, new_index: int) -> dict:
        """Move a replace rule in evaluation order (position 0 = first). rule_id, new_index (0-based)."""
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
        """List intercept filter rules in order. First-match wins; no rules = intercept all; rules present but none match = auto-forward."""
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
        """Add an intercept filter rule (first-match decides hold vs auto-forward). pattern: binary pattern (empty = match all); action: "intercept"/"forward"; direction/session_ids: optional. Returns the new rule dict with its id."""
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
        """Update an intercept rule's label/action/enabled (null to keep). rule_id: from list_intercept_rules. Returns the updated rule."""
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
        """Remove an intercept rule by id."""
        ok = api.remove_intercept_rule(rule_id)
        return {"ok": ok, "rule_id": rule_id}

    @mcp.tool()
    def reorder_intercept_rule(rule_id: str, new_index: int) -> dict:
        """Move an intercept rule in evaluation order (position 0 = highest priority, first match wins). rule_id, new_index (0-based)."""
        ok = api.intercept_filter.move_rule(rule_id, new_index)
        return {"ok": ok, "rule_id": rule_id, "new_index": new_index}

    @mcp.tool()
    def clear_intercept_rules() -> dict:
        """Remove all intercept rules. Default resumes: all frames intercepted when tamper is enabled."""
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
        """Send raw bytes and return the response. Modes: one-shot (default) opens host:port, sends, reads, closes; forge-session reuse (source_session_id = live forge session) sends over its socket (direction ignored); proxy-session injection (source_session_id = live proxy session) injects and collects frames for receive_timeout. When source_session_id is set, host/port/tls come from the session. data_hex: bytes; transport: tcp/udp; direction: proxy injection only. Returns sent/received hex, success, error."""
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
        """Open a persistent connection for interactive Forge sends (stays open across sends; captured in Traffic). Use send_on_forge_session to send. TCP closes when the server drops it; UDP stays until terminate_session. tls: TCP only; transport: tcp/udp. Returns session_id."""
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
        """Send bytes over a forge session opened with open_forge_session (frames captured in its log). receive_timeout defaults to connect_timeout. Returns sent/received hex, response_packets, success, error."""
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
        """Inject bytes into the upstream side of an active session (server sees them in-session; response flows back to the client and is captured). session_id: active session; data_hex: bytes."""
        try:
            data = bytes.fromhex(data_hex)
        except ValueError as exc:
            return {"ok": False, "error": f"Invalid data hex: {exc}"}

        ok = await api.inject_to_server(session_id, data)
        return {"ok": ok, "session_id": session_id}

    @mcp.tool()
    async def inject_to_client(session_id: str, data_hex: str) -> dict:
        """Inject bytes into the client side of an active session (client sees them as if from the server). session_id: active session; data_hex: bytes."""
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
        """List forge playbooks (no run history)."""
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
        """Create a playbook with a single frame. data_hex: frame bytes; tls: TCP only; source_session_id: optional inject target; response_window: seconds per frame. Returns the new playbook."""
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
        """Return a playbook including its full run history (large). playbook_id: from list_playbooks."""
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
        """Update a playbook's connection config and/or first frame's bytes (null to keep each). Returns the updated playbook."""
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
        """Delete a playbook and its run history."""
        if playbook_id not in _playbooks:
            return {"ok": False, "error": f"Playbook '{playbook_id}' not found."}
        del _playbooks[playbook_id]
        return {"ok": True, "playbook_id": playbook_id}

    @mcp.tool()
    async def run_playbook(playbook_id: str) -> dict:
        """Run all frames in a playbook and record the run. Returns the PlaybookRun (includes captured traffic)."""
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
        """Create a playbook pre-loaded with a captured frame's bytes (MCP equivalent of 'Send to Forge'). session_id, frame_id, label (optional). Returns the new playbook."""
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
        """Replay a captured session against the upstream server. server_host/server_port: overrides; frame_delay: seconds between frames; direction: replay direction; frame_selector: e.g. "0,2,4-6" (None = all); modified_frames: {frame_id: replacement_hex} byte overrides. Returns a ForgeResult. For field edits use replay_with_field_edits."""
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
        """Replay a captured session with protocol field edits (needs a loaded definition; length fields recomputed). field_edits: {message_type: {field_name: new_value}}. server_host/server_port/frame_delay/direction/frame_selector as in forge_session. Frames whose type isn't edited (or fail to encode) replay unchanged."""
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
        """Return the proxy's TLS CA certificate (PEM) to install in the client/OS trust store for TLS interception. Returns {"pem": ...}, or an error if TLS/CA is not initialised."""
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
        """Start a background fuzzing campaign and return immediately. mutators: list of {"name": ..., ...params} — see list_mutators for names and parameters (protocol-aware mutators need a loaded definition). iterations (default 50); frame_selector; stop_on_crash; server_host/server_port overrides; response_timeout. Returns campaign_id and status. Poll with fuzz_status; details via fuzz_results."""
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
        """Return a fuzzing campaign's status summary (no per-iteration detail; use fuzz_results). campaign_id: from fuzz_start."""
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
        """Return per-iteration results for a campaign (each: mutated_bytes hex, response_bytes hex, response time, reset/timeout flags, 'interesting' flag). interesting_only: only flagged results."""
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
        """Request early stop of a running campaign (finishes the current iteration). campaign_id: from fuzz_start."""
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
        """List all fuzzing campaigns with summary info (oldest first). Per-iteration detail via fuzz_results."""
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
        """Hot-swap the active framer on running sessions without restarting. framer_name: built-in key ("raw", "delimiter", "length_prefix", "line") or custom; framer_kwargs: e.g. {"delimiter": "0d0a"} (hex) or {"length_size": 2}; custom_framer_path: .py for a custom framer; forwarder_name: limit to one forwarder. See list_framers. Returns swapped_sessions count."""
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
        """Hot-swap name, framing, and/or protocol definition on a running forwarder without restarting (applies immediately to live sessions). new_name (unique); framer_name/framer_kwargs/custom_framer_path; protocol_definition_path. See list_framers. Returns renamed, sessions_reframed, protocol_set."""
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
        """Return the global variable store (name -> hex value) shared by replace rules and playbooks ({{VAR}} placeholders)."""
        return dict(api.variables)

    @mcp.tool()
    def set_variable(name: str, value_hex: str) -> dict:
        """Set a variable in the global store (used as {{VAR}} in playbooks and by script rules). name; value_hex."""
        try:
            bytes.fromhex(value_hex)
        except ValueError as exc:
            return {"ok": False, "error": f"Invalid hex value: {exc}"}
        api.variables[name] = value_hex
        return {"ok": True, "name": name, "value_hex": value_hex}

    @mcp.tool()
    def delete_variable(name: str) -> dict:
        """Remove one variable by name."""
        if name not in api.variables:
            return {"ok": False, "error": f"Variable {name!r} not found."}
        del api.variables[name]
        return {"ok": True, "name": name}

    @mcp.tool()
    def clear_variables() -> dict:
        """Clear all variables. Returns the count cleared."""
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
        """List fuzzing mutators for fuzz_start. Each: name (spec key), parameters (kwargs + defaults), requires_protocol."""
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
        """List supported field-type names for decode_field (e.g. uint16_le, float32_be, int8, ascii, cstring, bytes)."""
        return analysis.supported_field_types()

    @mcp.tool()
    def get_frame_stats(
        session_id:     str,
        direction:      Optional[str] = None,
        size_bytes:     Optional[int] = None,
        bucket_prefix_len: int        = 2,
        max_bucket_offsets: int       = 256,
    ) -> dict:
        """Per-session frame statistics: direction/size distribution, prefix buckets, and for each (prefix,size) bucket with >=3 frames, per-offset change-rate, distinct-value count, and Shannon entropy. Standard scoping params (direction, size_bytes, byte_patterns)."""
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
        """Per-offset Shannon entropy across a same-size bucket (0 = constant, ~8 = random). Standard scoping params."""
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
        """Bucket frames into candidate packet types by (first prefix_len bytes, length). Returns per-cluster count, sequence range, and a short sample hex."""
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
        """Return a filtered, paginated slice of a session's frames. Standard scoping params plus limit/cursor; returns frames, total_matching, returned, next_cursor."""
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
        """Decode raw_bytes[offset:offset+size] as type across selected frames. type: see list_field_types; standard scoping params; deduplicate: emit a row only when the value changes (surfaces state transitions cheaply); include_timestamps: add per-row timestamp. Returns rows, total_returned, truncated."""
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
        """Byte-level diff of two frames: coalesced differing ranges (with integer delta where applicable), common prefix/suffix lengths, and a 16-byte-row side-by-side hex view. frame_a_id, frame_b_id."""
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
        """Column-by-column diff matrix across same-size selected frames, most-varying offset first; each column is one byte per frame, hex-concatenated. Standard scoping params; max_offsets cap."""
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
        """Per-offset and per-varying-range heuristics over a same-size bucket: candidate numeric types with min/max/distinct, and looks_like_length / looks_like_counter / looks_like_ascii_run flags. Standard scoping params."""
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
        """Find (offset, width, byteorder) whose integer value equals len(frame) - C for a constant C across all frames. Works across mixed sizes — call on the whole session."""
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
        """Check whether two offsets co-vary (Pearson r and change_pairing). offset_a/offset_b, type_a/type_b; standard scoping params."""
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
        """Find byte n-grams present in >= min_coverage of selected frames regardless of offset (magic markers, version stamps, trailers). min_length/max_length, max_results."""
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
        """Needleman-Wunsch alignment of mixed-size frames against the first selected frame. Returns aligned rows (hex, '--' for gaps), a consensus row, and variable regions. max_frames/max_frame_size caps."""
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
        """Printable-ASCII runs (>= min_length) per frame, with frame_id and offset. include_utf16_le: also Windows-style UTF-16. max_per_frame cap."""
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
        """Try Type-Length-Value layouts (type_width 1/2, length_width 1/2/4, BE/LE, length-includes-header or value-only) at start_offsets; report shapes that consume whole frames as record chains, with common type values. min_records, min_coverage, max_results."""
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
        """Try sum8/xor8/sum16/fletcher16/crc16_ccitt/crc16_xmodem/crc32_ieee/adler32 (both endiannesses) at each plausible offset, computed over the frame excluding the candidate field. min_coverage, max_results."""
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
        """For each (offset, width 4/8, byteorder), count frames whose decoded value falls in a known epoch (unix_seconds/ms, ntp_seconds, windows_filetime) and report Pearson correlation with capture time (disambiguates LE vs BE). min_coverage, max_results."""
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
        """Per-frame: known magic signatures (gzip, zlib, zstd, ZIP, PNG, ELF, TLS, ...) and sliding-window high-entropy regions (>= high_entropy_min over window_size bytes). window_step, max_per_frame."""
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
        """Find values sent at src_offset that reappear at a fixed dst_offset in the opposite direction within max_distance frames (transaction-ID / token pattern). widths (default [2,4,8]), min_coverage, max_results."""
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
        """Time series for one (byte_offset, byte_length, encoding) field: one row per frame with frame_id, timestamp, sequence_number, value. encoding: compact name (u8, i16_le, f32_le, ...)."""
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
        """Score every numeric encoding at every offset on a fixed-size bucket (float validity, high-byte stability, smoothness/monotonicity) — the fast first pass for finding numeric fields. size_bytes (default dominant size), max_sample, top_n, encodings. Returns ranked candidates."""
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
        """Bucket frames by the concatenated value across one or more (offset, length) ranges; returns per-bucket counts and {key_hex: [frame_ids]} (co-occurrence / join distribution). ranges, max_ids_per_bucket."""
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
        """Per-byte diff of two frames plus, given field_decls of (offset, length, encoding), the decoded delta per field — 'what changed between these two frames?'. frame_a, frame_b, max_diff_bytes cap."""
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
        """Confirm a field by experiment: over a live forge session, sweep a (byte_offset, byte_length, encoding) field across values (a list or {start, stop, step}), replay the base frame for each, and return {candidate_value: response_hex}. Counterpart to replay_with_field_edits."""
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
        """Flatten a session to CSV (one row per frame, one column per declared field plus frame_id/timestamp/sequence_number/direction/size) for external analysis. fields: list of {name, byte_offset, byte_length, encoding, optional message_filter}. Cells blank where a frame is too short or fails its filter. Returns columns and the csv string (large)."""
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
        """Group frames by (prefix, size) and report per-bucket mean/std/coefficient-of-variation of inter-arrival times and an is_periodic flag (heartbeats, pings, keepalives). bucket_prefix_len, cv_threshold, min_count."""
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
        """Return the active ProtocolDefinition as a YAML-compatible dict (the shape the loader accepts), or {"error": ...} if no definition is loaded."""
        from protopoke.protocol.definition import protocol_to_dict
        from protopoke.protocol.parser import DefinitionBasedDecoder
        if not isinstance(api._decoder, DefinitionBasedDecoder):
            return {"error": "No protocol definition is loaded."}
        return protocol_to_dict(api._decoder._def)

    @mcp.tool()
    def get_protocol_definition_schema() -> dict:
        """Return the authoritative YAML schema for ProtocolDefinition files (content: markdown spec, uri: resource URI, workflow: hand-off summary). The MCP layer cannot save definitions — emit YAML in chat for the operator to load."""
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
        """Return knowledge-base findings, optionally filtered. Read on session start to recover prior work. query (title/description/tags substring), status (hypothesis/confirmed/ruled_out/needs_review), author ("ai"/"user"), protocol_name/message_name/field_name/forwarder_id scope, tags."""
        results = api.knowledge.list_findings(
            query=query, status=status, author=author,
            protocol_name=protocol_name, message_name=message_name,
            field_name=field_name, forwarder_id=forwarder_id, tags=tags,
        )
        return [_serialise_finding(f) for f in results]

    @mcp.tool()
    def get_finding(finding_id: str) -> dict:
        """Return one finding by id, or None."""
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
        """Record a concrete, scoped, evidence-backed protocol claim (a field's meaning, a layout, a length/CRC relationship); use add_note for broad context. status: hypothesis until evidenced, then confirmed/ruled_out (or needs_review); confidence: low/medium/high; scope as tightly as you can (protocol_name/message_name/field_name/byte_offset/byte_length/direction/forwarder_id); evidence_frame_ids / counter_evidence_frame_ids; tags. Authored 'ai', unlocked."""
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
        """Update fields of an AI-authored, unlocked finding (refused on user-authored or locked entries — add a counter-finding instead). finding_id plus any field from add_finding."""
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
        """Remove an AI-authored, unlocked finding by id (refused on user-authored or locked)."""
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
        """Return free-form knowledge-base notes, optionally filtered. query (title/body/tags substring), author, tags."""
        return [n.to_dict() for n in api.knowledge.list_notes(
            query=query, author=author, tags=tags,
        )]

    @mcp.tool()
    def get_note(note_id: str) -> dict:
        """Return one note by id, or None."""
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
        """Record a free-form note for cross-cutting context that doesn't fit one field/message (open questions, test-setup, overall hypotheses); use add_finding for scoped claims. body_md: markdown; tags. Authored 'ai', unlocked."""
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
        """Update an AI-authored, unlocked note (refused on user-authored or locked). note_id; title/body_md/tags."""
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
        """Remove an AI-authored, unlocked note by id (refused on user-authored or locked)."""
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
