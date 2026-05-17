"""
ProjectManager — save/load a named ProtoPoke project.

A *project* is a single ``.pp`` ZIP file that bundles:

    project.json      — metadata (name, timestamps)
    forwarders.json   — list of ForwarderConfig objects
    rules.json        — replace rules + intercept rules
    forge.json        — playbooks (frames, runs/history, connection config)
    logs.json         — captured sessions and frames (the traffic tab content)
    filters.json      — frame display filters
    mcp.json          — embedded MCP server settings
    findings.json     — knowledge-base findings (reverse-engineering memory)
    notes.json        — knowledge-base free-form notes

The file is a standard ZIP archive (no extra dependencies needed — Python's
built-in ``zipfile`` module is used).

Everything is temporary (in-memory) by default.  The UI calls
``ProjectManager.save()`` / ``save_as()`` to persist, and ``open()`` to
restore a previous session.

Usage::

    pm = ProjectManager()
    pm.new("My Capture")
    pm.forwarders[0].listen_port = 9000
    pm.save_as("/tmp/capture.pp")

    pm2 = ProjectManager()
    state = pm2.open("/tmp/capture.pp")
    # state.forwarders, state.rules_engine, state.intercept_filter,
    # state.playbooks, state.captured_sessions
"""

from __future__ import annotations

import json
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..config import ForwarderConfig
from ..filters.frame_filter import FrameDisplayFilter
from ..knowledge import KnowledgeBase
from ..mcp.host import MCPSettings
from ..rules.engine import RulesEngine, InterceptFilter
from ..forge.models import Playbook

# Safety limits for ZIP loading.
_ZIP_MAX_MEMBERS      = 32
_ZIP_MAX_MEMBER_BYTES = 100 * 1024 * 1024  # 100 MB


@dataclass
class ProjectState:
    """
    All serialisable state for one project.

    Returned by :meth:`ProjectManager.open` so callers can unpack each piece
    and wire it into the running ProtoPokeAPI.

    Attributes:
        forwarders:        List of named forwarder configurations.
        rules_engine:      Active replace rules.
        intercept_filter:  Active intercept rules.
        playbooks:         All forge playbooks (with frames and run history).
        captured_sessions: Serialised session + frame data for the Traffic tab.
        name:              Human-readable project name.
    """

    forwarders:        list[ForwarderConfig]
    rules_engine:      RulesEngine
    intercept_filter:  InterceptFilter
    playbooks:         list[Playbook]
    captured_sessions: list[dict]               = field(default_factory=list)
    name:              str                      = "Untitled"
    frame_filters:     list[FrameDisplayFilter] = field(default_factory=list)
    mcp_settings:      MCPSettings              = field(default_factory=MCPSettings)
    knowledge:         KnowledgeBase            = field(default_factory=KnowledgeBase)


class ProjectManager:
    """
    Manages loading and saving of a ProtoPoke project.

    Projects are stored as a single ``.pp`` ZIP file containing
    JSON members for every piece of state.

    Attributes:
        forwarders:        List of active :class:`~protopoke.config.ForwarderConfig` objects.
        rules_engine:      The active :class:`~protopoke.rules.engine.RulesEngine`.
        intercept_filter:  The active :class:`~protopoke.rules.engine.InterceptFilter`.
        playbooks:         List of active :class:`~protopoke.forge.models.Playbook`.
        captured_sessions: Serialised sessions+frames (set by the app before saving).
        name:              Current project name (shown in the title bar).
        path:              Path of the on-disk project file, or ``None``
                           for an unsaved in-memory project.
        is_dirty:          ``True`` if there are unsaved changes.
    """

    def __init__(self) -> None:
        self.forwarders:        list[ForwarderConfig]    = []
        self.rules_engine:      RulesEngine              = RulesEngine()
        self.intercept_filter:  InterceptFilter          = InterceptFilter()
        self.playbooks:         list[Playbook]           = []
        self.captured_sessions: list[dict]               = []
        self.frame_filters:     list[FrameDisplayFilter] = []
        self.mcp_settings:      MCPSettings              = MCPSettings()
        self.knowledge:         KnowledgeBase            = KnowledgeBase()
        self.name:              str                      = "Untitled"
        self.path:              Optional[Path]           = None
        self.is_dirty:          bool                     = False

        self._created_at: float = time.time()
        self._saved_at:   float = 0.0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def new(self, name: str = "Untitled") -> None:
        """Reset to a blank in-memory project."""
        self.forwarders        = []
        self.rules_engine      = RulesEngine()
        self.intercept_filter  = InterceptFilter()
        self.playbooks         = []
        self.captured_sessions = []
        self.frame_filters     = []
        self.mcp_settings      = MCPSettings()
        self.knowledge         = KnowledgeBase()
        self.name              = name
        self.path              = None
        self.is_dirty          = False
        self._created_at       = time.time()
        self._saved_at         = 0.0

    def open(self, path: str | Path) -> ProjectState:
        """
        Load a project from *path* (a ``.pp`` ZIP file).

        Raises:
            FileNotFoundError: Path does not exist.
            ValueError:        Project file is invalid.
        """
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Project not found: {path}")
        return self._open_zip(p)

    def save(self) -> Path:
        """Write the current project to :attr:`path`."""
        if self.path is None:
            raise RuntimeError(
                "No project path set. Use save_as(path) to choose a location."
            )
        return self._write_zip(self.path)

    def save_as(self, path: str | Path) -> Path:
        """Write the current project to *path* and update :attr:`path`."""
        self.path = Path(path)
        return self._write_zip(self.path)

    def mark_dirty(self) -> None:
        """Signal that the in-memory state has changed since last save."""
        self.is_dirty = True

    # ------------------------------------------------------------------
    # Internal: ZIP-based write
    # ------------------------------------------------------------------

    def _write_zip(self, zip_path: Path) -> Path:
        zip_path.parent.mkdir(parents=True, exist_ok=True)
        now = time.time()

        meta = {
            "name":       self.name,
            "created_at": self._created_at,
            "saved_at":   now,
        }

        rules_data = {
            "replace":   self.rules_engine.to_list(),
            "intercept": self.intercept_filter.to_list(),
        }

        forge_data = {
            "playbooks": [p.to_dict() for p in self.playbooks],
        }

        logs_data = {
            "sessions": self.captured_sessions,
        }

        forwarders_data = {"forwarders": [f.to_dict() for f in self.forwarders]}

        filters_data = {"filters": [f.to_dict() for f in self.frame_filters]}

        mcp_data = self.mcp_settings.to_dict()

        findings_data = {"findings": [f.to_dict() for f in self.knowledge.findings]}
        notes_data    = {"notes":    [n.to_dict() for n in self.knowledge.notes]}

        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("project.json",    json.dumps(meta,             indent=2))
            zf.writestr("forwarders.json", json.dumps(forwarders_data,  indent=2))
            zf.writestr("rules.json",      json.dumps(rules_data,       indent=2))
            zf.writestr("forge.json",      json.dumps(forge_data,       indent=2))
            zf.writestr("logs.json",       json.dumps(logs_data,        indent=2))
            zf.writestr("filters.json",    json.dumps(filters_data,     indent=2))
            zf.writestr("mcp.json",        json.dumps(mcp_data,         indent=2))
            zf.writestr("findings.json",   json.dumps(findings_data,    indent=2))
            zf.writestr("notes.json",      json.dumps(notes_data,       indent=2))

        self._saved_at = now
        self.is_dirty  = False
        return zip_path.resolve()

    # ------------------------------------------------------------------
    # Internal: ZIP-based open
    # ------------------------------------------------------------------

    def _open_zip(self, zip_path: Path) -> ProjectState:
        try:
            zf = zipfile.ZipFile(zip_path, "r")
        except zipfile.BadZipFile as exc:
            raise ValueError(f"Not a valid project file: {zip_path}") from exc

        with zf:
            infos = zf.infolist()

            if len(infos) > _ZIP_MAX_MEMBERS:
                raise ValueError(
                    f"Project file has too many members ({len(infos)}); "
                    f"maximum allowed is {_ZIP_MAX_MEMBERS}."
                )
            for info in infos:
                if info.file_size > _ZIP_MAX_MEMBER_BYTES:
                    raise ValueError(
                        f"Project member {info.filename!r} is too large "
                        f"({info.file_size:,} bytes uncompressed; "
                        f"limit is {_ZIP_MAX_MEMBER_BYTES:,} bytes)."
                    )

            names = {info.filename for info in infos}

            def _read(name: str) -> str | None:
                return zf.read(name).decode("utf-8") if name in names else None

            meta_raw = _read("project.json")
            if meta_raw is None:
                raise ValueError(f"Not a valid project file (missing project.json): {zip_path}")
            meta = json.loads(meta_raw)

            forwarders_raw = _read("forwarders.json")
            if forwarders_raw is None:
                raise ValueError(
                    f"Not a valid project file (missing forwarders.json): {zip_path}"
                )
            fdata = json.loads(forwarders_raw)
            self.forwarders = [
                ForwarderConfig.from_dict(fd) for fd in fdata.get("forwarders", [])
            ]
            if not self.forwarders:
                self.forwarders = [ForwarderConfig(name="Default", enabled=True)]

            # Rules
            rules_raw = _read("rules.json")
            if rules_raw:
                rules_data = json.loads(rules_raw)
                self.rules_engine     = RulesEngine.from_list(rules_data.get("replace", []))
                self.intercept_filter = InterceptFilter.from_list(rules_data.get("intercept", []))
            else:
                self.rules_engine     = RulesEngine()
                self.intercept_filter = InterceptFilter()

            # Forge playbooks
            forge_raw = _read("forge.json")
            if forge_raw:
                forge_data = json.loads(forge_raw)
                self.playbooks = [
                    Playbook.from_dict(p) for p in forge_data.get("playbooks", [])
                ]
            else:
                self.playbooks = []

            # Logs
            logs_raw = _read("logs.json")
            if logs_raw:
                self.captured_sessions = json.loads(logs_raw).get("sessions", [])
            else:
                self.captured_sessions = []

            filters_raw = _read("filters.json")
            self.frame_filters = (
                [FrameDisplayFilter.from_dict(fd)
                 for fd in json.loads(filters_raw).get("filters", [])]
                if filters_raw else []
            )

            mcp_raw = _read("mcp.json")
            self.mcp_settings = (
                MCPSettings.from_dict(json.loads(mcp_raw))
                if mcp_raw else MCPSettings()
            )

            findings_raw = _read("findings.json")
            notes_raw    = _read("notes.json")
            self.knowledge = KnowledgeBase.from_dict({
                "findings": json.loads(findings_raw).get("findings", []) if findings_raw else [],
                "notes":    json.loads(notes_raw).get("notes",    []) if notes_raw    else [],
            })

        self.name      = meta.get("name", zip_path.stem)
        self.path      = zip_path
        self.is_dirty  = False
        self._saved_at = meta.get("saved_at", 0.0)

        return ProjectState(
            forwarders=self.forwarders,
            rules_engine=self.rules_engine,
            intercept_filter=self.intercept_filter,
            playbooks=self.playbooks,
            captured_sessions=self.captured_sessions,
            name=self.name,
            frame_filters=self.frame_filters,
            mcp_settings=self.mcp_settings,
            knowledge=self.knowledge,
        )

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        saved = f"path={self.path}" if self.path else "unsaved"
        dirty = " *" if self.is_dirty else ""
        return f"ProjectManager(name={self.name!r} {saved}{dirty})"
