"""
ProjectManager — save/load a named ProtoPoke project.

A *project* is a single ``.pp`` ZIP file that bundles:

    project.json    — metadata (name, version, timestamps)
    config.json     — ProxyConfig serialised to JSON
    rules.json      — replace rules + intercept rules
    forge.json      — playbooks (frames, runs/history, connection config)
    logs.json       — captured sessions and frames (the traffic tab content)

The file is a standard ZIP archive (no extra dependencies needed — Python's
built-in ``zipfile`` module is used).

Everything is temporary (in-memory) by default.  The UI calls
``ProjectManager.save()`` / ``save_as()`` to persist, and ``open()`` to
restore a previous session.

Usage::

    pm = ProjectManager()
    pm.new("My Capture")
    pm.config.listen_port = 9000
    pm.save_as("/tmp/capture.pp")

    pm2 = ProjectManager()
    state = pm2.open("/tmp/capture.pp")
    # state.config, state.rules_engine, state.intercept_filter,
    # state.playbooks, state.captured_sessions
"""

from __future__ import annotations

import io
import json
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..config import ProxyConfig
from ..rules.engine import RulesEngine, InterceptFilter
from ..forge.models import Playbook

# Project format version — bump when the schema changes incompatibly.
_FORMAT_VERSION = 3

# Safety limits for ZIP loading.
_ZIP_MAX_MEMBERS      = 32
_ZIP_MAX_MEMBER_BYTES = 100 * 1024 * 1024  # 100 MB


@dataclass
class ProjectState:
    """
    All serialisable state for one project.

    Returned by :meth:`ProjectManager.open` so callers can unpack each piece
    and wire it into the running ProxyAPI.

    Attributes:
        config:            Proxy configuration.
        rules_engine:      Active replace rules.
        intercept_filter:  Active intercept rules.
        playbooks:         All forge playbooks (with frames and run history).
        captured_sessions: Serialised session + frame data for the Traffic tab.
        name:              Human-readable project name.
    """

    config:            ProxyConfig
    rules_engine:      RulesEngine
    intercept_filter:  InterceptFilter
    playbooks:         list[Playbook]
    captured_sessions: list[dict]     = field(default_factory=list)
    name:              str            = "Untitled"


class ProjectManager:
    """
    Manages loading and saving of a ProtoPoke project.

    Projects are stored as a single ``.pp`` ZIP file containing
    JSON members for every piece of state.

    Attributes:
        config:            The active :class:`~protopoke.config.ProxyConfig`.
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
        self.config:            ProxyConfig       = ProxyConfig()
        self.rules_engine:      RulesEngine       = RulesEngine()
        self.intercept_filter:  InterceptFilter   = InterceptFilter()
        self.playbooks:         list[Playbook]    = []
        self.captured_sessions: list[dict]        = []
        self.name:              str               = "Untitled"
        self.path:              Optional[Path]    = None
        self.is_dirty:          bool              = False

        self._created_at: float = time.time()
        self._saved_at:   float = 0.0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def new(self, name: str = "Untitled") -> None:
        """Reset to a blank in-memory project."""
        self.config            = ProxyConfig()
        self.rules_engine      = RulesEngine()
        self.intercept_filter  = InterceptFilter()
        self.playbooks         = []
        self.captured_sessions = []
        self.name              = name
        self.path              = None
        self.is_dirty          = False
        self._created_at       = time.time()
        self._saved_at         = 0.0

    def open(self, path: str | Path) -> ProjectState:
        """
        Load a project from *path* (ZIP file or legacy directory).

        Raises:
            FileNotFoundError: Path does not exist.
            ValueError:        Project file is invalid or too new.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Project not found: {path}")

        if p.is_file():
            return self._open_zip(p)
        elif p.is_dir():
            return self._open_directory(p)
        else:
            raise FileNotFoundError(f"Project path is neither a file nor a directory: {path}")

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
            "format_version": _FORMAT_VERSION,
            "name":           self.name,
            "created_at":     self._created_at,
            "saved_at":       now,
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

        config_json = self._config_to_json()

        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("project.json", json.dumps(meta,        indent=2))
            zf.writestr("config.json",  config_json)
            zf.writestr("rules.json",   json.dumps(rules_data,  indent=2))
            zf.writestr("forge.json",   json.dumps(forge_data,  indent=2))
            zf.writestr("logs.json",    json.dumps(logs_data,   indent=2))

        self._saved_at = now
        self.is_dirty  = False
        return zip_path.resolve()

    def _config_to_json(self) -> str:
        import tempfile, os
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tmp:
            tmp_path = tmp.name
        try:
            self.config.save(Path(tmp_path))
            with open(tmp_path, encoding="utf-8") as f:
                return f.read()
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

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
            if meta.get("format_version", 1) > _FORMAT_VERSION:
                raise ValueError(
                    f"Project was created with a newer version of ProtoPoke "
                    f"(format_version={meta['format_version']}). Please upgrade."
                )

            # Config
            config_raw = _read("config.json")
            if config_raw:
                import tempfile, os
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", delete=False, encoding="utf-8"
                ) as tmp:
                    tmp.write(config_raw)
                    tmp_path = tmp.name
                try:
                    self.config = ProxyConfig.load(Path(tmp_path))
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
            else:
                self.config = ProxyConfig()

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

        self.name      = meta.get("name", zip_path.stem)
        self.path      = zip_path
        self.is_dirty  = False
        self._saved_at = meta.get("saved_at", 0.0)

        return ProjectState(
            config=self.config,
            rules_engine=self.rules_engine,
            intercept_filter=self.intercept_filter,
            playbooks=self.playbooks,
            captured_sessions=self.captured_sessions,
            name=self.name,
        )

    # ------------------------------------------------------------------
    # Internal: legacy directory-based open
    # ------------------------------------------------------------------

    def _open_directory(self, project_dir: Path) -> ProjectState:
        """Load a project from the legacy directory format."""
        meta_path = project_dir / "project.json"
        if not meta_path.exists():
            raise ValueError(
                f"Not a valid project directory (missing project.json): {project_dir}"
            )

        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("format_version", 1) > _FORMAT_VERSION:
            raise ValueError(
                f"Project was created with a newer version of ProtoPoke "
                f"(format_version={meta['format_version']}). Please upgrade."
            )

        config_path = project_dir / "config.json"
        self.config = ProxyConfig.load(config_path) if config_path.exists() else ProxyConfig()

        rules_path = project_dir / "rules.json"
        if rules_path.exists():
            rules_data = json.loads(rules_path.read_text(encoding="utf-8"))
            self.rules_engine     = RulesEngine.from_list(rules_data.get("replace", []))
            self.intercept_filter = InterceptFilter.from_list(rules_data.get("intercept", []))
        else:
            self.rules_engine     = RulesEngine()
            self.intercept_filter = InterceptFilter()

        # New forge.json format
        forge_path = project_dir / "forge.json"
        if forge_path.exists():
            forge_data = json.loads(forge_path.read_text(encoding="utf-8"))
            self.playbooks = [
                Playbook.from_dict(p) for p in forge_data.get("playbooks", [])
            ]
        else:
            self.playbooks = []

        logs_path = project_dir / "logs.json"
        if logs_path.exists():
            self.captured_sessions = json.loads(logs_path.read_text(encoding="utf-8")).get("sessions", [])
        else:
            self.captured_sessions = []

        self.name      = meta.get("name", project_dir.stem)
        self.path      = project_dir
        self.is_dirty  = False
        self._saved_at = meta.get("saved_at", 0.0)

        return ProjectState(
            config=self.config,
            rules_engine=self.rules_engine,
            intercept_filter=self.intercept_filter,
            playbooks=self.playbooks,
            captured_sessions=self.captured_sessions,
            name=self.name,
        )

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        saved = f"path={self.path}" if self.path else "unsaved"
        dirty = " *" if self.is_dirty else ""
        return f"ProjectManager(name={self.name!r} {saved}{dirty})"
