"""
ProjectManager — save/load a named ProtoPoke project.

A *project* is a single ``.pp`` ZIP file that bundles:

    project.json    — metadata (name, version, timestamps)
    config.json     — ProxyConfig serialised to JSON
    rules.json      — replace rules + intercept rules
    repeater.json   — repeater request tabs (current bytes + history)
    sequencer.json  — sequencer sessions (steps, variables, history)
    logs.json       — captured sessions and frames (the log tab content)

The file is a standard ZIP archive (no extra dependencies needed — Python's
built-in ``zipfile`` module is used).  Older directory-based projects are
still readable for backward compatibility.

Everything is temporary (in-memory) by default.  The UI calls
``ProjectManager.save()`` / ``save_as()`` to persist, and ``open()`` to
restore a previous session.

Usage::

    pm = ProjectManager()

    # Start with a blank in-memory project
    pm.new("My Capture")

    # Mutate state ...
    pm.config.listen_port = 9000
    pm.rules_engine.add_rule(ReplaceRule.create(...))

    # Save to disk (single ZIP file)
    pm.save_as("/tmp/capture.pp")

    # Later: reload
    pm2 = ProjectManager()
    state = pm2.open("/tmp/capture.pp")
    # state.config, state.rules_engine, state.intercept_filter,
    # state.repeater_requests, state.sequencer_sessions, state.captured_sessions
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
from ..replay.models import RepeaterRequest
from ..sequencer.models import SequencerSession

# Project format version — bump when the schema changes incompatibly.
_FORMAT_VERSION = 2

# Safety limits for ZIP loading.
# Each individual member must not expand beyond 100 MB when decompressed, and
# the archive may contain at most 32 members total.  These bounds are generous
# for any legitimate project file while guarding against decompression bombs.
_ZIP_MAX_MEMBERS      = 32
_ZIP_MAX_MEMBER_BYTES = 100 * 1024 * 1024  # 100 MB


@dataclass
class ProjectState:
    """
    All serialisable state for one project.

    Returned by :meth:`ProjectManager.open` so callers can unpack each piece
    and wire it into the running ProxyAPI.

    Attributes:
        config:              Proxy configuration.
        rules_engine:        Active replace rules.
        intercept_filter:    Active intercept rules.
        repeater_requests:   All repeater tabs (with history).
        sequencer_sessions:  All sequencer sessions (with steps, variables, history).
        captured_sessions:   Serialised session + frame data for the Logs tab.
        name:                Human-readable project name.
        db_path:             Legacy: path to the SQLite sessions database, or ``None``.
    """

    config:              ProxyConfig
    rules_engine:        RulesEngine
    intercept_filter:    InterceptFilter
    repeater_requests:   list[RepeaterRequest]
    sequencer_sessions:  list[SequencerSession]
    captured_sessions:   list[dict]       = field(default_factory=list)
    name:                str              = "Untitled"
    db_path:             Optional[Path]   = None


class ProjectManager:
    """
    Manages loading and saving of a ProtoPoke project.

    Projects are stored as a single ``.pp`` ZIP file containing
    JSON members for every piece of state.  Older directory-based projects
    are still readable (backward compat) but always saved in the new format.

    Attributes:
        config:             The active :class:`~protopoke.config.ProxyConfig`.
        rules_engine:       The active :class:`~protopoke.rules.engine.RulesEngine`.
        intercept_filter:   The active :class:`~protopoke.rules.engine.InterceptFilter`.
        repeater_requests:  List of active :class:`~protopoke.replay.models.RepeaterRequest`.
        sequencer_sessions: List of active :class:`~protopoke.sequencer.models.SequencerSession`.
        captured_sessions:  Serialised sessions+frames (set by the app before saving).
        name:               Current project name (shown in the title bar).
        path:               Path of the on-disk project file, or ``None``
                            for an unsaved in-memory project.
        is_dirty:           ``True`` if there are unsaved changes.
    """

    def __init__(self) -> None:
        self.config:              ProxyConfig            = ProxyConfig()
        self.rules_engine:        RulesEngine            = RulesEngine()
        self.intercept_filter:    InterceptFilter        = InterceptFilter()
        self.repeater_requests:   list[RepeaterRequest]  = []
        self.sequencer_sessions:  list[SequencerSession] = []
        self.captured_sessions:   list[dict]             = []
        self.name:                str                    = "Untitled"
        self.path:                Optional[Path]         = None
        self.is_dirty:            bool                   = False

        # Timestamps
        self._created_at:  float = time.time()
        self._saved_at:    float = 0.0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def new(self, name: str = "Untitled") -> None:
        """
        Reset to a blank in-memory project.

        Clears all state.  Does *not* stop a running proxy — the caller
        must do that before calling ``new()``.
        """
        self.config             = ProxyConfig()
        self.rules_engine       = RulesEngine()
        self.intercept_filter   = InterceptFilter()
        self.repeater_requests  = []
        self.sequencer_sessions = []
        self.captured_sessions  = []
        self.name               = name
        self.path               = None
        self.is_dirty           = False
        self._created_at        = time.time()
        self._saved_at          = 0.0

    def open(self, path: str | Path) -> ProjectState:
        """
        Load a project from *path*.

        Supports two formats:
        - **New format** (ZIP file): a single ``.pp`` file produced by
          :meth:`save` / :meth:`save_as`.
        - **Legacy format** (directory): the old ``.pp`` directory format.

        Updates ``self.config``, ``self.rules_engine``, etc. in place and
        returns a :class:`ProjectState` snapshot for the caller to use.

        Raises:
            FileNotFoundError: Path does not exist.
            ValueError:        Project file/directory is invalid or too new.
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
        """
        Write the current project to :attr:`path`.

        Raises:
            RuntimeError: Called on an unsaved project (use ``save_as`` first).
        """
        if self.path is None:
            raise RuntimeError(
                "No project path set. Use save_as(path) to choose a location."
            )
        return self._write_zip(self.path)

    def save_as(self, path: str | Path) -> Path:
        """
        Write the current project to a (possibly new) *path* and update
        :attr:`path` to point there.

        The result is always a single ``.pp`` ZIP file.

        Args:
            path: Destination file path (should end in ``.pp``).

        Returns:
            The resolved absolute path that was written.
        """
        self.path = Path(path)
        return self._write_zip(self.path)

    def mark_dirty(self) -> None:
        """Signal that the in-memory state has changed since last save."""
        self.is_dirty = True

    # ------------------------------------------------------------------
    # Internal: ZIP-based write
    # ------------------------------------------------------------------

    def _write_zip(self, zip_path: Path) -> Path:
        """Serialise all state into a single ZIP file at *zip_path*."""
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

        repeater_data = {
            "requests": [r.to_dict() for r in self.repeater_requests],
        }

        sequencer_data = {
            "sessions": [s.to_dict() for s in self.sequencer_sessions],
        }

        logs_data = {
            "sessions": self.captured_sessions,
        }

        # Build config JSON in-memory (ProxyConfig.save() writes to a file,
        # so we use its to_dict/json method if available, else fallback)
        config_json = self._config_to_json()

        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("project.json",  json.dumps(meta,           indent=2))
            zf.writestr("config.json",   config_json)
            zf.writestr("rules.json",    json.dumps(rules_data,     indent=2))
            zf.writestr("repeater.json", json.dumps(repeater_data,  indent=2))
            zf.writestr("sequencer.json",json.dumps(sequencer_data, indent=2))
            zf.writestr("logs.json",     json.dumps(logs_data,      indent=2))

        self._saved_at = now
        self.is_dirty  = False
        return zip_path.resolve()

    def _config_to_json(self) -> str:
        """Serialise ProxyConfig to a JSON string (without writing to disk)."""
        buf = io.StringIO()
        # ProxyConfig.save() writes to a Path; we use a tmp file approach via
        # in-memory buffer by calling the same logic as save() but capturing it.
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
        """Load a project from a ZIP file."""
        try:
            zf = zipfile.ZipFile(zip_path, "r")
        except zipfile.BadZipFile as exc:
            raise ValueError(f"Not a valid project file: {zip_path}") from exc

        with zf:
            infos = zf.infolist()

            # Guard against decompression bombs: reject archives with too many
            # members or any member whose uncompressed size exceeds the limit.
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

            # Repeater
            repeater_raw = _read("repeater.json")
            if repeater_raw:
                repeater_data = json.loads(repeater_raw)
                self.repeater_requests = [
                    RepeaterRequest.from_dict(r) for r in repeater_data.get("requests", [])
                ]
            else:
                self.repeater_requests = []

            # Sequencer
            sequencer_raw = _read("sequencer.json")
            if sequencer_raw:
                sequencer_data = json.loads(sequencer_raw)
                self.sequencer_sessions = [
                    SequencerSession.from_dict(s) for s in sequencer_data.get("sessions", [])
                ]
            else:
                self.sequencer_sessions = []

            # Logs
            logs_raw = _read("logs.json")
            if logs_raw:
                logs_data = json.loads(logs_raw)
                self.captured_sessions = logs_data.get("sessions", [])
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
            repeater_requests=self.repeater_requests,
            sequencer_sessions=self.sequencer_sessions,
            captured_sessions=self.captured_sessions,
            name=self.name,
        )

    # ------------------------------------------------------------------
    # Internal: legacy directory-based open (backward compat)
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

        # Config
        config_path = project_dir / "config.json"
        self.config = ProxyConfig.load(config_path) if config_path.exists() else ProxyConfig()

        # Rules
        rules_path = project_dir / "rules.json"
        if rules_path.exists():
            rules_data = json.loads(rules_path.read_text(encoding="utf-8"))
            self.rules_engine     = RulesEngine.from_list(rules_data.get("replace", []))
            self.intercept_filter = InterceptFilter.from_list(rules_data.get("intercept", []))
        else:
            self.rules_engine     = RulesEngine()
            self.intercept_filter = InterceptFilter()

        # Repeater
        repeater_path = project_dir / "repeater.json"
        if repeater_path.exists():
            repeater_data = json.loads(repeater_path.read_text(encoding="utf-8"))
            self.repeater_requests = [
                RepeaterRequest.from_dict(r) for r in repeater_data.get("requests", [])
            ]
        else:
            self.repeater_requests = []

        # Sequencer
        sequencer_path = project_dir / "sequencer.json"
        if sequencer_path.exists():
            sequencer_data = json.loads(sequencer_path.read_text(encoding="utf-8"))
            self.sequencer_sessions = [
                SequencerSession.from_dict(s) for s in sequencer_data.get("sessions", [])
            ]
        else:
            self.sequencer_sessions = []

        # Logs (legacy dirs may not have this)
        logs_path = project_dir / "logs.json"
        if logs_path.exists():
            logs_data = json.loads(logs_path.read_text(encoding="utf-8"))
            self.captured_sessions = logs_data.get("sessions", [])
        else:
            self.captured_sessions = []

        self.name      = meta.get("name", project_dir.stem)
        self.path      = project_dir
        self.is_dirty  = False
        self._saved_at = meta.get("saved_at", 0.0)

        db_path: Optional[Path] = None
        sessions_db = project_dir / "sessions.db"
        if sessions_db.exists():
            db_path = sessions_db

        return ProjectState(
            config=self.config,
            rules_engine=self.rules_engine,
            intercept_filter=self.intercept_filter,
            repeater_requests=self.repeater_requests,
            sequencer_sessions=self.sequencer_sessions,
            captured_sessions=self.captured_sessions,
            name=self.name,
            db_path=db_path,
        )

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @property
    def db_path(self) -> Optional[Path]:
        """Legacy: path for ``sessions.db`` (only used by directory-format projects)."""
        if self.path is None or self.path.is_file():
            return None
        return self.path / "sessions.db"

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        saved = f"path={self.path}" if self.path else "unsaved"
        dirty = " *" if self.is_dirty else ""
        return f"ProjectManager(name={self.name!r} {saved}{dirty})"
