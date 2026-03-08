"""
ProjectManager — save/load a named ProtoPoke project.

A *project* is a directory with the ``.protopoke`` extension that bundles:

    project.json    — metadata (name, version, timestamps)
    config.json     — ProxyConfig serialised to JSON
    rules.json      — replace rules + intercept rules
    repeater.json   — repeater request tabs (current bytes + history)
    sessions.db     — SQLite database of captured sessions and frames

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

    # Save to disk
    pm.save_as("/tmp/capture.protopoke")

    # Later: reload
    pm2 = ProjectManager()
    state = pm2.open("/tmp/capture.protopoke")
    # state.config, state.rules_engine, state.intercept_filter,
    # state.repeater_requests, state.db_path
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..config import ProxyConfig
from ..rules.engine import RulesEngine, InterceptFilter
from ..replay.models import RepeaterRequest

# Project format version — bump when the schema changes incompatibly.
_FORMAT_VERSION = 1


@dataclass
class ProjectState:
    """
    All serialisable state for one project.

    Returned by :meth:`ProjectManager.open` so callers can unpack each piece
    and wire it into the running ProxyAPI.

    Attributes:
        config:             Proxy configuration.
        rules_engine:       Active replace rules.
        intercept_filter:   Active intercept rules.
        repeater_requests:  All repeater tabs (with history).
        db_path:            Path to the SQLite sessions database, or ``None``
                            when in-memory mode.
        name:               Human-readable project name.
    """

    config:              ProxyConfig
    rules_engine:        RulesEngine
    intercept_filter:    InterceptFilter
    repeater_requests:   list[RepeaterRequest]
    db_path:             Optional[Path]
    name:                str = "Untitled"


class ProjectManager:
    """
    Manages loading and saving of a ProtoPoke project directory.

    The manager holds *references* to the live state objects (config,
    rules_engine, intercept_filter, repeater_requests).  Callers mutate
    those objects directly; the manager only reads them when saving.

    Attributes:
        config:             The active :class:`~protopoke.config.ProxyConfig`.
        rules_engine:       The active :class:`~protopoke.rules.engine.RulesEngine`.
        intercept_filter:   The active :class:`~protopoke.rules.engine.InterceptFilter`.
        repeater_requests:  List of active :class:`~protopoke.replay.models.RepeaterRequest`.
        name:               Current project name (shown in the title bar).
        path:               Path of the on-disk project directory, or ``None``
                            for an unsaved in-memory project.
        is_dirty:           ``True`` if there are unsaved changes.
    """

    def __init__(self) -> None:
        self.config:             ProxyConfig          = ProxyConfig()
        self.rules_engine:       RulesEngine          = RulesEngine()
        self.intercept_filter:   InterceptFilter      = InterceptFilter()
        self.repeater_requests:  list[RepeaterRequest] = []
        self.name:               str                  = "Untitled"
        self.path:               Optional[Path]       = None
        self.is_dirty:           bool                 = False

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
        self.config            = ProxyConfig()
        self.rules_engine      = RulesEngine()
        self.intercept_filter  = InterceptFilter()
        self.repeater_requests = []
        self.name              = name
        self.path              = None
        self.is_dirty          = False
        self._created_at       = time.time()
        self._saved_at         = 0.0

    def open(self, path: str | Path) -> ProjectState:
        """
        Load a project from *path* (a ``.protopoke`` directory).

        Updates ``self.config``, ``self.rules_engine``, etc. in place and
        returns a :class:`ProjectState` snapshot for the caller to use.

        Args:
            path: Path to the ``.protopoke`` project directory.

        Raises:
            FileNotFoundError: Directory does not exist.
            ValueError:        ``project.json`` is missing or has wrong version.
        """
        project_dir = Path(path)
        if not project_dir.is_dir():
            raise FileNotFoundError(f"Project directory not found: {path}")

        meta_path = project_dir / "project.json"
        if not meta_path.exists():
            raise ValueError(f"Not a valid project directory (missing project.json): {path}")

        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("format_version", 1) > _FORMAT_VERSION:
            raise ValueError(
                f"Project was created with a newer version of ProtoPoke "
                f"(format_version={meta['format_version']}). Please upgrade."
            )

        # Config
        config_path = project_dir / "config.json"
        if config_path.exists():
            self.config = ProxyConfig.load(config_path)
        else:
            self.config = ProxyConfig()

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
            db_path=db_path,
            name=self.name,
        )

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
        return self._write(self.path)

    def save_as(self, path: str | Path) -> Path:
        """
        Write the current project to a (possibly new) *path* and update
        :attr:`path` to point there.

        Args:
            path: Destination ``.protopoke`` directory path.

        Returns:
            The resolved absolute path that was written.
        """
        self.path = Path(path)
        return self._write(self.path)

    def mark_dirty(self) -> None:
        """Signal that the in-memory state has changed since last save."""
        self.is_dirty = True

    # ------------------------------------------------------------------
    # Internal write helpers
    # ------------------------------------------------------------------

    def _write(self, project_dir: Path) -> Path:
        """Serialise all state to *project_dir*."""
        project_dir.mkdir(parents=True, exist_ok=True)

        now = time.time()

        # project.json
        meta = {
            "format_version": _FORMAT_VERSION,
            "name":           self.name,
            "created_at":     self._created_at,
            "saved_at":       now,
        }
        (project_dir / "project.json").write_text(
            json.dumps(meta, indent=2), encoding="utf-8"
        )

        # config.json
        self.config.save(project_dir / "config.json")

        # rules.json
        rules_data = {
            "replace":   self.rules_engine.to_list(),
            "intercept": self.intercept_filter.to_list(),
        }
        (project_dir / "rules.json").write_text(
            json.dumps(rules_data, indent=2), encoding="utf-8"
        )

        # repeater.json
        repeater_data = {
            "requests": [r.to_dict() for r in self.repeater_requests],
        }
        (project_dir / "repeater.json").write_text(
            json.dumps(repeater_data, indent=2), encoding="utf-8"
        )

        self._saved_at = now
        self.is_dirty  = False

        return project_dir.resolve()

    # ------------------------------------------------------------------
    # Convenience: SQLite backend path for this project
    # ------------------------------------------------------------------

    @property
    def db_path(self) -> Optional[Path]:
        """
        Path for the project's ``sessions.db`` file, or ``None`` if
        the project has not been saved yet (in-memory mode).
        """
        if self.path is None:
            return None
        return self.path / "sessions.db"

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        saved = f"path={self.path}" if self.path else "unsaved"
        dirty = " *" if self.is_dirty else ""
        return f"ProjectManager(name={self.name!r} {saved}{dirty})"
