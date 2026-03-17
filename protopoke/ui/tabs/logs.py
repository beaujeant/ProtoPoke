"""LogsTab — read-only application log viewer with level filter."""

from __future__ import annotations

import logging
from collections import deque
from typing import Deque

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, Select, Static
from textual.containers import Horizontal, Vertical

import time as _time


# ---------------------------------------------------------------------------
# In-memory log handler
# ---------------------------------------------------------------------------

_MAX_RECORDS = 2000

_LEVEL_COLORS = {
    logging.DEBUG:    "dim",
    logging.INFO:     "green",
    logging.WARNING:  "yellow",
    logging.ERROR:    "red",
    logging.CRITICAL: "bold red",
}


class _UILogHandler(logging.Handler):
    """Stores log records in a deque and optionally notifies a callback."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self._records: Deque[logging.LogRecord] = deque(maxlen=_MAX_RECORDS)
        self._tab: "LogsTab | None" = None

    def emit(self, record: logging.LogRecord) -> None:
        self._records.append(record)
        if self._tab is not None:
            self._tab.call_from_thread(self._tab._append_record, record)

    def attach(self, tab: "LogsTab") -> None:
        self._tab = tab

    def detach(self) -> None:
        self._tab = None

    @property
    def records(self) -> list[logging.LogRecord]:
        return list(self._records)


# Singleton handler — installed once at module import time so no records are
# missed regardless of when the tab is first mounted.
_handler = _UILogHandler()
_handler.setFormatter(logging.Formatter("%(message)s"))
logging.getLogger().addHandler(_handler)


# ---------------------------------------------------------------------------
# Filter options
# ---------------------------------------------------------------------------

_LEVEL_OPTIONS: list[tuple[str, str]] = [
    ("All levels", "ALL"),
    ("DEBUG",      "DEBUG"),
    ("INFO",       "INFO"),
    ("WARNING",    "WARNING"),
    ("ERROR",      "ERROR"),
    ("CRITICAL",   "CRITICAL"),
]


# ---------------------------------------------------------------------------
# LogsTab widget
# ---------------------------------------------------------------------------

class LogsTab(Widget):
    """
    Tab 6 — Application log viewer.

    Layout (vertical):
      ┌─────────────────────────────────────────┐
      │ Toolbar: title + level filter dropdown  │
      ├─────────────────────────────────────────┤
      │ Log records (DataTable, read-only)      │
      └─────────────────────────────────────────┘
    """

    DEFAULT_CSS = """
    LogsTab {
        layout: vertical;
    }
    LogsTab .toolbar {
        height: 3;
        background: $primary-darken-2;
        align: left middle;
        padding: 0 1;
    }
    LogsTab .toolbar Static {
        height: 100%;
        color: $text;
        text-style: bold;
        content-align-horizontal: left;
        content-align-vertical: middle;
        width: 1fr;
    }
    LogsTab .toolbar Select {
        width: 22;
        height: 3;
    }
    LogsTab DataTable {
        height: 1fr;
    }
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._level_filter: int | None = None   # None = show all

    def compose(self) -> ComposeResult:
        with Horizontal(classes="toolbar"):
            yield Static("  Logs")
            yield Select(
                options=_LEVEL_OPTIONS,
                value="ALL",
                id="level-filter",
                allow_blank=False,
            )
        yield DataTable(id="logs-table", cursor_type="row")

    def on_mount(self) -> None:
        dt = self.query_one("#logs-table", DataTable)
        dt.add_column("Time",    key="time",    width=10)
        dt.add_column("Level",   key="level",   width=10)
        dt.add_column("Logger",  key="logger",  width=22)
        dt.add_column("Message", key="message")

        # Attach this tab to the singleton handler so future records arrive
        # via _append_record, then replay all buffered records.
        _handler.attach(self)
        for record in _handler.records:
            self._insert_record(record)

    def on_unmount(self) -> None:
        _handler.detach()

    # ------------------------------------------------------------------
    # Level filter
    # ------------------------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "level-filter":
            return
        val = str(event.value)
        if val == "ALL":
            self._level_filter = None
        else:
            self._level_filter = getattr(logging, val, None)
        self._reload_table()

    def _reload_table(self) -> None:
        dt = self.query_one("#logs-table", DataTable)
        dt.clear()
        for record in _handler.records:
            self._insert_record(record)

    # ------------------------------------------------------------------
    # Record display helpers
    # ------------------------------------------------------------------

    def _passes_filter(self, record: logging.LogRecord) -> bool:
        return self._level_filter is None or record.levelno >= self._level_filter

    def _insert_record(self, record: logging.LogRecord) -> None:
        if not self._passes_filter(record):
            return

        from rich.text import Text

        ts      = _time.strftime("%H:%M:%S", _time.localtime(record.created))
        level   = record.levelname
        logger  = record.name
        message = record.getMessage()
        if record.exc_info:
            import traceback
            message += "\n" + "".join(traceback.format_exception(*record.exc_info)).strip()

        color = _LEVEL_COLORS.get(record.levelno, "")
        level_cell = Text(level, style=color) if color else Text(level)

        dt = self.query_one("#logs-table", DataTable)
        dt.add_row(ts, level_cell, logger, message)

    def _append_record(self, record: logging.LogRecord) -> None:
        """Called from the handler (on the main thread via call_from_thread)."""
        self._insert_record(record)
        # Scroll to keep the newest record visible
        dt = self.query_one("#logs-table", DataTable)
        dt.scroll_end(animate=False)
