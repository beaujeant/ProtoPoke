"""NoteEditModal — create or edit a knowledge-base Note."""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static, Switch, TextArea

from ...knowledge import Note


def _csv_list(s: str) -> list[str]:
    return [p.strip() for p in s.split(",") if p.strip()]


class NoteEditModal(ModalScreen[Optional[Note]]):
    """
    Create or edit a free-form Note.

    Mirrors :class:`FindingEditModal` — new entries are created as
    ``author="user", locked=True``; existing entries become locked on
    save so the AI cannot subsequently modify them via MCP.
    """

    DEFAULT_CSS = """
    NoteEditModal > Vertical {
        width: 80;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    NoteEditModal Label {
        margin-top: 1;
    }
    NoteEditModal #body {
        height: 16;
    }
    NoteEditModal .buttons {
        height: 3;
        margin-top: 2;
        align: right middle;
    }
    NoteEditModal Button {
        margin-left: 1;
        padding: 0 0;
    }
    NoteEditModal #validation-msg {
        color: $error;
        height: 1;
    }
    NoteEditModal .hint {
        color: $text-muted;
    }
    """

    def __init__(self, existing: Optional[Note] = None) -> None:
        super().__init__()
        self._existing = existing

    def compose(self) -> ComposeResult:
        ex = self._existing
        title = "Edit Note" if ex else "New Note"
        with Vertical():
            yield Label(title, classes="modal-title")

            yield Label("Title:")
            yield Input(value=ex.title if ex else "", id="title")

            yield Label("Body (markdown):")
            yield TextArea(ex.body_md if ex else "", id="body")

            yield Label("Tags (comma-separated):")
            yield Input(value=", ".join(ex.tags) if ex else "", id="tags")

            if ex:
                with Horizontal():
                    yield Label("Locked:")
                    yield Switch(value=ex.locked, id="locked")
                yield Static(
                    f"Author: {ex.author}.  Saving will lock this note — "
                    f"the AI will no longer modify it via MCP.",
                    classes="hint",
                )

            yield Static("", id="validation-msg")

            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Save",   variant="primary", id="btn-save")

    def on_mount(self) -> None:
        self.query_one("#title", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
        else:
            self._try_save()

    def _try_save(self) -> None:
        title   = self.query_one("#title", Input).value.strip()
        if not title:
            self.query_one("#validation-msg", Static).update("Title is required.")
            return
        body_md = self.query_one("#body", TextArea).text
        tags    = _csv_list(self.query_one("#tags", Input).value)

        if self._existing:
            ex = self._existing
            ex.title = title
            ex.body_md = body_md
            ex.tags = tags
            ex.locked = bool(self.query_one("#locked", Switch).value)
            self.dismiss(ex)
            return

        new_note = Note.create(title=title, body_md=body_md,
                               author="user", locked=True, tags=tags)
        self.dismiss(new_note)
