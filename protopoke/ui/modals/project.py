"""Project management modals: New, Open, Save As."""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static
from textual.containers import Horizontal, Vertical

from .file_picker import FilePickerModal


def _expand(path: str) -> str:
    """Expand a leading ~/ to the user's home directory."""
    return str(Path(path).expanduser())


def _expand_pp(path: str) -> str:
    """Expand ~/ and ensure the path ends with .pp."""
    p = Path(path).expanduser()
    if p.suffix.lower() != ".pp":
        p = p.with_suffix(".pp")
    return str(p)


class NewProjectModal(ModalScreen[str | None]):
    """
    Modal dialog to create a new project.

    Dismisses with the project name string, or None if cancelled.
    """

    DEFAULT_CSS = """
    NewProjectModal {
        align: center middle;
    }
    NewProjectModal > Vertical {
        width: 60;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    NewProjectModal Label {
        margin-bottom: 1;
    }
    NewProjectModal Input {
        margin-bottom: 1;
    }
    NewProjectModal .buttons {
        height: 3;
        margin-top: 1;
        align: right middle;
    }
    NewProjectModal Button {
        margin-left: 1;
        padding: 0 0;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("New Project", classes="modal-title")
            yield Label("Project name:")
            yield Input(placeholder="My Capture", id="project-name")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Create", variant="primary", id="btn-create")

    def on_mount(self) -> None:
        self.query_one("#project-name", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-create":
            name = self.query_one("#project-name", Input).value.strip() or "Untitled"
            self.dismiss(name)
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        name = event.value.strip() or "Untitled"
        self.dismiss(name)


class OpenProjectModal(ModalScreen[str | None]):
    """
    Modal dialog to open an existing project file.

    Dismisses with the path string, or None if cancelled.
    """

    DEFAULT_CSS = """
    OpenProjectModal {
        align: center middle;
    }
    OpenProjectModal > Vertical {
        width: 70;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    OpenProjectModal Label {
        margin-bottom: 1;
    }
    OpenProjectModal .field-row {
        height: 3;
        margin-bottom: 0;
        align: left middle;
    }
    OpenProjectModal .field-input {
        width: 1fr;
    }
    OpenProjectModal .btn-browse {
        width: 10;
        min-width: 10;
        margin-left: 1;
    }
    OpenProjectModal .buttons {
        height: 3;
        margin-top: 1;
        align: right middle;
    }
    OpenProjectModal Button {
        margin-left: 1;
        padding: 0 0;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Open Project", classes="modal-title")
            yield Label("Path to .pp file:")
            with Horizontal(classes="field-row"):
                yield Input(placeholder="/path/to/capture.pp", id="project-path", classes="field-input")
                yield Button("Browse", id="btn-browse", classes="btn-browse")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Open", variant="primary", id="btn-open")

    def on_mount(self) -> None:
        self.query_one("#project-path", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-browse":
            current = self.query_one("#project-path", Input).value.strip() or None
            def _on_pick(path: str | None) -> None:
                if path is not None:
                    self.query_one("#project-path", Input).value = path
            self.app.push_screen(FilePickerModal(current), _on_pick)
        elif btn_id == "btn-open":
            raw = self.query_one("#project-path", Input).value.strip()
            self.dismiss(_expand(raw) if raw else None)
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        self.dismiss(_expand(raw) if raw else None)


class SaveAsModal(ModalScreen[str | None]):
    """
    Modal dialog to choose where to save the project.

    Dismisses with the path string, or None if cancelled.
    """

    DEFAULT_CSS = """
    SaveAsModal {
        align: center middle;
    }
    SaveAsModal > Vertical {
        width: 70;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    SaveAsModal Label {
        margin-bottom: 1;
    }
    SaveAsModal .field-row {
        height: 3;
        margin-bottom: 0;
        align: left middle;
    }
    SaveAsModal .field-input {
        width: 1fr;
    }
    SaveAsModal .btn-browse {
        width: 10;
        min-width: 10;
        margin-left: 1;
    }
    SaveAsModal .hint {
        color: $text-muted;
        margin-top: 1;
    }
    SaveAsModal .buttons {
        height: 3;
        margin-top: 1;
        align: right middle;
    }
    SaveAsModal Button {
        margin-left: 1;
        padding: 0 0;
    }
    """

    def __init__(self, default_path: str = "") -> None:
        super().__init__()
        self._default_path = default_path

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Save Project As", classes="modal-title")
            yield Label("Destination path (.pp file):")
            with Horizontal(classes="field-row"):
                yield Input(
                    value=self._default_path,
                    placeholder="~/captures/session1.pp",
                    id="save-path",
                    classes="field-input",
                )
                yield Button("Browse", id="btn-browse", classes="btn-browse")
            yield Static("The project is saved as a single ZIP file (.pp).", classes="hint")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Save", variant="primary", id="btn-save")

    def on_mount(self) -> None:
        self.query_one("#save-path", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-browse":
            current = self.query_one("#save-path", Input).value.strip() or None
            def _on_pick(path: str | None) -> None:
                if path is not None:
                    self.query_one("#save-path", Input).value = path
            self.app.push_screen(FilePickerModal(current), _on_pick)
        elif btn_id == "btn-save":
            raw = self.query_one("#save-path", Input).value.strip()
            self.dismiss(_expand_pp(raw) if raw else None)
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        self.dismiss(_expand_pp(raw) if raw else None)
