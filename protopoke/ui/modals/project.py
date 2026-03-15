"""Project management modals: New, Open, Save As."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static
from textual.containers import Horizontal, Vertical


class NewProjectModal(ModalScreen[str | None]):
    """
    Modal dialog to create a new project.

    Dismisses with the project name string, or None if cancelled.
    """

    DEFAULT_CSS = """
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
    Modal dialog to open an existing project file or legacy directory.

    Dismisses with the path string, or None if cancelled.
    """

    DEFAULT_CSS = """
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
    OpenProjectModal Input {
        margin-bottom: 1;
    }
    OpenProjectModal .hint {
        color: $text-muted;
        margin-bottom: 1;
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
            yield Label("Path to .protopoke file (or legacy directory):")
            yield Input(placeholder="/path/to/capture.protopoke", id="project-path")
            yield Static("Tip: Tab-complete doesn't work here — paste the full path.", classes="hint")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Open", variant="primary", id="btn-open")

    def on_mount(self) -> None:
        self.query_one("#project-path", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-open":
            path = self.query_one("#project-path", Input).value.strip()
            self.dismiss(path or None)
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        path = event.value.strip()
        self.dismiss(path or None)


class SaveAsModal(ModalScreen[str | None]):
    """
    Modal dialog to choose where to save the project.

    Dismisses with the path string, or None if cancelled.
    """

    DEFAULT_CSS = """
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
    SaveAsModal Input {
        margin-bottom: 1;
    }
    SaveAsModal .hint {
        color: $text-muted;
        margin-bottom: 1;
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
            yield Label("Destination path (.protopoke file):")
            yield Input(value=self._default_path, placeholder="~/captures/session1.protopoke", id="save-path")
            yield Static("The project is saved as a single ZIP file (.protopoke).", classes="hint")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Save", variant="primary", id="btn-save")

    def on_mount(self) -> None:
        self.query_one("#save-path", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            path = self.query_one("#save-path", Input).value.strip()
            self.dismiss(path or None)
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        path = event.value.strip()
        self.dismiss(path or None)
