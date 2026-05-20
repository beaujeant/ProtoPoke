"""FilePickerModal — a textual-native file browser dialog."""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Input, Label
from textual.containers import Horizontal, Vertical


class FilePickerModal(ModalScreen[str | None]):
    """
    Modal file browser using Textual's DirectoryTree.

    Dismisses with the selected file path (str) on confirmation,
    or ``None`` if the user cancels.
    """

    DEFAULT_CSS = """
    FilePickerModal {
        align: center middle;
    }
    FilePickerModal > Vertical {
        width: 80;
        height: 30;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    FilePickerModal .modal-title {
        text-style: bold;
        margin-bottom: 1;
        color: $text;
    }
    FilePickerModal DirectoryTree {
        height: 1fr;
        border: solid $primary-darken-2;
    }
    FilePickerModal .path-row {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    FilePickerModal .path-label {
        width: 8;
        padding: 0 1;
    }
    FilePickerModal #selected-path {
        width: 1fr;
    }
    FilePickerModal .buttons {
        height: 3;
        margin-top: 1;
        align: right middle;
    }
    FilePickerModal Button {
        margin-left: 1;
    }
    """

    def __init__(self, start_path: str | None = None) -> None:
        super().__init__()
        if start_path:
            p = Path(start_path).expanduser()
            # If given a file, start in its parent directory
            self._start_dir = str(p.parent if p.is_file() else p)
            self._initial_value = str(p) if p.is_file() else ""
        else:
            self._start_dir = str(Path.home())
            self._initial_value = ""

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Browse for file", classes="modal-title")
            yield DirectoryTree(self._start_dir, id="file-tree")
            with Horizontal(classes="path-row"):
                yield Label("Path:", classes="path-label")
                yield Input(
                    value=self._initial_value,
                    id="selected-path",
                    placeholder="Select a file above…",
                )
            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("OK", variant="primary", id="btn-ok")

    def on_directory_tree_file_selected(
        self, event: DirectoryTree.FileSelected
    ) -> None:
        """Populate the path input when the user clicks a file."""
        self.query_one("#selected-path", Input).value = str(event.path)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-ok":
            path = self.query_one("#selected-path", Input).value.strip()
            self.dismiss(path if path else None)
        else:
            self.dismiss(None)

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)
