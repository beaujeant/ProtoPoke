"""CopyFrameModal — pick a target playbook to copy a frame into."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Static
from textual.containers import Horizontal, Vertical


class CopyFrameModal(ModalScreen[str | None]):
    """
    Modal listing playbooks so the user can pick one as the copy target.

    Dismisses with the chosen playbook **id**, or ``None`` if cancelled.
    """

    DEFAULT_CSS = """
    CopyFrameModal {
        align: center middle;
    }
    CopyFrameModal > Vertical {
        width: 70;
        height: auto;
        max-height: 80%;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    CopyFrameModal .modal-title {
        text-style: bold;
        margin-bottom: 1;
    }
    CopyFrameModal DataTable {
        height: auto;
        max-height: 16;
        margin-bottom: 1;
    }
    CopyFrameModal .buttons {
        height: 3;
        margin-top: 1;
        align: right middle;
    }
    CopyFrameModal Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        playbooks: list[tuple[str, str, str, int, int]],
        # Each tuple: (id, label, host, port, frame_count)
    ) -> None:
        super().__init__()
        self._playbooks = playbooks
        self._selected_id: str | None = None

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("Copy frame to playbook", classes="modal-title")
            yield DataTable(id="target-table", cursor_type="row")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Copy",   variant="primary", id="btn-copy")

    def on_mount(self) -> None:
        dt = self.query_one("#target-table", DataTable)
        dt.add_column("Name",   key="name")
        dt.add_column("Host",   key="host")
        dt.add_column("Port",   key="port")
        dt.add_column("Frames", key="frames")
        for pb_id, label, host, port, frame_count in self._playbooks:
            dt.add_row(
                label,
                host or "—",
                str(port) if port else "—",
                str(frame_count),
                key=pb_id,
            )
        if self._playbooks:
            self._selected_id = self._playbooks[0][0]
        dt.focus()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key and event.row_key.value:
            self._selected_id = event.row_key.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == "btn-copy" and self._selected_id:
            self.dismiss(self._selected_id)
        else:
            self.dismiss(None)

    def on_key(self, event) -> None:
        if event.key == "enter" and self._selected_id:
            self.dismiss(self._selected_id)
        elif event.key == "escape":
            self.dismiss(None)
