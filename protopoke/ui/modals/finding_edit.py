"""FindingEditModal — create or edit a knowledge-base Finding."""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Static, Switch, TextArea

from ...config import ForwarderConfig
from ...knowledge import Finding
from ...knowledge.models import FINDING_CONFIDENCE, FINDING_STATUSES


_STATUS_OPTIONS = [(s, s) for s in FINDING_STATUSES]
_CONFIDENCE_OPTIONS = [(c, c) for c in FINDING_CONFIDENCE]
_DIRECTION_OPTIONS = [
    ("(both directions)",  ""),
    ("Client → Server",    "client_to_server"),
    ("Server → Client",    "server_to_client"),
]


def _int_or_none(s: str) -> Optional[int]:
    s = s.strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def _csv_list(s: str) -> list[str]:
    return [p.strip() for p in s.split(",") if p.strip()]


class FindingEditModal(ModalScreen[Optional[Finding]]):
    """
    Create or edit a Finding.

    Dismisses with the new/updated Finding, or ``None`` if cancelled.
    Saving from this modal sets ``author="user"`` and ``locked=True`` on
    new entries; for existing entries, the author is preserved but
    ``locked`` becomes True (the user has now taken ownership and the
    AI may no longer mutate it via MCP).
    """

    DEFAULT_CSS = """
    FindingEditModal > Vertical {
        width: 90;
        height: auto;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    FindingEditModal Label {
        margin-top: 1;
    }
    FindingEditModal .row {
        height: auto;
    }
    FindingEditModal .row Select {
        width: 22;
        margin-right: 2;
    }
    FindingEditModal #desc {
        height: 8;
    }
    FindingEditModal .buttons {
        height: 3;
        margin-top: 2;
        align: right middle;
    }
    FindingEditModal Button {
        margin-left: 1;
        padding: 0 0;
    }
    FindingEditModal #validation-msg {
        color: $error;
        height: 1;
    }
    FindingEditModal .hint {
        color: $text-muted;
    }
    """

    def __init__(
        self,
        existing:   Optional[Finding] = None,
        forwarders: Optional[list[ForwarderConfig]] = None,
    ) -> None:
        super().__init__()
        self._existing = existing
        self._forwarders = forwarders or []

    def compose(self) -> ComposeResult:
        ex = self._existing
        title = "Edit Finding" if ex else "New Finding"

        fwd_options = [("(none)", "")] + [(f.name, f.id) for f in self._forwarders]
        current_fwd = ex.forwarder_id if (ex and ex.forwarder_id) else ""

        with Vertical():
            yield Label(title, classes="modal-title")

            yield Label("Title:")
            yield Input(value=ex.title if ex else "",
                        placeholder="e.g. bytes 4-5 look like a CRC16",
                        id="title")

            yield Label("Description (markdown):")
            yield TextArea(ex.description if ex else "", id="desc")

            with Horizontal(classes="row"):
                yield Label("Status:")
                yield Select(_STATUS_OPTIONS,
                             value=ex.status if ex else "hypothesis",
                             id="status", allow_blank=False)
                yield Label("Confidence:")
                yield Select(_CONFIDENCE_OPTIONS,
                             value=ex.confidence if ex else "medium",
                             id="confidence", allow_blank=False)

            yield Label("Scope")
            with Horizontal(classes="row"):
                yield Label("Protocol:")
                yield Input(value=(ex.protocol_name or "") if ex else "",
                            placeholder="(optional)", id="protocol-name")
                yield Label("Message:")
                yield Input(value=(ex.message_name or "") if ex else "",
                            placeholder="(optional)", id="message-name")

            with Horizontal(classes="row"):
                yield Label("Field:")
                yield Input(value=(ex.field_name or "") if ex else "",
                            placeholder="(optional)", id="field-name")
                yield Label("Byte offset:")
                yield Input(
                    value=str(ex.byte_offset) if (ex and ex.byte_offset is not None) else "",
                    placeholder="(opt)", id="byte-offset",
                )
                yield Label("Length:")
                yield Input(
                    value=str(ex.byte_length) if (ex and ex.byte_length is not None) else "",
                    placeholder="(opt)", id="byte-length",
                )

            with Horizontal(classes="row"):
                yield Label("Direction:")
                yield Select(
                    _DIRECTION_OPTIONS,
                    value=(ex.direction.value if (ex and ex.direction) else ""),
                    id="direction", allow_blank=False,
                )
                yield Label("Forwarder:")
                yield Select(fwd_options, value=current_fwd,
                             id="forwarder", allow_blank=False)

            yield Label("Evidence frame IDs (comma-separated):")
            yield Input(
                value=", ".join(ex.evidence_frame_ids) if ex else "",
                id="evidence-ids",
            )

            yield Label("Counter-evidence frame IDs (comma-separated):")
            yield Input(
                value=", ".join(ex.counter_evidence_frame_ids) if ex else "",
                id="counter-evidence-ids",
            )

            yield Label("Tags (comma-separated):")
            yield Input(value=", ".join(ex.tags) if ex else "", id="tags")

            if ex:
                with Horizontal(classes="row"):
                    yield Label("Locked:")
                    yield Switch(value=ex.locked, id="locked")
                yield Static(
                    f"Author: {ex.author}.  Saving will lock this entry — "
                    f"the AI will no longer be able to modify it via MCP.",
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
        title = self.query_one("#title", Input).value.strip()
        if not title:
            self.query_one("#validation-msg", Static).update("Title is required.")
            return

        description = self.query_one("#desc", TextArea).text
        status      = str(self.query_one("#status", Select).value)
        confidence  = str(self.query_one("#confidence", Select).value)
        protocol_name = self.query_one("#protocol-name", Input).value.strip() or None
        message_name  = self.query_one("#message-name", Input).value.strip() or None
        field_name    = self.query_one("#field-name", Input).value.strip() or None
        byte_offset   = _int_or_none(self.query_one("#byte-offset", Input).value)
        byte_length   = _int_or_none(self.query_one("#byte-length", Input).value)
        direction_val = str(self.query_one("#direction", Select).value)
        direction     = direction_val or None
        forwarder_val = str(self.query_one("#forwarder", Select).value)
        forwarder_id  = forwarder_val or None
        evidence_ids  = _csv_list(self.query_one("#evidence-ids", Input).value)
        counter_ids   = _csv_list(self.query_one("#counter-evidence-ids", Input).value)
        tags          = _csv_list(self.query_one("#tags", Input).value)

        if self._existing:
            ex = self._existing
            ex.title       = title
            ex.description = description
            ex.status      = status
            ex.confidence  = confidence
            ex.protocol_name = protocol_name
            ex.message_name  = message_name
            ex.field_name    = field_name
            ex.byte_offset   = byte_offset
            ex.byte_length   = byte_length
            from ...models import Direction
            ex.direction = Direction(direction) if direction else None
            ex.forwarder_id = forwarder_id
            ex.evidence_frame_ids = evidence_ids
            ex.counter_evidence_frame_ids = counter_ids
            ex.tags = tags
            ex.locked = bool(self.query_one("#locked", Switch).value)
            self.dismiss(ex)
            return

        try:
            new_finding = Finding.create(
                title=title, description=description,
                status=status, confidence=confidence, author="user", locked=True,
                protocol_name=protocol_name, message_name=message_name,
                field_name=field_name, byte_offset=byte_offset,
                byte_length=byte_length, direction=direction,
                forwarder_id=forwarder_id,
                evidence_frame_ids=evidence_ids,
                counter_evidence_frame_ids=counter_ids,
                tags=tags,
            )
        except ValueError as exc:
            self.query_one("#validation-msg", Static).update(str(exc))
            return
        self.dismiss(new_finding)
