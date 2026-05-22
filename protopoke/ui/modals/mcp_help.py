"""MCPHelpModal — shows the MCP endpoint URL and explains the Profile setting."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Static
from textual.containers import Vertical, VerticalScroll, Horizontal


_HELP_TEXT = """\
Enable the embedded MCP server, then register this URL with an 
MCP client (Claude Code, Cursor, mcp-inspector). Stdio-only 
clients (Claude Desktop, ChatGPT Desktop) connect through the 
`protopoke-mcp` stdio bridge.

The server runs inside this process and shares the same state 
you see in the UI, so the AI sees every session, rule, and frame
 — and vice versa.

──────────────────────────────────────────
Profile
──────────────────────────────────────────
Every tool's description and parameter schema is re-sent to the 
AI on every turn, so the exposed tool catalogue is a fixed 
per-turn token cost. The Profile setting controls how big that 
catalogue is:

Full: Exposes every tool. The AI can drive everything:
forwarders, rules, tamper/intercept, playbooks, replay,
variables, and TLS, on top of all the inspection and analysis
tools.

Analysis: A reverse-engineering subset, roughly half the 
per-turn cost. Keeps session/frame inspection, all analysis tools,
the knowledge base (findings/notes), read-only protocol-definition
tools, and the active-probe send/inject/forge tools. Drops the 
operational surface: forwarder lifecycle/config, replace &
intercept rules, the tamper queue, playbooks, replay,
variables, and TLS CA.

Tools dropped by the Analysis profile remain available to you in 
the TUI — they are just not exposed to the AI. Changing the 
profile restarts the embedded server, since the tool surface is 
fixed when the server is built.
"""


class MCPHelpModal(ModalScreen[None]):
    """Read-only modal showing the MCP URL and explaining the Profile setting."""

    DEFAULT_CSS = """
    MCPHelpModal {
        align: center middle;
    }
    MCPHelpModal > Vertical {
        width: 72;
        height: auto;
        max-height: 90%;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    MCPHelpModal .modal-title {
        text-style: bold;
        margin-bottom: 1;
    }
    MCPHelpModal #mcp-help-url {
        color: $text-accent;
        margin-bottom: 1;
    }
    MCPHelpModal #mcp-help-scroll {
        height: 1fr;
        max-height: 100%;
    }
    MCPHelpModal #mcp-help-body {
        margin-bottom: 1;
    }
    MCPHelpModal .buttons {
        height: 3;
        margin-top: 1;
        align: right middle;
    }
    """

    def __init__(self, url: str) -> None:
        super().__init__()
        self._url = url

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("MCP Server", classes="modal-title")
            with VerticalScroll(id="mcp-help-scroll"):
                yield Static(self._url, id="mcp-help-url", markup=False)
                yield Static(_HELP_TEXT, id="mcp-help-body", markup=False)
            with Horizontal(classes="buttons"):
                yield Button("Close", variant="primary", id="btn-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def on_key(self, event) -> None:
        if event.key in ("escape", "enter", "q"):
            self.dismiss(None)
