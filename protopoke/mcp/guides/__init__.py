"""Authoring guides shipped with the MCP server as readable resources.

Each guide is a self-contained Markdown document teaching an AI client how
to write a particular extension point of ProtoPoke (framers, protocol
definitions, custom replace scripts). They are exposed over MCP as
``protopoke://guides/<name>`` resources by
:func:`protopoke.mcp.server.build_mcp_server`, so any connected client can
fetch them on demand without local file access.

The Markdown files are package data; they are loaded via
``importlib.resources`` so they keep working when ProtoPoke is installed
from a wheel.
"""

from __future__ import annotations

from importlib import resources
from typing import Dict


# slug -> (filename, human title, short description)
GUIDES: Dict[str, tuple[str, str, str]] = {
    "framers": (
        "framers.md",
        "Authoring a Framer",
        "How to choose a built-in framer or write a custom Python framer "
        "script that cuts a TCP byte stream into frames.",
    ),
    "protocol-definitions": (
        "protocol_definitions.md",
        "Authoring a Protocol Definition",
        "YAML/JSON schema for describing message types, fields, match "
        "strategies, and length expressions so ProtoPoke can decode frames.",
    ),
    "replace-scripts": (
        "replace_scripts.md",
        "Authoring a Custom Replace Script",
        "How to write the apply(data, variables) function used by script "
        "replace rules to transform frames and share state across the session.",
    ),
}


def load_guide(slug: str) -> str:
    """Return the markdown body of the guide identified by *slug*.

    Raises:
        KeyError: if *slug* is not a known guide.
    """
    filename, _, _ = GUIDES[slug]
    return resources.files(__name__).joinpath(filename).read_text(encoding="utf-8")


def build_index() -> str:
    """Render a small markdown index listing every guide and its URI.

    Used as the body of the ``protopoke://guides`` resource so clients with
    only tool access (no resource browser) can still discover the guides
    via ``get_authoring_guide("index")``.
    """
    lines = [
        "# ProtoPoke Authoring Guides",
        "",
        "These guides teach an AI client how to extend ProtoPoke. Fetch "
        "each one as an MCP resource at the URI below, or call the "
        "`get_authoring_guide` tool with the matching slug.",
        "",
    ]
    for slug, (_, title, description) in GUIDES.items():
        lines.append(f"- **{title}** — `protopoke://guides/{slug}` "
                     f"(slug: `{slug}`)")
        lines.append(f"  {description}")
    lines.append("")
    return "\n".join(lines)


__all__ = ["GUIDES", "load_guide", "build_index"]
