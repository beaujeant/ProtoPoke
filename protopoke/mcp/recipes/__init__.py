"""Workflow recipes shipped with the MCP server as readable resources.

Each recipe is a self-contained Markdown document that chains several
ProtoPoke MCP tools together to accomplish an end-to-end task (reverse-
engineering an unknown protocol, replaying with mutation, intercepting
and rewriting frames). They complement the per-extension-point guides
in :mod:`protopoke.mcp.guides` by documenting **composition** rather
than individual tool semantics.

Recipes are exposed over MCP as ``protopoke://recipes/<slug>`` resources
by :func:`protopoke.mcp.server.build_mcp_server`, with a
``protopoke://recipes`` index resource and ``list_workflow_recipes`` /
``get_workflow_recipe`` tool fallbacks for clients that ignore
resources.

The Markdown files are package data; they are loaded via
``importlib.resources`` so they keep working when ProtoPoke is installed
from a wheel.
"""

from __future__ import annotations

from importlib import resources
from typing import Dict


# slug -> (filename, human title, short description)
RECIPES: Dict[str, tuple[str, str, str]] = {
    "reverse-engineer-unknown-protocol": (
        "reverse_engineer_unknown_protocol.md",
        "Reverse-engineer an Unknown Protocol",
        "Capture, cluster, and analyse traffic from an unknown binary "
        "protocol, then iteratively build a protocol definition that "
        "decodes it.",
    ),
    "replay-with-mutation": (
        "replay_with_mutation.md",
        "Replay a Session with Mutation",
        "Turn a captured session into a reusable playbook, parameterise "
        "it with variables, and run a fuzz campaign with mutators.",
    ),
    "intercept-and-rewrite": (
        "intercept_and_rewrite.md",
        "Intercept and Rewrite Frames",
        "Choose between global replace rules, intercept rules, and "
        "script rules, and wire each one up end to end.",
    ),
}


def load_recipe(slug: str) -> str:
    """Return the markdown body of the recipe identified by *slug*.

    Raises:
        KeyError: if *slug* is not a known recipe.
    """
    filename, _, _ = RECIPES[slug]
    return resources.files(__name__).joinpath(filename).read_text(encoding="utf-8")


def build_index() -> str:
    """Render a small markdown index listing every recipe and its URI.

    Used as the body of the ``protopoke://recipes`` resource so clients
    with only tool access (no resource browser) can still discover the
    recipes via ``get_workflow_recipe("index")``.
    """
    lines = [
        "# ProtoPoke Workflow Recipes",
        "",
        "These recipes chain several MCP tools together to accomplish "
        "common end-to-end tasks. Fetch each one as an MCP resource at "
        "the URI below, or call the `get_workflow_recipe` tool with the "
        "matching slug.",
        "",
    ]
    for slug, (_, title, description) in RECIPES.items():
        lines.append(f"- **{title}** — `protopoke://recipes/{slug}` "
                     f"(slug: `{slug}`)")
        lines.append(f"  {description}")
    lines.append("")
    return "\n".join(lines)


__all__ = ["RECIPES", "load_recipe", "build_index"]
