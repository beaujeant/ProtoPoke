"""Protocol parser: turns raw Frame bytes into structured ParsedMessage objects."""

from .engine import DefinitionBasedDecoder, DefinitionBasedEncoder

__all__ = ["DefinitionBasedDecoder", "DefinitionBasedEncoder"]
