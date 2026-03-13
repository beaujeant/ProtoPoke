# framing: turns the raw TCP byte stream into logical Frame objects

from .base import Framer
from .raw import RawFramer
from .delimiter import DelimiterFramer
from .length_prefix import LengthPrefixFramer
from .line import LineFramer

# Registry of built-in framers.
# To add a custom framer, import create_framer and extend this dict,
# or just instantiate your Framer subclass directly.
FRAMER_REGISTRY: dict[str, type[Framer]] = {
    "raw": RawFramer,
    "delimiter": DelimiterFramer,
    "length_prefix": LengthPrefixFramer,
    "line": LineFramer,
}


def create_framer(name: str, session_id: str, direction, **kwargs) -> Framer:
    """
    Instantiate a framer by name.

    Args:
        name: Framer name, must be a key in FRAMER_REGISTRY.
        session_id: Session this framer belongs to.
        direction: Direction (Direction.CLIENT_TO_SERVER or SERVER_TO_CLIENT).
        **kwargs: Extra arguments forwarded to the framer constructor.

    Raises:
        KeyError: If name is not in FRAMER_REGISTRY.
    """
    framer_class = FRAMER_REGISTRY[name]
    return framer_class(session_id=session_id, direction=direction, **kwargs)


