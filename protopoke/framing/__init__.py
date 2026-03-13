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


def load_framer_from_file(path: str, class_name: str) -> type[Framer]:
    """
    Dynamically load a custom :class:`Framer` subclass from a Python file.

    The file is executed in its own module namespace so it can import other
    local modules freely.  The loaded class is *not* added to
    ``FRAMER_REGISTRY`` automatically; call
    ``FRAMER_REGISTRY["custom"] = load_framer_from_file(...)`` if you want
    it available by name.

    Args:
        path:       Absolute or relative path to the ``.py`` file.
        class_name: Name of the ``Framer`` subclass defined in that file.

    Returns:
        The class object (not an instance).

    Raises:
        FileNotFoundError: *path* does not exist.
        AttributeError:    *class_name* is not defined in the file.
        TypeError:         *class_name* is not a ``Framer`` subclass.
    """
    import importlib.util
    from pathlib import Path as _Path

    file_path = _Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Custom framer file not found: {path}")

    spec = importlib.util.spec_from_file_location("_protopoke_custom_framer", file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load spec from {path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]

    cls = getattr(module, class_name, None)
    if cls is None:
        available = [n for n in dir(module) if not n.startswith("_")]
        raise AttributeError(
            f"Class {class_name!r} not found in {path}. "
            f"Available names: {available}"
        )
    if not (isinstance(cls, type) and issubclass(cls, Framer)):
        raise TypeError(
            f"{class_name!r} from {path} is not a Framer subclass "
            f"(got {type(cls).__name__!r})"
        )
    return cls
