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


class _CustomFramerAdapter(Framer):
    """
    Wraps a user-supplied duck-typed framer object in the internal
    :class:`Framer` interface.

    The wrapped class only needs two methods — no inheritance required:

    .. code-block:: python

        class MyFramer:
            def on_data(self, data: bytes) -> list[bytes]: ...
            def on_flush(self) -> list[bytes]: ...

    ``on_data`` is called with each raw read chunk and must return a list of
    complete message payloads (as plain ``bytes``).  ``on_flush`` is called
    when the connection closes and should return any partially buffered bytes.

    The adapter assigns session attribution, direction, and sequence numbers
    automatically, so the user script never needs to import from protopoke.
    """

    def __init__(self, impl, session_id: str, direction) -> None:
        super().__init__(session_id, direction)
        self._impl = impl

    def feed(self, data: bytes) -> list:
        return [self._make_frame(b) for b in self._impl.on_data(data)]

    def flush(self) -> list:
        return [self._make_frame(b) for b in self._impl.on_flush()]

    def reset(self) -> None:
        if hasattr(self._impl, "reset"):
            self._impl.reset()


def load_framer_from_file(path: str):
    """
    Load a custom framer from a Python script and return a factory function.

    The script must define a class with ``on_data`` and ``on_flush`` methods.
    No inheritance from ``Framer`` is required — plain classes work:

    .. code-block:: python

        class MyFramer:
            def on_data(self, data: bytes) -> list[bytes]:
                ...
            def on_flush(self) -> list[bytes]:
                ...

    The class is discovered automatically — the first class in the file with
    both methods is used.

    Args:
        path: Absolute or relative path to the ``.py`` file.

    Returns:
        A factory ``(session_id, direction) -> Framer`` that wraps the user
        class in :class:`_CustomFramerAdapter`.

    Raises:
        FileNotFoundError: *path* does not exist.
        TypeError:         No suitable class was found in the file.
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

    for attr_name in dir(module):
        cls = getattr(module, attr_name)
        if (
            isinstance(cls, type)
            and callable(getattr(cls, "on_data", None))
            and callable(getattr(cls, "on_flush", None))
        ):
            def _factory(session_id, direction, _cls=cls):
                return _CustomFramerAdapter(_cls(), session_id, direction)
            return _factory

    raise TypeError(
        f"No framer class found in {path}. "
        "Define a class with on_data(self, data: bytes) -> list[bytes] "
        "and on_flush(self) -> list[bytes]."
    )


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
