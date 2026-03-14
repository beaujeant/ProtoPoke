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


class _FunctionFramerAdapter(Framer):
    """
    Wraps a pair of module-level ``on_data`` / ``on_flush`` functions in the
    internal :class:`Framer` interface.

    Both directions of the same session share **one** ``state`` dict.  This
    lets the user correlate client→server and server→client parsing (e.g.
    recording which command the client sent so the server response can be
    parsed correctly).

    The user-supplied functions receive:

    .. code-block:: python

        on_data(data: bytes, state: dict, direction: str) -> list[bytes]
        on_flush(state: dict, direction: str) -> list[bytes]

    ``direction`` is the string ``"c2s"`` (client→server) or ``"s2c"``
    (server→client).  ``state`` is a plain dict that persists for the
    lifetime of the session and is passed to every call for both directions.
    """

    def __init__(self, on_data_fn, on_flush_fn, state: dict, direction_str: str,
                 session_id: str, direction) -> None:
        super().__init__(session_id, direction)
        self._on_data_fn    = on_data_fn
        self._on_flush_fn   = on_flush_fn
        self._state         = state
        self._direction_str = direction_str

    def feed(self, data: bytes) -> list:
        return [
            self._make_frame(b)
            for b in self._on_data_fn(data, self._state, self._direction_str)
        ]

    def flush(self) -> list:
        return [
            self._make_frame(b)
            for b in self._on_flush_fn(self._state, self._direction_str)
        ]

    def reset(self) -> None:
        pass  # state lifecycle is managed by the session, not the adapter


def load_framer_from_file(path: str):
    """
    Load a custom framer from a Python script and return a factory.

    **Preferred API — two plain functions (no class needed):**

    .. code-block:: python

        def on_data(data: bytes, state: dict, direction: str) -> list[bytes]:
            # direction is "c2s" (client→server) or "s2c" (server→client).
            # state is a single dict shared between BOTH directions for the
            # lifetime of the session — use it for per-direction buffers and
            # for any cross-direction correlation your protocol needs.
            buf = state.setdefault(direction, bytearray())
            buf.extend(data)
            # ... detect boundaries, slice complete frames out of buf ...
            return [complete_frame_bytes, ...]

        def on_flush(state: dict, direction: str) -> list[bytes]:
            buf = state.pop(direction, bytearray())
            return [bytes(buf)] if buf else []

    Because ``state`` is shared, a correlated protocol (e.g. where the
    server response format depends on which command the client sent) can
    simply write to and read from shared keys:

    .. code-block:: python

        def on_data(data, state, direction):
            buf = state.setdefault(direction, bytearray())
            buf.extend(data)
            if direction == "c2s":
                state["last_cmd"] = ...   # record for response parsing
            else:
                cmd = state.get("last_cmd")
                # parse server response according to cmd
            ...

    Args:
        path: Absolute or relative path to the ``.py`` file.

    Returns:
        A factory ``(session_id, direction, state) -> Framer`` where
        ``state`` is the shared dict created once per session in
        ``proxy.py`` and passed to both the client-side and server-side
        adapter instances.

    Raises:
        FileNotFoundError: *path* does not exist.
        TypeError:         Neither module-level functions nor a class with
                           ``on_data``/``on_flush`` were found.
    """
    import importlib.util
    import inspect
    from pathlib import Path as _Path

    file_path = _Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Custom framer file not found: {path}")

    spec = importlib.util.spec_from_file_location("_protopoke_custom_framer", file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load spec from {path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]

    # --- Preferred: module-level on_data / on_flush functions ---
    on_data_fn  = getattr(module, "on_data",  None)
    on_flush_fn = getattr(module, "on_flush", None)

    if inspect.isfunction(on_data_fn) and inspect.isfunction(on_flush_fn):
        def _fn_factory(session_id, direction, state,
                        _od=on_data_fn, _of=on_flush_fn):
            dir_str = "c2s" if "CLIENT" in direction.name else "s2c"
            return _FunctionFramerAdapter(_od, _of, state, dir_str,
                                          session_id, direction)
        return _fn_factory

    raise TypeError(
        f"No framer found in {path}. "
        "Define two module-level functions:\n"
        "  on_data(data: bytes, state: dict, direction: str) -> list[bytes]\n"
        "  on_flush(state: dict, direction: str) -> list[bytes]"
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
