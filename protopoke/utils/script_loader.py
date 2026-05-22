import importlib.util
import types
from pathlib import Path


def load_python_module(path: str) -> types.ModuleType:
    """
    Load a Python source file as a module.

    Uses the file stem as the module name so that tracebacks reference the
    actual filename rather than a generic placeholder.

    Raises:
        FileNotFoundError: *path* does not exist.
        ImportError:       A module spec cannot be created for *path*.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Script not found: {path}")
    spec = importlib.util.spec_from_file_location(p.stem, p)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot create module spec for: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod
