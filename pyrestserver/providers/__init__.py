"""Storage provider implementations for pyrestserver."""

from typing import Any


def __getattr__(name: str) -> Any:
    """Lazy import to avoid requiring optional dependencies."""
    if name == "LocalStorageProvider":
        from .local import LocalStorageProvider

        return LocalStorageProvider
    elif name == "DrimeStorageProvider":
        try:
            from .drime import DrimeStorageProvider

            return DrimeStorageProvider
        except ImportError as e:
            raise ImportError(
                "DrimeStorageProvider requires pydrime package. "
                "Install with: pip install pyrestserver[drime]"
            ) from e
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["LocalStorageProvider", "DrimeStorageProvider"]
