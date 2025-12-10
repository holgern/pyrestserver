"""REST API server for restic backup with pluggable storage backends.

This package provides a REST API server compatible with restic's REST backend v2
specification, supporting multiple storage backends including local filesystem
and Drime Cloud.

Example usage:
    # Using local filesystem (default)
    from pathlib import Path
    from pyrestserver.providers.local import LocalStorageProvider
    from pyrestserver.server import run_rest_server

    provider = LocalStorageProvider(Path("/path/to/backup"))
    run_rest_server(provider, host="0.0.0.0", port=8000)

    # Or use the CLI
    # pyrestserver --path /path/to/backup
"""

__version__ = "0.0.0"  # Placeholder, replaced by setuptools_scm

# Core interfaces
from .provider import StorageProvider
from .server import ResticRESTApp, create_rest_app, run_rest_server

# Storage providers
from .providers.local import LocalStorageProvider

# Optional Drime provider (only if pydrime is installed)
try:
    from .providers.drime import DrimeStorageProvider
except ImportError:
    DrimeStorageProvider = None  # type: ignore

__all__ = [
    "StorageProvider",
    "ResticRESTApp",
    "create_rest_app",
    "run_rest_server",
    "LocalStorageProvider",
    "DrimeStorageProvider",
]
