"""Backend configuration management using vaultconfig.

This module provides a thin adapter layer over vaultconfig for managing
pyrestserver backend configurations.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from vaultconfig import (  # type: ignore[import-untyped]
    ConfigManager,
    create_obscurer_from_hex,
)

# Backend types specific to pyrestserver
BackendType = Literal["local", "drime"]

# Configuration paths
CONFIG_DIR = Path.home() / ".config" / "pyrestserver"
BACKENDS_FILE = CONFIG_DIR / "backends.toml"

# Custom obscurer for pyrestserver using a random cipher key
# This provides application-specific protection for password obscuring
# IMPORTANT: This key is unique to pyrestserver and should not be changed
# as it would make previously obscured passwords unreadable.
# Generated with: secrets.token_bytes(32).hex()
_PYRESTSERVER_CIPHER_KEY = (
    "0a34b62682e9bae989fc36e770382b38f598f3ceff418e241da459fc801c7863"
)
_PYRESTSERVER_OBSCURER = create_obscurer_from_hex(_PYRESTSERVER_CIPHER_KEY)


class BackendConfig:
    """Adapter for vaultconfig ConfigEntry to maintain backward compatibility."""

    def __init__(self, name: str, backend_type: BackendType, config: dict[str, Any]):
        """Initialize backend config.

        Args:
            name: Backend name
            backend_type: Backend type
            config: Configuration dict
        """
        self.name = name
        self.backend_type = backend_type
        self._config = config

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value.

        Args:
            key: Configuration key
            default: Default value

        Returns:
            Configuration value (with passwords revealed if obscured)
        """
        value = self._config.get(key, default)

        # Reveal obscured passwords using pyrestserver's custom obscurer
        if isinstance(value, str) and key in ("password", "api_key", "drime_password"):
            try:
                return _PYRESTSERVER_OBSCURER.reveal(value)
            except ValueError:
                return value

        return value

    def get_all(self) -> dict[str, Any]:
        """Get all config values with passwords revealed.

        Returns:
            Dictionary of all configuration values
        """
        result = {}
        for key, value in self._config.items():
            if isinstance(value, str) and key in (
                "password",
                "api_key",
                "drime_password",
            ):
                try:
                    result[key] = _PYRESTSERVER_OBSCURER.reveal(value)
                except ValueError:
                    result[key] = value
            else:
                result[key] = value
        return result


class PyRestServerConfigManager:
    """Adapter for vaultconfig ConfigManager for pyrestserver backends."""

    def __init__(self, config_file: Path = BACKENDS_FILE):
        """Initialize config manager.

        Args:
            config_file: Path to config file (for compatibility)
        """
        self.config_file = config_file
        self._config_dir = config_file.parent

        # Use vaultconfig ConfigManager with custom obscurer
        self._manager = ConfigManager(
            config_dir=self._config_dir,
            format="toml",
            password=None,
            obscurer=_PYRESTSERVER_OBSCURER,
        )

    def list_backends(self) -> list[str]:
        """List all backend names.

        Returns:
            List of backend names
        """
        result: list[str] = self._manager.list_configs()
        return result

    def get_backend(self, name: str) -> BackendConfig | None:
        """Get backend configuration.

        Args:
            name: Backend name

        Returns:
            BackendConfig or None if not found
        """
        config_entry = self._manager.get_config(name)
        if not config_entry:
            return None

        # Extract backend type and config
        data = config_entry.get_all(reveal_secrets=False)
        backend_type = data.pop("type", "local")

        return BackendConfig(name, backend_type, data)

    def has_backend(self, name: str) -> bool:
        """Check if backend exists.

        Args:
            name: Backend name

        Returns:
            True if backend exists
        """
        result: bool = self._manager.has_config(name)
        return result

    def add_backend(
        self,
        name: str,
        backend_type: BackendType,
        config: dict[str, Any],
        obscure_passwords: bool = True,
    ) -> None:
        """Add or update backend.

        Args:
            name: Backend name
            backend_type: Backend type
            config: Configuration dict
            obscure_passwords: Whether to obscure passwords
        """
        # Add type to config
        full_config = {"type": backend_type, **config}

        # Manually obscure passwords using pyrestserver's custom obscurer
        if obscure_passwords:
            full_config = full_config.copy()
            for key in ("password", "api_key", "drime_password"):
                if key in full_config and isinstance(full_config[key], str):
                    if not _PYRESTSERVER_OBSCURER.is_obscured(full_config[key]):
                        full_config[key] = _PYRESTSERVER_OBSCURER.obscure(
                            full_config[key]
                        )

        self._manager.add_config(name, full_config, obscure_passwords=False)

    def remove_backend(self, name: str) -> bool:
        """Remove backend.

        Args:
            name: Backend name

        Returns:
            True if removed
        """
        result: bool = self._manager.remove_config(name)
        return result

    def get_backend_names_by_type(self, backend_type: BackendType) -> list[str]:
        """Get backend names by type.

        Args:
            backend_type: Backend type to filter

        Returns:
            List of backend names
        """
        result = []
        for name in self.list_backends():
            backend = self.get_backend(name)
            if backend and backend.backend_type == backend_type:
                result.append(name)
        return result


# Global config manager instance
_config_manager: PyRestServerConfigManager | None = None


def get_config_manager() -> PyRestServerConfigManager:
    """Get global config manager instance.

    Returns:
        PyRestServerConfigManager instance
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = PyRestServerConfigManager()
    return _config_manager
