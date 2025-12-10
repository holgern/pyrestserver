"""Local filesystem storage provider for restic REST API backend.

This provider implements storage operations using the local filesystem,
matching the behavior of the original rest-server implementation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from pyrestserver.constants import VALID_TYPES
from pyrestserver.provider import StorageProvider

logger = logging.getLogger(__name__)


class LocalStorageProvider(StorageProvider):
    """Storage provider for restic repository data in local filesystem.

    Repository structure on disk (matching rest-server):
        /{base_path}/{repo_path}/config         - Repository configuration file
        /{base_path}/{repo_path}/data/          - Data blobs (subdirectories 00-ff)
        /{base_path}/{repo_path}/keys/          - Key files
        /{base_path}/{repo_path}/locks/         - Lock files
        /{base_path}/{repo_path}/snapshots/     - Snapshot files
        /{base_path}/{repo_path}/index/         - Index files
    """

    def __init__(self, base_path: Path | str, readonly: bool = False) -> None:
        """Initialize the local storage provider.

        Args:
            base_path: Base directory for all repositories (e.g., /tmp/restic)
            readonly: Whether to allow write operations
        """
        self.base_path = Path(base_path)
        self._readonly = readonly

    def _normalize_path(self, path: str) -> str:
        """Normalize a path by removing leading/trailing slashes."""
        return path.strip("/")

    def _get_repo_path(self, repo_path: str) -> Path:
        """Get the filesystem path for a repository.

        Args:
            repo_path: Path like "my-repo" or "user/backup"

        Returns:
            Full filesystem path to the repository
        """
        normalized = self._normalize_path(repo_path)
        if not normalized:
            return self.base_path
        return self.base_path / normalized

    def _get_blob_path(self, repo_path: str, blob_type: str, name: str) -> Path:
        """Get the filesystem path for a blob.

        Args:
            repo_path: Path to the repository root
            blob_type: Type of blob
            name: Blob name

        Returns:
            Full filesystem path to the blob file
        """
        repo = self._get_repo_path(repo_path)

        # For data blobs, they're stored in subdirectories based on first 2 chars
        if blob_type == "data" and len(name) >= 2:
            subdir = name[:2]
            return repo / blob_type / subdir / name
        else:
            return repo / blob_type / name

    def repository_exists(self, repo_path: str) -> bool:
        """Check if a repository exists (has a config file).

        Args:
            repo_path: Path to the repository root

        Returns:
            True if config file exists
        """
        exists, _ = self.config_exists(repo_path)
        return exists

    def config_exists(self, repo_path: str) -> tuple[bool, int]:
        """Check if a repository config exists and get its size.

        Args:
            repo_path: Path to the repository root

        Returns:
            Tuple of (exists, size)
        """
        config_path = self._get_repo_path(repo_path) / "config"
        if not config_path.exists():
            return False, 0

        try:
            size = config_path.stat().st_size
            return True, size
        except OSError as e:
            logger.error(f"Error checking config: {e}")
            return False, 0

    def create_repository(self, repo_path: str) -> bool:
        """Create repository folder structure.

        Args:
            repo_path: Path to the repository root

        Returns:
            True if created successfully
        """
        if self._readonly:
            return False

        repo = self._get_repo_path(repo_path)

        # Create subdirectories with proper permissions (matching rest-server defaults)
        folders_to_create = ["data", "keys", "locks", "snapshots", "index"]

        try:
            for folder in folders_to_create:
                folder_path = repo / folder
                folder_path.mkdir(parents=True, exist_ok=True, mode=0o700)
            return True
        except OSError as e:
            logger.error(f"Error creating repository: {e}")
            return False

    def delete_repository(self, repo_path: str) -> bool:
        """Delete a repository and all its contents.

        Args:
            repo_path: Path to the repository root

        Returns:
            True if deleted successfully
        """
        if self._readonly:
            return False

        repo = self._get_repo_path(repo_path)

        if not repo.exists():
            return False

        try:
            import shutil

            shutil.rmtree(repo)
            return True
        except OSError as e:
            logger.error(f"Error deleting repository: {e}")
            return False

    def get_config(self, repo_path: str) -> bytes | None:
        """Get repository config file content.

        Args:
            repo_path: Path to the repository root

        Returns:
            Config file content or None if not found
        """
        config_path = self._get_repo_path(repo_path) / "config"

        if not config_path.exists():
            return None

        try:
            return config_path.read_bytes()
        except OSError as e:
            logger.error(f"Error reading config: {e}")
            return None

    def save_config(self, repo_path: str, data: bytes) -> bool:
        """Save repository config file.

        Args:
            repo_path: Path to the repository root
            data: Config file content

        Returns:
            True if saved successfully
        """
        if self._readonly:
            return False

        if len(data) == 0:
            logger.error("Refusing to save empty config file")
            return False

        config_path = self._get_repo_path(repo_path) / "config"

        try:
            # Ensure parent directory exists
            config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

            # Write the config file
            config_path.write_bytes(data)

            # Set proper permissions (matching rest-server defaults)
            config_path.chmod(0o600)

            return True
        except OSError as e:
            logger.error(f"Error saving config: {e}")
            return False

    def list_blobs(self, repo_path: str, blob_type: str) -> list[dict[str, Any]] | None:
        """List all blobs of a given type.

        Args:
            repo_path: Path to the repository root
            blob_type: Type of blobs (data, keys, locks, snapshots, index)

        Returns:
            List of {name, size} dicts, or None if type folder doesn't exist
        """
        if blob_type not in VALID_TYPES:
            return None

        type_path = self._get_repo_path(repo_path) / blob_type

        if not type_path.exists():
            return []

        blobs: list[dict[str, Any]] = []

        try:
            # For data type, we need to list subdirectories (00-ff)
            if blob_type == "data":
                for subdir in type_path.iterdir():
                    if subdir.is_dir():
                        for blob_file in subdir.iterdir():
                            if blob_file.is_file():
                                blobs.append(
                                    {
                                        "name": blob_file.name,
                                        "size": blob_file.stat().st_size,
                                    }
                                )
            else:
                # List files directly in the type folder
                for blob_file in type_path.iterdir():
                    if blob_file.is_file():
                        blobs.append(
                            {
                                "name": blob_file.name,
                                "size": blob_file.stat().st_size,
                            }
                        )

            return blobs
        except OSError as e:
            logger.error(f"Error listing blobs: {e}")
            return []

    def blob_exists(
        self, repo_path: str, blob_type: str, name: str
    ) -> tuple[bool, int]:
        """Check if a blob exists and get its size.

        Args:
            repo_path: Path to the repository root
            blob_type: Type of blob
            name: Blob name

        Returns:
            Tuple of (exists, size)
        """
        if blob_type not in VALID_TYPES:
            return False, 0

        blob_path = self._get_blob_path(repo_path, blob_type, name)

        if not blob_path.exists():
            return False, 0

        try:
            size = blob_path.stat().st_size
            return True, size
        except OSError as e:
            logger.error(f"Error checking blob: {e}")
            return False, 0

    def get_blob(self, repo_path: str, blob_type: str, name: str) -> bytes | None:
        """Get blob content.

        Args:
            repo_path: Path to the repository root
            blob_type: Type of blob
            name: Blob name

        Returns:
            Blob content or None if not found
        """
        if blob_type not in VALID_TYPES:
            return None

        blob_path = self._get_blob_path(repo_path, blob_type, name)

        if not blob_path.exists():
            return None

        try:
            return blob_path.read_bytes()
        except OSError as e:
            logger.error(f"Error reading blob {blob_type}/{name}: {e}")
            return None

    def save_blob(self, repo_path: str, blob_type: str, name: str, data: bytes) -> bool:
        """Save blob content.

        Args:
            repo_path: Path to the repository root
            blob_type: Type of blob
            name: Blob name
            data: Blob content

        Returns:
            True if saved successfully
        """
        if self._readonly:
            return False

        if blob_type not in VALID_TYPES:
            return False

        blob_path = self._get_blob_path(repo_path, blob_type, name)

        try:
            # Ensure parent directory exists
            blob_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

            # Write the blob file
            blob_path.write_bytes(data)

            # Set proper permissions (matching rest-server defaults)
            blob_path.chmod(0o600)

            return True
        except OSError as e:
            logger.error(f"Error saving blob {blob_type}/{name}: {e}")
            return False

    def delete_blob(self, repo_path: str, blob_type: str, name: str) -> bool:
        """Delete a blob.

        Args:
            repo_path: Path to the repository root
            blob_type: Type of blob
            name: Blob name

        Returns:
            True if deleted successfully
        """
        if self._readonly:
            return False

        if blob_type not in VALID_TYPES:
            return False

        blob_path = self._get_blob_path(repo_path, blob_type, name)

        if not blob_path.exists():
            return False

        try:
            blob_path.unlink()
            return True
        except OSError as e:
            logger.error(f"Error deleting blob {blob_type}/{name}: {e}")
            return False

    def is_readonly(self) -> bool:
        """Check if the provider is in read-only mode."""
        return self._readonly
