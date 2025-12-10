"""Abstract base class for storage providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class StorageProvider(ABC):
    """Abstract base class for restic storage providers.

    This interface defines all operations required to implement a storage backend
    for the restic REST API. Concrete implementations can use local filesystem,
    cloud storage, or any other storage mechanism.
    """

    @abstractmethod
    def repository_exists(self, repo_path: str) -> bool:
        """Check if a repository exists (has a config file).

        Args:
            repo_path: Path to the repository root

        Returns:
            True if the repository exists (config file present)
        """
        pass

    @abstractmethod
    def config_exists(self, repo_path: str) -> tuple[bool, int]:
        """Check if a repository config exists and get its size.

        Args:
            repo_path: Path to the repository root

        Returns:
            Tuple of (exists, size in bytes)
        """
        pass

    @abstractmethod
    def create_repository(self, repo_path: str) -> bool:
        """Create repository folder structure.

        Creates the necessary directory structure for a restic repository:
        - data/
        - keys/
        - locks/
        - snapshots/
        - index/

        Args:
            repo_path: Path to the repository root

        Returns:
            True if created successfully
        """
        pass

    @abstractmethod
    def delete_repository(self, repo_path: str) -> bool:
        """Delete a repository and all its contents.

        Args:
            repo_path: Path to the repository root

        Returns:
            True if deleted successfully
        """
        pass

    @abstractmethod
    def get_config(self, repo_path: str) -> bytes | None:
        """Get repository config file content.

        Args:
            repo_path: Path to the repository root

        Returns:
            Config file content or None if not found
        """
        pass

    @abstractmethod
    def save_config(self, repo_path: str, data: bytes) -> bool:
        """Save repository config file.

        Args:
            repo_path: Path to the repository root
            data: Config file content

        Returns:
            True if saved successfully
        """
        pass

    @abstractmethod
    def list_blobs(self, repo_path: str, blob_type: str) -> list[dict[str, Any]] | None:
        """List all blobs of a given type.

        Args:
            repo_path: Path to the repository root
            blob_type: Type of blobs (data, keys, locks, snapshots, index)

        Returns:
            List of dictionaries with 'name' and 'size' keys, or None if
            type folder doesn't exist
        """
        pass

    @abstractmethod
    def blob_exists(
        self, repo_path: str, blob_type: str, name: str
    ) -> tuple[bool, int]:
        """Check if a blob exists and get its size.

        Args:
            repo_path: Path to the repository root
            blob_type: Type of blob
            name: Blob name

        Returns:
            Tuple of (exists, size in bytes)
        """
        pass

    @abstractmethod
    def get_blob(self, repo_path: str, blob_type: str, name: str) -> bytes | None:
        """Get blob content.

        Args:
            repo_path: Path to the repository root
            blob_type: Type of blob
            name: Blob name

        Returns:
            Blob content or None if not found
        """
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    def delete_blob(self, repo_path: str, blob_type: str, name: str) -> bool:
        """Delete a blob.

        Args:
            repo_path: Path to the repository root
            blob_type: Type of blob
            name: Blob name

        Returns:
            True if deleted successfully
        """
        pass

    @abstractmethod
    def is_readonly(self) -> bool:
        """Check if the provider is in read-only mode.

        Returns:
            True if read-only mode is enabled
        """
        pass
