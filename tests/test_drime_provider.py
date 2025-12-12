"""Tests for the Drime Cloud storage provider.

Note: These tests require pydrime to be installed. They are skipped if
pydrime is not available.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

# Try to import pydrime - skip tests if not available
try:
    import pydrime  # noqa: F401

    PYDRIME_AVAILABLE = True
except ImportError:
    PYDRIME_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not PYDRIME_AVAILABLE, reason="pydrime not installed (optional dependency)"
)


class TestDrimeStorageProvider:
    """Tests for the DrimeStorageProvider class."""

    def setup_method(self):
        """Set up test fixtures."""
        if not PYDRIME_AVAILABLE:
            return
        self.mock_client = MagicMock()

    def _create_provider(self, readonly: bool = False, workspace_id: int = 0):
        """Create a DrimeStorageProvider with mocked client."""
        from pyrestserver.providers.drime import DrimeStorageProvider

        return DrimeStorageProvider(
            client=self.mock_client,
            config={"workspace_id": workspace_id},
            readonly=readonly,
        )

    def _mock_file_entries(self, entries: list[dict]):
        """Create mock FileEntriesResult from entries list."""
        return {
            "data": [
                {
                    "id": e.get("id", 1),
                    "name": e.get("name", "test"),
                    "file_name": e.get("file_name", e.get("name", "test")),
                    "mime": e.get("mime", ""),
                    "file_size": e.get("file_size", 0),
                    "parent_id": e.get("parent_id"),
                    "created_at": e.get("created_at", "2024-01-01T00:00:00Z"),
                    "type": e.get("type", "file"),
                    "extension": e.get("extension"),
                    "hash": e.get("hash", "abc123"),
                    "url": e.get("url", ""),
                    "workspace_id": e.get("workspace_id", 0),
                }
                for e in entries
            ],
            "total": len(entries),
        }


class TestReadonlyMode(TestDrimeStorageProvider):
    """Tests for readonly mode."""

    def test_is_readonly_false(self):
        """Test is_readonly returns False when not readonly."""
        provider = self._create_provider(readonly=False)
        assert provider.is_readonly() is False

    def test_is_readonly_true(self):
        """Test is_readonly returns True when readonly."""
        provider = self._create_provider(readonly=True)
        assert provider.is_readonly() is True


class TestRepositoryOperations(TestDrimeStorageProvider):
    """Tests for repository operations."""

    def test_repository_exists_true(self):
        """Test repository_exists returns True when config exists."""
        provider = self._create_provider()
        # Mock folder lookup
        self.mock_client.get_file_entries.side_effect = [
            self._mock_file_entries([{"id": 1, "name": "myrepo", "type": "folder"}]),
            self._mock_file_entries(
                [{"id": 2, "name": "config", "type": "file", "file_size": 256}]
            ),
        ]

        assert provider.repository_exists("myrepo") is True

    def test_repository_exists_false_no_config(self):
        """Test repository_exists returns False when config doesn't exist."""
        provider = self._create_provider()
        self.mock_client.get_file_entries.side_effect = [
            self._mock_file_entries([{"id": 1, "name": "myrepo", "type": "folder"}]),
            self._mock_file_entries([]),  # No config file
        ]

        assert provider.repository_exists("myrepo") is False

    def test_create_repository_success(self):
        """Test successful repository creation."""
        provider = self._create_provider()
        self.mock_client.get_file_entries.return_value = self._mock_file_entries([])
        self.mock_client.create_folder.return_value = {"folder": {"id": 1}}

        result = provider.create_repository("myrepo")
        assert result is True
        # Should create main folder + subdirectories
        assert self.mock_client.create_folder.call_count >= 1

    def test_create_repository_readonly_fails(self):
        """Test that repository creation fails in readonly mode."""
        provider = self._create_provider(readonly=True)
        result = provider.create_repository("myrepo")
        assert result is False
        self.mock_client.create_folder.assert_not_called()

    def test_delete_repository_readonly_fails(self):
        """Test that repository deletion fails in readonly mode."""
        provider = self._create_provider(readonly=True)
        result = provider.delete_repository("myrepo")
        assert result is False


class TestConfigOperations(TestDrimeStorageProvider):
    """Tests for config operations."""

    def test_config_exists_true(self):
        """Test config_exists returns True and size when config exists."""
        provider = self._create_provider()
        self.mock_client.get_file_entries.side_effect = [
            self._mock_file_entries([{"id": 1, "name": "myrepo", "type": "folder"}]),
            self._mock_file_entries(
                [{"id": 2, "name": "config", "type": "file", "file_size": 256}]
            ),
        ]

        exists, size = provider.config_exists("myrepo")
        assert exists is True
        assert size == 256

    def test_config_exists_false(self):
        """Test config_exists returns False when config doesn't exist."""
        provider = self._create_provider()
        self.mock_client.get_file_entries.side_effect = [
            self._mock_file_entries([{"id": 1, "name": "myrepo", "type": "folder"}]),
            self._mock_file_entries([]),
        ]

        exists, size = provider.config_exists("myrepo")
        assert exists is False
        assert size == 0

    def test_save_config_empty_data_fails(self):
        """Test that saving empty config fails."""
        provider = self._create_provider()
        result = provider.save_config("myrepo", b"")
        assert result is False

    def test_save_config_readonly_fails(self):
        """Test that saving config fails in readonly mode."""
        provider = self._create_provider(readonly=True)
        result = provider.save_config("myrepo", b"config")
        assert result is False


class TestBlobOperations(TestDrimeStorageProvider):
    """Tests for blob operations."""

    def test_list_blobs_invalid_type(self):
        """Test listing blobs with invalid type."""
        provider = self._create_provider()
        result = provider.list_blobs("myrepo", "invalid")
        assert result is None

    def test_blob_exists_invalid_type(self):
        """Test blob_exists with invalid type."""
        provider = self._create_provider()
        exists, size = provider.blob_exists("myrepo", "invalid", "blob1")
        assert exists is False
        assert size == 0

    def test_save_blob_readonly_fails(self):
        """Test that saving blob fails in readonly mode."""
        provider = self._create_provider(readonly=True)
        result = provider.save_blob("myrepo", "keys", "abc123", b"data")
        assert result is False

    def test_save_blob_invalid_type_fails(self):
        """Test that saving blob with invalid type fails."""
        provider = self._create_provider()
        result = provider.save_blob("myrepo", "invalid", "abc123", b"data")
        assert result is False

    def test_delete_blob_readonly_fails(self):
        """Test that deleting blob fails in readonly mode."""
        provider = self._create_provider(readonly=True)
        result = provider.delete_blob("myrepo", "keys", "abc123")
        assert result is False

    def test_delete_blob_invalid_type_fails(self):
        """Test that deleting blob with invalid type fails."""
        provider = self._create_provider()
        result = provider.delete_blob("myrepo", "invalid", "abc123")
        assert result is False


class TestNormalizePath(TestDrimeStorageProvider):
    """Tests for path normalization."""

    def test_normalize_empty_path(self):
        """Test normalizing empty path."""
        provider = self._create_provider()
        assert provider._normalize_path("") == ""
        assert provider._normalize_path("/") == ""

    def test_normalize_simple_path(self):
        """Test normalizing simple path."""
        provider = self._create_provider()
        assert provider._normalize_path("/myrepo") == "myrepo"
        assert provider._normalize_path("myrepo/") == "myrepo"
        assert provider._normalize_path("/myrepo/") == "myrepo"

    def test_normalize_nested_path(self):
        """Test normalizing nested path."""
        provider = self._create_provider()
        assert provider._normalize_path("/backups/myrepo") == "backups/myrepo"


class TestFolderCache(TestDrimeStorageProvider):
    """Tests for folder ID caching."""

    def test_folder_cache_hit(self):
        """Test that folder cache is used on subsequent lookups."""
        provider = self._create_provider()
        self.mock_client.get_file_entries.return_value = self._mock_file_entries(
            [{"id": 1, "name": "myrepo", "type": "folder"}]
        )

        # First lookup - should call API
        folder_id = provider._get_folder_id_by_path("myrepo")
        assert folder_id == 1
        assert self.mock_client.get_file_entries.call_count == 1

        # Second lookup - should use cache
        folder_id = provider._get_folder_id_by_path("myrepo")
        assert folder_id == 1
        # Call count should still be 1 (cache hit)
        assert self.mock_client.get_file_entries.call_count == 1

    def test_folder_cache_cleared_on_delete(self):
        """Test that folder cache is cleared when repository is deleted."""
        provider = self._create_provider()
        self.mock_client.get_file_entries.return_value = self._mock_file_entries(
            [{"id": 1, "name": "myrepo", "type": "folder"}]
        )
        self.mock_client.delete_file_entries.return_value = {}

        # Populate cache
        provider._get_folder_id_by_path("myrepo")
        assert "myrepo" in provider._folder_cache

        # Delete repository
        provider.delete_repository("myrepo")

        # Cache should be cleared
        assert "myrepo" not in provider._folder_cache
