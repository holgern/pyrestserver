"""Tests for the local filesystem storage provider."""

from __future__ import annotations

import tempfile
from pathlib import Path


class TestLocalStorageProvider:
    """Tests for the LocalStorageProvider class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.base_path = Path(self.temp_dir)

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_provider(self, readonly: bool = False):
        """Create a LocalStorageProvider with temp directory."""
        from pyrestserver.providers.local import LocalStorageProvider

        return LocalStorageProvider(self.base_path, readonly=readonly)


class TestReadonlyMode(TestLocalStorageProvider):
    """Tests for readonly mode."""

    def test_is_readonly_false(self):
        """Test is_readonly returns False when not readonly."""
        provider = self._create_provider(readonly=False)
        assert provider.is_readonly() is False

    def test_is_readonly_true(self):
        """Test is_readonly returns True when readonly."""
        provider = self._create_provider(readonly=True)
        assert provider.is_readonly() is True


class TestRepositoryOperations(TestLocalStorageProvider):
    """Tests for repository operations."""

    def test_repository_exists_false_initially(self):
        """Test repository_exists returns False for new repo."""
        provider = self._create_provider()
        assert provider.repository_exists("myrepo") is False

    def test_create_repository_success(self):
        """Test successful repository creation."""
        provider = self._create_provider()
        result = provider.create_repository("myrepo")
        assert result is True
        # Check that directories were created
        repo_path = self.base_path / "myrepo"
        assert repo_path.exists()
        assert (repo_path / "data").exists()
        assert (repo_path / "keys").exists()
        assert (repo_path / "locks").exists()
        assert (repo_path / "snapshots").exists()
        assert (repo_path / "index").exists()

    def test_create_repository_readonly_fails(self):
        """Test that repository creation fails in readonly mode."""
        provider = self._create_provider(readonly=True)
        result = provider.create_repository("myrepo")
        assert result is False
        assert not (self.base_path / "myrepo").exists()

    def test_repository_exists_true_after_creation(self):
        """Test repository_exists returns True after config is saved."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        # Initially false (no config yet)
        assert provider.repository_exists("myrepo") is False
        # Save a config
        provider.save_config("myrepo", b"test config")
        # Now should exist
        assert provider.repository_exists("myrepo") is True

    def test_delete_repository_success(self):
        """Test successful repository deletion."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        result = provider.delete_repository("myrepo")
        assert result is True
        assert not (self.base_path / "myrepo").exists()

    def test_delete_repository_not_found(self):
        """Test deleting non-existent repository."""
        provider = self._create_provider()
        result = provider.delete_repository("nonexistent")
        assert result is False

    def test_delete_repository_readonly_fails(self):
        """Test that repository deletion fails in readonly mode."""
        provider = self._create_provider(readonly=True)
        # Create a repo first (using non-readonly provider)
        provider_rw = self._create_provider(readonly=False)
        provider_rw.create_repository("myrepo")
        # Try to delete with readonly provider
        result = provider.delete_repository("myrepo")
        assert result is False
        assert (self.base_path / "myrepo").exists()


class TestConfigOperations(TestLocalStorageProvider):
    """Tests for config operations."""

    def test_config_exists_false_initially(self):
        """Test config_exists returns False when config doesn't exist."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        exists, size = provider.config_exists("myrepo")
        assert exists is False
        assert size == 0

    def test_save_config_success(self):
        """Test saving config content."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        config_data = b"test config data"
        result = provider.save_config("myrepo", config_data)
        assert result is True
        # Check file exists
        config_file = self.base_path / "myrepo" / "config"
        assert config_file.exists()
        assert config_file.read_bytes() == config_data

    def test_save_config_creates_repo_if_needed(self):
        """Test that save_config creates repository directories."""
        provider = self._create_provider()
        config_data = b"test config"
        result = provider.save_config("myrepo", config_data)
        assert result is True
        assert (self.base_path / "myrepo").exists()

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

    def test_config_exists_true_after_save(self):
        """Test config_exists returns True and size after saving."""
        provider = self._create_provider()
        config_data = b"test config data"
        provider.save_config("myrepo", config_data)
        exists, size = provider.config_exists("myrepo")
        assert exists is True
        assert size == len(config_data)

    def test_get_config_success(self):
        """Test getting config content."""
        provider = self._create_provider()
        config_data = b"test config data"
        provider.save_config("myrepo", config_data)
        result = provider.get_config("myrepo")
        assert result == config_data

    def test_get_config_not_found(self):
        """Test getting config when it doesn't exist."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        result = provider.get_config("myrepo")
        assert result is None


class TestBlobListOperations(TestLocalStorageProvider):
    """Tests for blob listing operations."""

    def test_list_blobs_empty(self):
        """Test listing blobs when folder is empty."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        result = provider.list_blobs("myrepo", "keys")
        assert result == []

    def test_list_blobs_invalid_type(self):
        """Test listing blobs with invalid type."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        result = provider.list_blobs("myrepo", "invalid")
        assert result is None

    def test_list_blobs_success(self):
        """Test listing blobs after adding some."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        # Add some blobs
        provider.save_blob("myrepo", "keys", "key1", b"key data 1")
        provider.save_blob("myrepo", "keys", "key2", b"key data 2")
        result = provider.list_blobs("myrepo", "keys")
        assert result is not None
        assert len(result) == 2
        # Sort by name for consistent testing
        result = sorted(result, key=lambda x: x["name"])
        assert result[0]["name"] == "key1"
        assert result[0]["size"] == 10
        assert result[1]["name"] == "key2"
        assert result[1]["size"] == 10

    def test_list_blobs_data_with_subdirs(self):
        """Test listing data blobs (which have subdirectories)."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        # Add data blobs (use names starting with 2-char prefix)
        provider.save_blob("myrepo", "data", "00abc123", b"data 1")
        provider.save_blob("myrepo", "data", "00def456", b"data 2")
        provider.save_blob("myrepo", "data", "01xyz789", b"data 3")
        result = provider.list_blobs("myrepo", "data")
        assert result is not None
        assert len(result) == 3


class TestBlobOperations(TestLocalStorageProvider):
    """Tests for individual blob operations."""

    def test_blob_exists_false_initially(self):
        """Test blob_exists returns False when blob doesn't exist."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        exists, size = provider.blob_exists("myrepo", "keys", "key1")
        assert exists is False
        assert size == 0

    def test_blob_exists_invalid_type(self):
        """Test blob_exists with invalid type."""
        provider = self._create_provider()
        exists, size = provider.blob_exists("myrepo", "invalid", "key1")
        assert exists is False
        assert size == 0

    def test_save_blob_success(self):
        """Test saving blob content."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        blob_data = b"blob content"
        result = provider.save_blob("myrepo", "keys", "key1", blob_data)
        assert result is True
        # Check file exists
        blob_file = self.base_path / "myrepo" / "keys" / "key1"
        assert blob_file.exists()
        assert blob_file.read_bytes() == blob_data

    def test_save_blob_data_with_subdir(self):
        """Test saving data blob (creates subdirectory)."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        blob_data = b"data blob"
        # Data blobs use first 2 chars as subdirectory
        result = provider.save_blob("myrepo", "data", "abc123def", blob_data)
        assert result is True
        blob_file = self.base_path / "myrepo" / "data" / "ab" / "abc123def"
        assert blob_file.exists()
        assert blob_file.read_bytes() == blob_data

    def test_save_blob_readonly_fails(self):
        """Test that saving blob fails in readonly mode."""
        provider = self._create_provider(readonly=True)
        result = provider.save_blob("myrepo", "keys", "key1", b"data")
        assert result is False

    def test_save_blob_invalid_type_fails(self):
        """Test that saving blob with invalid type fails."""
        provider = self._create_provider()
        result = provider.save_blob("myrepo", "invalid", "key1", b"data")
        assert result is False

    def test_blob_exists_true_after_save(self):
        """Test blob_exists returns True and size after saving."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        blob_data = b"blob content"
        provider.save_blob("myrepo", "keys", "key1", blob_data)
        exists, size = provider.blob_exists("myrepo", "keys", "key1")
        assert exists is True
        assert size == len(blob_data)

    def test_get_blob_success(self):
        """Test getting blob content."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        blob_data = b"blob content"
        provider.save_blob("myrepo", "keys", "key1", blob_data)
        result = provider.get_blob("myrepo", "keys", "key1")
        assert result == blob_data

    def test_get_blob_not_found(self):
        """Test getting non-existent blob."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        result = provider.get_blob("myrepo", "keys", "nonexistent")
        assert result is None

    def test_get_blob_invalid_type(self):
        """Test getting blob with invalid type."""
        provider = self._create_provider()
        result = provider.get_blob("myrepo", "invalid", "key1")
        assert result is None

    def test_delete_blob_success(self):
        """Test deleting blob."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        provider.save_blob("myrepo", "keys", "key1", b"data")
        result = provider.delete_blob("myrepo", "keys", "key1")
        assert result is True
        blob_file = self.base_path / "myrepo" / "keys" / "key1"
        assert not blob_file.exists()

    def test_delete_blob_not_found(self):
        """Test deleting non-existent blob."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        result = provider.delete_blob("myrepo", "keys", "nonexistent")
        assert result is False

    def test_delete_blob_readonly_fails(self):
        """Test that deleting blob fails in readonly mode."""
        provider_rw = self._create_provider(readonly=False)
        provider_rw.create_repository("myrepo")
        provider_rw.save_blob("myrepo", "keys", "key1", b"data")
        provider = self._create_provider(readonly=True)
        result = provider.delete_blob("myrepo", "keys", "key1")
        assert result is False


class TestNestedRepositories(TestLocalStorageProvider):
    """Tests for nested repository paths."""

    def test_nested_repo_path(self):
        """Test creating and using nested repository paths."""
        provider = self._create_provider()
        provider.create_repository("backups/myrepo")
        provider.save_config("backups/myrepo", b"config")
        assert provider.repository_exists("backups/myrepo")
        config = provider.get_config("backups/myrepo")
        assert config == b"config"


class TestFilePermissions(TestLocalStorageProvider):
    """Tests for file permissions."""

    def test_directory_permissions(self):
        """Test that directories are created with correct permissions."""
        provider = self._create_provider()
        provider.create_repository("myrepo")
        repo_path = self.base_path / "myrepo"
        # Check directory has 0700 permissions (owner only)
        import stat

        mode = repo_path.stat().st_mode
        # Check that directory is at least owner-accessible (0700)
        # Note: actual permissions may be 0755 depending on umask
        assert stat.S_IMODE(mode) & 0o700 == 0o700

    def test_file_permissions(self):
        """Test that files are created with correct permissions."""
        import platform
        import stat

        provider = self._create_provider()
        provider.save_config("myrepo", b"config")
        config_file = self.base_path / "myrepo" / "config"

        mode = config_file.stat().st_mode

        # On Windows, file permissions work differently
        # Windows typically sets files to 0o666 (438 in decimal)
        if platform.system() == "Windows":
            # On Windows, just check that the file is readable and writable
            assert stat.S_IMODE(mode) & stat.S_IREAD
            assert stat.S_IMODE(mode) & stat.S_IWRITE
        else:
            # On Unix-like systems, check file has 0600 permissions
            # (owner read/write only)
            assert stat.S_IMODE(mode) == 0o600
