"""Tests for the REST API server module."""

# pyright: reportAttributeAccessIssue=false

from __future__ import annotations

import base64
import json
from io import BytesIO
from unittest.mock import MagicMock


class TestResticRESTApp:
    """Tests for the ResticRESTApp class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_provider = MagicMock()

    def _create_app(
        self,
        readonly: bool = False,
        username: str | None = None,
        password: str | None = None,
    ):
        """Create a ResticRESTApp with mocked provider."""
        from pyrestserver.server import ResticRESTApp

        self.mock_provider.is_readonly.return_value = readonly
        app = ResticRESTApp(
            provider=self.mock_provider,
            username=username,
            password=password,
        )
        return app

    def _make_request(
        self,
        app,
        method: str,
        path: str,
        query_string: str = "",
        body: bytes | None = None,
        headers: dict | None = None,
    ) -> tuple[str, list, bytes]:
        """Make a WSGI request and return status, headers, body."""
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": query_string,
            "wsgi.input": BytesIO(body or b""),
            "CONTENT_LENGTH": str(len(body)) if body else "0",
        }
        if headers:
            for key, value in headers.items():
                # Convert to WSGI format (HTTP_X_HEADER for X-Header)
                wsgi_key = f"HTTP_{key.upper().replace('-', '_')}"
                environ[wsgi_key] = value

        response_status: str = ""
        response_headers: list = []

        def start_response(status: str, hdrs: list) -> None:
            nonlocal response_status, response_headers
            response_status = status
            response_headers = hdrs

        result = app(environ, start_response)
        body_bytes = b"".join(result)

        return response_status, response_headers, body_bytes


class TestAPIVersionDetection(TestResticRESTApp):
    """Tests for API version detection."""

    def test_api_v1_default(self):
        """Test that API v1 is used by default."""
        app = self._create_app()
        environ = {}
        assert app._get_api_version(environ) == 1

    def test_api_v1_with_other_accept_header(self):
        """Test that API v1 is used for non-matching Accept headers."""
        app = self._create_app()
        environ = {"HTTP_ACCEPT": "application/json"}
        assert app._get_api_version(environ) == 1

    def test_api_v2_exact_match(self):
        """Test that API v2 is used only for exact match."""
        from pyrestserver.constants import API_V2_MEDIA_TYPE

        app = self._create_app()
        environ = {"HTTP_ACCEPT": API_V2_MEDIA_TYPE}
        assert app._get_api_version(environ) == 2

    def test_api_v1_with_v2_substring(self):
        """Test that API v1 is used when v2 is a substring (not exact match)."""
        from pyrestserver.constants import API_V2_MEDIA_TYPE

        app = self._create_app()
        # This would match with substring check but should NOT match with exact
        environ = {"HTTP_ACCEPT": f"{API_V2_MEDIA_TYPE}; charset=utf-8"}
        assert app._get_api_version(environ) == 1


class TestPathParsing(TestResticRESTApp):
    """Tests for path parsing."""

    def test_parse_empty_path(self):
        """Test parsing empty path."""
        app = self._create_app()
        assert app._parse_path("") == ("", None, None)
        assert app._parse_path("/") == ("", None, None)

    def test_parse_repo_path_only(self):
        """Test parsing path with only repo name."""
        app = self._create_app()
        assert app._parse_path("/myrepo") == ("myrepo", None, None)

    def test_parse_config_path(self):
        """Test parsing config path."""
        app = self._create_app()
        assert app._parse_path("/myrepo/config") == ("myrepo", "config", None)

    def test_parse_type_listing_path(self):
        """Test parsing type listing paths."""
        app = self._create_app()
        assert app._parse_path("/myrepo/data") == ("myrepo", "data", None)
        assert app._parse_path("/myrepo/keys") == ("myrepo", "keys", None)
        assert app._parse_path("/myrepo/locks") == ("myrepo", "locks", None)
        assert app._parse_path("/myrepo/snapshots") == ("myrepo", "snapshots", None)
        assert app._parse_path("/myrepo/index") == ("myrepo", "index", None)

    def test_parse_type_listing_with_trailing_slash(self):
        """Test parsing type listing paths with trailing slash."""
        app = self._create_app()
        # Trailing slash should be stripped
        assert app._parse_path("/myrepo/keys/") == ("myrepo", "keys", None)

    def test_parse_blob_path(self):
        """Test parsing blob paths."""
        app = self._create_app()
        assert app._parse_path("/myrepo/keys/abc123") == ("myrepo", "keys", "abc123")
        assert app._parse_path("/myrepo/locks/xyz789") == ("myrepo", "locks", "xyz789")

    def test_parse_data_blob_with_subdir(self):
        """Test parsing data blob paths with subdirectories."""
        app = self._create_app()
        # Data blobs have 2-char subdirectories
        assert app._parse_path("/myrepo/data/00/abc123") == ("myrepo", "data", "abc123")
        assert app._parse_path("/myrepo/data/ff/xyz789") == ("myrepo", "data", "xyz789")

    def test_parse_nested_repo_path(self):
        """Test parsing nested repository paths."""
        app = self._create_app()
        assert app._parse_path("/backups/myrepo/config") == (
            "backups/myrepo",
            "config",
            None,
        )
        assert app._parse_path("/backups/myrepo/keys/abc") == (
            "backups/myrepo",
            "keys",
            "abc",
        )


class TestAuthentication(TestResticRESTApp):
    """Tests for authentication."""

    def test_no_auth_required(self):
        """Test that no auth is required when not configured."""
        app = self._create_app()
        assert app._check_auth({}) is True

    def test_auth_missing_when_required(self):
        """Test that missing auth fails when required."""
        app = self._create_app(username="user", password="pass")
        assert app._check_auth({}) is False

    def test_auth_wrong_scheme(self):
        """Test that wrong auth scheme fails."""
        app = self._create_app(username="user", password="pass")
        environ = {"HTTP_AUTHORIZATION": "Bearer token123"}
        assert app._check_auth(environ) is False

    def test_auth_invalid_base64(self):
        """Test that invalid base64 fails."""
        app = self._create_app(username="user", password="pass")
        environ = {"HTTP_AUTHORIZATION": "Basic !!!invalid!!!"}
        assert app._check_auth(environ) is False

    def test_auth_wrong_credentials(self):
        """Test that wrong credentials fail."""
        app = self._create_app(username="user", password="pass")
        wrong_creds = base64.b64encode(b"wrong:creds").decode()
        environ = {"HTTP_AUTHORIZATION": f"Basic {wrong_creds}"}
        assert app._check_auth(environ) is False

    def test_auth_correct_credentials(self):
        """Test that correct credentials succeed."""
        app = self._create_app(username="user", password="pass")
        correct_creds = base64.b64encode(b"user:pass").decode()
        environ = {"HTTP_AUTHORIZATION": f"Basic {correct_creds}"}
        assert app._check_auth(environ) is True

    def test_auth_password_with_colon(self):
        """Test that passwords containing colons work."""
        app = self._create_app(username="user", password="pass:word:extra")
        creds = base64.b64encode(b"user:pass:word:extra").decode()
        environ = {"HTTP_AUTHORIZATION": f"Basic {creds}"}
        assert app._check_auth(environ) is True


class TestResponseHelpers(TestResticRESTApp):
    """Tests for response helper methods."""

    def test_send_response_with_body(self):
        """Test sending response with body."""
        app = self._create_app()
        headers = []

        def start_response(status, h):
            headers.extend(h)

        result = app._send_response(start_response, "200 OK", body=b"Hello")
        assert result == [b"Hello"]
        assert ("Content-Length", "5") in headers

    def test_send_response_without_body(self):
        """Test sending response without body."""
        app = self._create_app()
        headers = []

        def start_response(status, h):
            headers.extend(h)

        result = app._send_response(start_response, "204 No Content")
        assert result == [b""]
        assert ("Content-Length", "0") in headers

    def test_send_json_v1(self):
        """Test sending JSON response with API v1."""
        from pyrestserver.constants import API_V1_MEDIA_TYPE

        app = self._create_app()
        headers = []

        def start_response(status, h):
            headers.extend(h)

        data = ["item1", "item2"]
        result = app._send_json(start_response, "200 OK", data, api_version=1)
        assert json.loads(result[0]) == data
        assert ("Content-Type", API_V1_MEDIA_TYPE) in headers

    def test_send_json_v2(self):
        """Test sending JSON response with API v2."""
        from pyrestserver.constants import API_V2_MEDIA_TYPE

        app = self._create_app()
        headers = []

        def start_response(status, h):
            headers.extend(h)

        data = [{"name": "item1", "size": 100}]
        result = app._send_json(start_response, "200 OK", data, api_version=2)
        assert json.loads(result[0]) == data
        assert ("Content-Type", API_V2_MEDIA_TYPE) in headers


class TestRepositoryOperations(TestResticRESTApp):
    """Tests for repository operations."""

    def test_create_repo_success(self):
        """Test successful repository creation."""
        app = self._create_app()
        self.mock_provider.repository_exists.return_value = False
        self.mock_provider.create_repository.return_value = True

        status, headers, body = self._make_request(
            app, "POST", "/myrepo", query_string="create=true"
        )
        assert status == "200 OK"
        self.mock_provider.create_repository.assert_called_once_with("myrepo")

    def test_create_repo_already_exists(self):
        """Test creating repository that already exists."""
        app = self._create_app()
        self.mock_provider.repository_exists.return_value = True

        status, headers, body = self._make_request(
            app, "POST", "/myrepo", query_string="create=true"
        )
        assert status == "200 OK"
        self.mock_provider.create_repository.assert_not_called()

    def test_create_repo_readonly_forbidden(self):
        """Test that repository creation is forbidden in readonly mode."""
        app = self._create_app(readonly=True)

        status, headers, body = self._make_request(
            app, "POST", "/myrepo", query_string="create=true"
        )
        assert status == "403 Forbidden"

    def test_delete_repo_success(self):
        """Test successful repository deletion."""
        app = self._create_app()
        self.mock_provider.delete_repository.return_value = True

        status, headers, body = self._make_request(app, "DELETE", "/myrepo")
        assert status == "200 OK"
        self.mock_provider.delete_repository.assert_called_once_with("myrepo")

    def test_delete_repo_not_found(self):
        """Test deleting non-existent repository."""
        app = self._create_app()
        self.mock_provider.delete_repository.return_value = False

        status, headers, body = self._make_request(app, "DELETE", "/myrepo")
        assert status == "404 Not Found"


class TestConfigOperations(TestResticRESTApp):
    """Tests for config operations."""

    def test_head_config_exists(self):
        """Test HEAD request for existing config."""
        app = self._create_app()
        self.mock_provider.config_exists.return_value = (True, 256)

        status, headers, body = self._make_request(app, "HEAD", "/myrepo/config")
        assert status == "200 OK"
        assert ("Content-Length", "256") in headers

    def test_head_config_not_found(self):
        """Test HEAD request for non-existent config."""
        app = self._create_app()
        self.mock_provider.config_exists.return_value = (False, 0)

        status, headers, body = self._make_request(app, "HEAD", "/myrepo/config")
        assert status == "404 Not Found"

    def test_get_config_success(self):
        """Test GET request for config."""
        app = self._create_app()
        config_data = b"config content"
        self.mock_provider.get_config.return_value = config_data

        status, headers, body = self._make_request(app, "GET", "/myrepo/config")
        assert status == "200 OK"
        assert body == config_data

    def test_get_config_not_found(self):
        """Test GET request for non-existent config."""
        app = self._create_app()
        self.mock_provider.get_config.return_value = None

        status, headers, body = self._make_request(app, "GET", "/myrepo/config")
        assert status == "404 Not Found"

    def test_save_config_success(self):
        """Test POST request to save config."""
        app = self._create_app()
        self.mock_provider.save_config.return_value = True
        config_data = b"new config"

        status, headers, body = self._make_request(
            app, "POST", "/myrepo/config", body=config_data
        )
        assert status == "200 OK"
        self.mock_provider.save_config.assert_called_once_with("myrepo", config_data)

    def test_save_config_readonly_forbidden(self):
        """Test that saving config is forbidden in readonly mode."""
        app = self._create_app(readonly=True)

        status, headers, body = self._make_request(
            app, "POST", "/myrepo/config", body=b"config"
        )
        assert status == "403 Forbidden"


class TestBlobListOperations(TestResticRESTApp):
    """Tests for blob listing operations."""

    def test_list_blobs_v1(self):
        """Test listing blobs with API v1 (returns names only)."""
        app = self._create_app()
        self.mock_provider.list_blobs.return_value = [
            {"name": "blob1", "size": 100},
            {"name": "blob2", "size": 200},
        ]

        status, headers, body = self._make_request(app, "GET", "/myrepo/keys")
        assert status == "200 OK"
        data = json.loads(body)
        # V1 returns just names
        assert data == ["blob1", "blob2"]

    def test_list_blobs_v2(self):
        """Test listing blobs with API v2 (returns name and size)."""
        from pyrestserver.constants import API_V2_MEDIA_TYPE

        app = self._create_app()
        blobs = [
            {"name": "blob1", "size": 100},
            {"name": "blob2", "size": 200},
        ]
        self.mock_provider.list_blobs.return_value = blobs

        status, headers, body = self._make_request(
            app, "GET", "/myrepo/keys", headers={"Accept": API_V2_MEDIA_TYPE}
        )
        assert status == "200 OK"
        data = json.loads(body)
        # V2 returns full objects
        assert data == blobs

    def test_list_blobs_empty(self):
        """Test listing blobs when folder is empty."""
        app = self._create_app()
        self.mock_provider.list_blobs.return_value = []

        status, headers, body = self._make_request(app, "GET", "/myrepo/keys")
        assert status == "200 OK"
        assert json.loads(body) == []

    def test_list_blobs_not_found(self):
        """Test listing blobs for non-existent type folder."""
        app = self._create_app()
        self.mock_provider.list_blobs.return_value = None

        status, headers, body = self._make_request(app, "GET", "/myrepo/keys")
        assert status == "404 Not Found"


class TestBlobOperations(TestResticRESTApp):
    """Tests for individual blob operations."""

    def test_head_blob_exists(self):
        """Test HEAD request for existing blob."""
        app = self._create_app()
        self.mock_provider.blob_exists.return_value = (True, 1024)

        status, headers, body = self._make_request(app, "HEAD", "/myrepo/keys/abc123")
        assert status == "200 OK"
        assert ("Content-Length", "1024") in headers

    def test_head_blob_not_found(self):
        """Test HEAD request for non-existent blob."""
        app = self._create_app()
        self.mock_provider.blob_exists.return_value = (False, 0)

        status, headers, body = self._make_request(app, "HEAD", "/myrepo/keys/abc123")
        assert status == "404 Not Found"

    def test_get_blob_success(self):
        """Test GET request for blob content."""
        app = self._create_app()
        blob_data = b"blob content"
        self.mock_provider.get_blob.return_value = blob_data

        status, headers, body = self._make_request(app, "GET", "/myrepo/keys/abc123")
        assert status == "200 OK"
        assert body == blob_data
        assert ("Accept-Ranges", "bytes") in headers

    def test_get_blob_not_found(self):
        """Test GET request for non-existent blob."""
        app = self._create_app()
        self.mock_provider.get_blob.return_value = None

        status, headers, body = self._make_request(app, "GET", "/myrepo/keys/abc123")
        assert status == "404 Not Found"

    def test_save_blob_success(self):
        """Test POST request to save blob."""
        app = self._create_app()
        self.mock_provider.save_blob.return_value = True
        blob_data = b"new blob"

        status, headers, body = self._make_request(
            app, "POST", "/myrepo/keys/abc123", body=blob_data
        )
        assert status == "200 OK"
        self.mock_provider.save_blob.assert_called_once_with(
            "myrepo", "keys", "abc123", blob_data
        )

    def test_save_blob_readonly_forbidden(self):
        """Test that saving blob is forbidden in readonly mode."""
        app = self._create_app(readonly=True)

        status, headers, body = self._make_request(
            app, "POST", "/myrepo/keys/abc123", body=b"data"
        )
        assert status == "403 Forbidden"

    def test_delete_blob_success(self):
        """Test DELETE request for blob."""
        app = self._create_app()
        self.mock_provider.delete_blob.return_value = True

        status, headers, body = self._make_request(app, "DELETE", "/myrepo/keys/abc123")
        assert status == "200 OK"
        self.mock_provider.delete_blob.assert_called_once_with(
            "myrepo", "keys", "abc123"
        )

    def test_delete_blob_not_found(self):
        """Test DELETE request for non-existent blob."""
        app = self._create_app()
        self.mock_provider.delete_blob.return_value = False

        status, headers, body = self._make_request(app, "DELETE", "/myrepo/keys/abc123")
        assert status == "404 Not Found"


class TestRangeRequests(TestResticRESTApp):
    """Tests for HTTP range requests."""

    def test_range_request_full_range(self):
        """Test range request with start and end."""
        app = self._create_app()
        blob_data = b"0123456789"
        self.mock_provider.get_blob.return_value = blob_data

        status, headers, body = self._make_request(
            app, "GET", "/myrepo/keys/abc123", headers={"Range": "bytes=2-5"}
        )
        assert status == "206 Partial Content"
        assert body == b"2345"
        assert ("Content-Range", "bytes 2-5/10") in headers

    def test_range_request_open_end(self):
        """Test range request with only start (open end)."""
        app = self._create_app()
        blob_data = b"0123456789"
        self.mock_provider.get_blob.return_value = blob_data

        status, headers, body = self._make_request(
            app, "GET", "/myrepo/keys/abc123", headers={"Range": "bytes=7-"}
        )
        assert status == "206 Partial Content"
        assert body == b"789"
        assert ("Content-Range", "bytes 7-9/10") in headers

    def test_range_request_suffix(self):
        """Test range request for last N bytes."""
        app = self._create_app()
        blob_data = b"0123456789"
        self.mock_provider.get_blob.return_value = blob_data

        status, headers, body = self._make_request(
            app, "GET", "/myrepo/keys/abc123", headers={"Range": "bytes=-3"}
        )
        assert status == "206 Partial Content"
        assert body == b"789"
        assert ("Content-Range", "bytes 7-9/10") in headers

    def test_range_request_invalid_range(self):
        """Test range request with invalid range."""
        app = self._create_app()
        blob_data = b"0123456789"
        self.mock_provider.get_blob.return_value = blob_data

        status, headers, body = self._make_request(
            app, "GET", "/myrepo/keys/abc123", headers={"Range": "bytes=15-20"}
        )
        assert status == "416 Range Not Satisfiable"


class TestUnauthorizedAccess(TestResticRESTApp):
    """Tests for unauthorized access handling."""

    def test_unauthorized_returns_401(self):
        """Test that missing auth returns 401 with WWW-Authenticate header."""
        app = self._create_app(username="user", password="pass")

        status, headers, body = self._make_request(app, "GET", "/myrepo/config")
        assert status == "401 Unauthorized"
        assert any(h[0] == "WWW-Authenticate" for h in headers)


class TestErrorHandling(TestResticRESTApp):
    """Tests for error handling."""

    def test_internal_error_returns_500(self):
        """Test that internal errors return 500."""
        app = self._create_app()
        self.mock_provider.get_config.side_effect = Exception("Internal error")

        status, headers, body = self._make_request(app, "GET", "/myrepo/config")
        assert status == "500 Internal Server Error"

    def test_unknown_path_returns_404(self):
        """Test that unknown paths return 404."""
        app = self._create_app()

        status, headers, body = self._make_request(app, "GET", "/myrepo/unknown")
        assert status == "404 Not Found"


class TestUploadVerification(TestResticRESTApp):
    """Tests for upload hash verification."""

    def test_data_blob_upload_with_matching_hash_succeeds(self):
        """Test that data blob upload with matching SHA-256 hash succeeds."""
        import hashlib

        app = self._create_app()
        self.mock_provider.save_blob.return_value = True

        # Create test data and calculate its hash
        blob_data = b"test data content for hash verification"
        calculated_hash = hashlib.sha256(blob_data).hexdigest()

        # Upload with matching hash - use first 2 chars for subdir
        status, headers, body = self._make_request(
            app,
            "POST",
            f"/myrepo/data/{calculated_hash[:2]}/{calculated_hash}",
            body=blob_data,
        )
        assert status == "200 OK"
        self.mock_provider.save_blob.assert_called_once_with(
            "myrepo", "data", calculated_hash, blob_data
        )

    def test_data_blob_upload_with_mismatching_hash_fails(self):
        """Test that data blob upload with mismatching hash returns 400."""
        app = self._create_app()

        # Use incorrect hash
        blob_data = b"test data content"
        wrong_hash = "0" * 64  # Invalid hash

        status, headers, body = self._make_request(
            app, "POST", f"/myrepo/data/00/{wrong_hash}", body=blob_data
        )
        assert status == "400 Bad Request"
        assert b"Content hash does not match blob name" in body
        # Provider should not be called
        self.mock_provider.save_blob.assert_not_called()

    def test_data_blob_upload_with_no_verify_allows_mismatch(self):
        """Test that --no-verify-upload disables hash verification."""
        app = self._create_app()
        # Enable no_verify_upload
        app.no_verify_upload = True
        self.mock_provider.save_blob.return_value = True

        # Upload with wrong hash should succeed when verification is disabled
        blob_data = b"test data content"
        wrong_hash = "0" * 64

        status, headers, body = self._make_request(
            app, "POST", f"/myrepo/data/00/{wrong_hash}", body=blob_data
        )
        assert status == "200 OK"
        # Provider should be called even with wrong hash
        self.mock_provider.save_blob.assert_called_once_with(
            "myrepo", "data", wrong_hash, blob_data
        )

    def test_verification_only_applies_to_data_blobs(self):
        """Test that hash verification only applies to data blob type."""

        app = self._create_app()
        self.mock_provider.save_blob.return_value = True

        # Test non-data blob types (keys, locks, snapshots, index)
        blob_data = b"test content"
        # Use hash that doesn't match the data
        wrong_hash = "0" * 64

        for blob_type in ["keys", "locks", "snapshots", "index"]:
            self.mock_provider.save_blob.reset_mock()

            status, headers, body = self._make_request(
                app, "POST", f"/myrepo/{blob_type}/{wrong_hash}", body=blob_data
            )
            # Should succeed because verification is only for data blobs
            assert status == "200 OK", f"Failed for blob type: {blob_type}"
            self.mock_provider.save_blob.assert_called_once()

    def test_empty_data_blob_upload_fails_verification(self):
        """Test that empty data uploads fail hash verification."""
        app = self._create_app()

        # Empty data has hash:
        # e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        wrong_hash = "0" * 64

        # Empty data with wrong hash should fail
        status, headers, body = self._make_request(
            app, "POST", f"/myrepo/data/00/{wrong_hash}", body=b""
        )
        assert status == "400 Bad Request"

        # Empty data with correct hash should succeed
        self.mock_provider.save_blob.return_value = True
        status, headers, body = self._make_request(
            app, "POST", f"/myrepo/data/{empty_hash[:2]}/{empty_hash}", body=b""
        )
        assert status == "200 OK"

    def test_large_data_blob_hash_verification(self):
        """Test hash verification works for larger data blobs."""
        import hashlib

        app = self._create_app()
        self.mock_provider.save_blob.return_value = True

        # Create larger test data (1MB)
        blob_data = b"x" * (1024 * 1024)
        calculated_hash = hashlib.sha256(blob_data).hexdigest()

        status, headers, body = self._make_request(
            app,
            "POST",
            f"/myrepo/data/{calculated_hash[:2]}/{calculated_hash}",
            body=blob_data,
        )
        assert status == "200 OK"
        self.mock_provider.save_blob.assert_called_once()

    def test_config_upload_bypasses_verification(self):
        """Test that config file uploads bypass hash verification."""
        app = self._create_app()
        self.mock_provider.save_config.return_value = True

        # Config file doesn't use hash-based naming
        config_data = b"config content"

        status, headers, body = self._make_request(
            app, "POST", "/myrepo/config", body=config_data
        )
        # Should succeed regardless of content
        assert status == "200 OK"
        self.mock_provider.save_config.assert_called_once_with("myrepo", config_data)

    def test_verification_metrics_counters(self):
        """Test that verification success/failure counters are incremented."""
        import hashlib

        app = self._create_app()
        self.mock_provider.save_blob.return_value = True

        # Initial counters should be zero
        assert app._upload_verification_successes == 0
        assert app._upload_verification_failures == 0

        # Upload with matching hash
        blob_data = b"test data"
        correct_hash = hashlib.sha256(blob_data).hexdigest()
        status, headers, body = self._make_request(
            app,
            "POST",
            f"/myrepo/data/{correct_hash[:2]}/{correct_hash}",
            body=blob_data,
        )
        assert status == "200 OK"
        assert app._upload_verification_successes == 1
        assert app._upload_verification_failures == 0

        # Upload with mismatching hash
        wrong_hash = "0" * 64
        status, headers, body = self._make_request(
            app, "POST", f"/myrepo/data/00/{wrong_hash}", body=blob_data
        )
        assert status == "400 Bad Request"
        assert app._upload_verification_successes == 1
        assert app._upload_verification_failures == 1

        # Another successful upload
        blob_data2 = b"more test data"
        correct_hash2 = hashlib.sha256(blob_data2).hexdigest()
        status, headers, body = self._make_request(
            app,
            "POST",
            f"/myrepo/data/{correct_hash2[:2]}/{correct_hash2}",
            body=blob_data2,
        )
        assert status == "200 OK"
        assert app._upload_verification_successes == 2
        assert app._upload_verification_failures == 1
