"""Shared constants for restic REST API."""

# Valid restic blob types
VALID_TYPES = {"data", "keys", "locks", "snapshots", "index", "config"}

# API version media types
API_V1_MEDIA_TYPE = "application/vnd.x.restic.rest.v1"
API_V2_MEDIA_TYPE = "application/vnd.x.restic.rest.v2"

# Default server configuration
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
