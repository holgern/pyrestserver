[![PyPI - Version](https://img.shields.io/pypi/v/pyrestserver)](https://pypi.org/project/pyrestserver/)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pyrestserver)
![PyPI - Downloads](https://img.shields.io/pypi/dm/pyrestserver)
[![codecov](https://codecov.io/gh/holgern/pyrestserver/graph/badge.svg?token=iCHXwbjAXG)](https://codecov.io/gh/holgern/pyrestserver)

# pyrestserver

REST API server for [restic](https://restic.net/) backup software with pluggable storage
backends.

This package provides a Python implementation of the restic REST API with support for
multiple storage backends, including local filesystem and Drime Cloud storage.

## Features

- **REST API compatible with restic** - Drop-in replacement for
  [rest-server](https://github.com/restic/rest-server)
- **Upload verification** - SHA-256 hash verification for data integrity (enabled by
  default)
- **Pluggable storage backends** - Support for local filesystem and cloud storage
  (Drime)
- **Authentication** - htpasswd-based authentication support
- **Append-only mode** - Prevent deletion of existing backups
- **TLS support** - Secure communication with TLS/SSL
- **Prometheus metrics** - Built-in metrics endpoint (basic implementation)

## Installation

### Basic Installation (Local filesystem only)

```bash
pip install pyrestserver
```

### With Drime Cloud Backend

```bash
pip install pyrestserver[drime]
```

### Development Installation

```bash
git clone <repository-url>
cd pyrestserver
pip install -e ".[dev,drime]"
```

## Quick Start

### Local Filesystem Backend

Start a REST server with local filesystem storage:

```bash
# Start server with default settings (no auth, data in /tmp/restic)
pyrestserver --path /tmp/restic --no-auth

# Start with authentication
pyrestserver --path /srv/restic --htpasswd-file /etc/restic/htpasswd

# Start with TLS
pyrestserver --path /srv/restic \
  --tls \
  --tls-cert /etc/restic/cert.pem \
  --tls-key /etc/restic/key.pem

# Start in append-only mode (prevents deletion)
pyrestserver --path /srv/restic --append-only
```

### Drime Cloud Backend

Start a REST server with Drime Cloud storage:

```bash
# Set environment variables for Drime authentication
export DRIME_USERNAME="your-username"
export DRIME_PASSWORD="your-password"

# Start server with Drime backend
pyrestserver --backend drime \
  --workspace-id 0 \
  --no-auth
```

### Using with restic

Once the server is running, configure restic to use it:

```bash
# Initialize a new repository
restic -r rest:http://localhost:8000/myrepo init

# Create a backup
restic -r rest:http://localhost:8000/myrepo backup /path/to/data

# List snapshots
restic -r rest:http://localhost:8000/myrepo snapshots

# Restore a backup
restic -r rest:http://localhost:8000/myrepo restore latest --target /restore/path
```

With authentication:

```bash
# Use --username and --password or set RESTIC_REST_USERNAME and RESTIC_REST_PASSWORD
export RESTIC_REST_USERNAME=myuser
export RESTIC_REST_PASSWORD=mypassword

restic -r rest:http://localhost:8000/myrepo snapshots
```

## Command Line Interface

The `pyrestserver` command provides a CLI interface matching the original rest-server:

```
Usage: pyrestserver [OPTIONS]

Options:
  --path PATH                     Data directory (default: /tmp/restic)
  --listen ADDRESS                Listen address (default: :8000)
  --no-auth                       Disable authentication
  --htpasswd-file PATH            Path to htpasswd file
  --tls                           Enable TLS
  --tls-cert PATH                 Path to TLS certificate
  --tls-key PATH                  Path to TLS private key
  --append-only                   Enable append-only mode
  --private-repos                 Enable private repositories mode
  --no-verify-upload              Disable upload integrity verification (not recommended)
  --debug                         Enable debug logging
  --prometheus                    Enable Prometheus metrics
  --prometheus-no-auth            Disable auth for metrics endpoint
  --backend {local,drime}         Storage backend (default: local)
  --workspace-id INTEGER          Drime workspace ID (default: 0)
  --help                          Show this message and exit
```

### Authentication

Create an htpasswd file for authentication:

```bash
# Using htpasswd (from apache2-utils)
htpasswd -c /etc/restic/htpasswd myuser

# Or use Python's htpasswd library
python -c "import bcrypt; print('myuser:' + bcrypt.hashpw(b'mypassword', bcrypt.gensalt()).decode())"
```

## Upload Verification

By default, pyrestserver verifies the integrity of uploaded data blobs by checking that
the SHA-256 hash of the uploaded content matches the hash specified in the URL. This
provides protection against data corruption during transmission and storage.

### How it works

- When restic uploads a data blob to `/data/ab/abc123...`, the filename (`abc123...`) is
  the SHA-256 hash of the content
- pyrestserver calculates the SHA-256 hash of the uploaded data and compares it with the
  filename
- If they don't match, the upload is rejected with HTTP 400 Bad Request
- Only `data` blobs are verified (keys, locks, snapshots, and index files use different
  naming schemes)

### Security Benefits

- **Data integrity**: Prevents corrupted uploads from being stored
- **Early detection**: Catches transmission errors before data is saved
- **Compatibility**: Matches the behavior of the Go-based rest-server

### Disabling Verification (Not Recommended)

For low-power devices where SHA-256 hashing may be too CPU-intensive, you can disable
verification:

```bash
# Disable upload verification (NOT recommended for production)
pyrestserver --path /srv/restic --no-verify-upload
```

**⚠️ Warning**: Only disable verification if you're running on a very low-power device
(e.g., Raspberry Pi Zero) and understand the security implications. Modern CPUs handle
SHA-256 hashing with minimal overhead.

### Metrics

Upload verification failures are tracked in Prometheus metrics (when enabled) as
`restic_upload_verification_failures_total`.

## Programmatic Usage

You can also use pyrestserver as a library in your Python code:

### Basic WSGI Application

```python
from pyrestserver import ResticRESTApp
from pyrestserver.providers.local import LocalStorageProvider

# Create a storage provider
provider = LocalStorageProvider(
    base_path="/srv/restic",
    readonly=False
)

# Create the WSGI application
app = ResticRESTApp(
    provider=provider,
    append_only=False,
    auth_required=False
)

# Use with any WSGI server (gunicorn, waitress, etc.)
```

### Custom Storage Backend

```python
from pyrestserver import StorageProvider

class MyCustomProvider(StorageProvider):
    """Custom storage provider implementation."""

    def repository_exists(self, repo_path: str) -> bool:
        # Implementation
        pass

    def config_exists(self, repo_path: str) -> tuple[bool, int]:
        # Implementation
        pass

    # Implement other required methods...
```

### Using Drime Backend

```python
from pydrime import DrimeClient
from pyrestserver import ResticRESTApp
from pyrestserver.providers.drime import DrimeStorageProvider

# Create Drime client
client = DrimeClient(
    username="your-username",
    password="your-password"
)

# Create Drime storage provider
provider = DrimeStorageProvider(
    client=client,
    workspace_id=0,
    readonly=False
)

# Create the WSGI application
app = ResticRESTApp(
    provider=provider,
    append_only=False,
    auth_required=False
)
```

## Storage Backends

### Local Filesystem

The local filesystem backend stores repository data in a directory structure:

```
/path/to/data/
├── repo1/
│   ├── config
│   ├── data/
│   │   ├── 00/
│   │   ├── 01/
│   │   └── ...
│   ├── index/
│   ├── keys/
│   ├── locks/
│   └── snapshots/
└── repo2/
    └── ...
```

Files are created with permissions:

- Directories: 0700 (owner read/write/execute)
- Files: 0600 (owner read/write)

### Drime Cloud

The Drime backend stores repository data in Drime Cloud storage with the same structure.
It uses the `pydrime` library to interact with the Drime API.

## API Endpoints

The REST API provides the following endpoints (compatible with restic):

- `GET /{repo}/config` - Get repository configuration
- `POST /{repo}/config` - Create repository configuration
- `HEAD /{repo}/config` - Check if repository exists
- `GET /{repo}/{type}` - List blobs of a type
- `GET /{repo}/{type}/{name}` - Get blob content
- `HEAD /{repo}/{type}/{name}` - Check if blob exists
- `POST /{repo}/{type}/{name}` - Upload blob
- `DELETE /{repo}/{type}/{name}` - Delete blob (not allowed in append-only mode)

Valid blob types: `data`, `index`, `keys`, `locks`, `snapshots`

## Metrics

Basic Prometheus metrics are available at `/metrics` (when enabled with `--prometheus`):

- `restic_repo_read_total` - Total repository read operations
- `restic_repo_write_total` - Total repository write operations
- (More metrics to be implemented)

## Development

### Running Tests

```bash
pytest
```

### Code Quality

```bash
# Run ruff linter
ruff check .

# Format code
ruff format .
```

## Differences from rest-server

This implementation aims to be compatible with the Go-based rest-server, with the
following differences:

1. **Storage backends**: Pluggable architecture allows for cloud storage backends
2. **Upload verification**: SHA-256 hash verification is implemented and enabled by
   default (matching rest-server v0.14.0+)
3. **Metrics**: Basic Prometheus metrics (more comprehensive metrics planned)
4. **Private repos**: Not fully implemented in v1
5. **Quotas**: Not implemented in v1
6. **Performance**: Python implementation may have different performance characteristics

## Architecture

### Storage Provider Interface

All storage backends implement the `StorageProvider` abstract base class:

```python
class StorageProvider(ABC):
    @abstractmethod
    def repository_exists(self, repo_path: str) -> bool:
        """Check if a repository exists."""

    @abstractmethod
    def config_exists(self, repo_path: str) -> tuple[bool, int]:
        """Check if config exists and return (exists, size)."""

    @abstractmethod
    def create_repository(self, repo_path: str) -> bool:
        """Create repository folder structure."""

    @abstractmethod
    def get_config(self, repo_path: str) -> bytes | None:
        """Get repository config content."""

    @abstractmethod
    def save_config(self, repo_path: str, data: bytes) -> bool:
        """Save repository config."""

    @abstractmethod
    def list_blobs(self, repo_path: str, blob_type: str) -> list[dict] | None:
        """List blobs of a given type."""

    @abstractmethod
    def blob_exists(self, repo_path: str, blob_type: str, name: str) -> tuple[bool, int]:
        """Check if blob exists and return (exists, size)."""

    @abstractmethod
    def get_blob(self, repo_path: str, blob_type: str, name: str) -> bytes | None:
        """Get blob content."""

    @abstractmethod
    def save_blob(self, repo_path: str, blob_type: str, name: str, data: bytes) -> bool:
        """Save blob content."""

    @abstractmethod
    def delete_blob(self, repo_path: str, blob_type: str, name: str) -> bool:
        """Delete a blob."""

    @abstractmethod
    def is_readonly(self) -> bool:
        """Check if provider is read-only."""
```

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Credits

- Based on the [restic REST server](https://github.com/restic/rest-server)
- Uses [pydrime](https://github.com/yourusername/pydrime) for Drime Cloud integration

## Links

- [restic](https://restic.net/) - Fast, secure, efficient backup program
- [rest-server](https://github.com/restic/rest-server) - Original Go-based REST server
- Documentation:
  [restic REST API](https://restic.readthedocs.io/en/stable/100_references.html#rest-backend)
