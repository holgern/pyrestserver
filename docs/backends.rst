Storage Backends
================

PyRestServer supports multiple storage backends through a pluggable architecture.

Overview
--------

All storage backends implement the ``StorageProvider`` interface, allowing PyRestServer to work with different storage systems transparently.

Available backends:

- **Local Filesystem** - Store data on local disk (built-in)
- **Drime Cloud** - Store data in Drime Cloud storage (requires pydrime)

Local Filesystem Backend
-------------------------

The local backend stores repository data in a directory structure on the local filesystem.

Configuration
~~~~~~~~~~~~~

Start with local backend:

.. code-block:: bash

   pyrestserver serve --path /srv/restic

Or configure:

.. code-block:: bash

   pyrestserver config add mylocal \
       --type local \
       --path /srv/restic

Directory Structure
~~~~~~~~~~~~~~~~~~~

The local backend creates the following structure:

.. code-block:: text

   /srv/restic/
   ├── repo1/
   │   ├── config              # Repository configuration
   │   ├── data/               # Data blobs
   │   │   ├── 00/            # Subdirectory for blobs starting with 00
   │   │   ├── 01/
   │   │   ├── ...
   │   │   └── ff/
   │   ├── index/              # Index files
   │   ├── keys/               # Encryption keys
   │   ├── locks/              # Lock files
   │   └── snapshots/          # Snapshot metadata
   └── repo2/
       └── ...

Permissions
~~~~~~~~~~~

Files and directories are created with secure permissions:

- **Directories:** ``0700`` (rwx------)
- **Files:** ``0600`` (rw-------)

This ensures only the owner can access the backup data.

Pros and Cons
~~~~~~~~~~~~~

**Advantages:**

✅ Simple and fast
✅ No external dependencies
✅ Easy to backup (standard filesystem)
✅ Works offline
✅ Full control over data

**Disadvantages:**

❌ Limited to single machine (without NFS/CIFS)
❌ No built-in redundancy
❌ Requires sufficient local disk space

Best For
~~~~~~~~

- Single-server backups
- Local network backups
- Development and testing
- On-premise deployments

Drime Cloud Backend
-------------------

The Drime backend stores repository data in Drime Cloud storage.

Prerequisites
~~~~~~~~~~~~~

Install with Drime support:

.. code-block:: bash

   pip install pyrestserver[drime]

Configuration
~~~~~~~~~~~~~

Configure Drime backend:

.. code-block:: bash

   pyrestserver config add mydrime \
       --type drime \
       --api-key "your-api-key" \
       --workspace-id 0

Or use environment variables:

.. code-block:: bash

   export DRIME_API_KEY="your-api-key"

   pyrestserver serve --backend drime --workspace-id 0

Configuration Options
~~~~~~~~~~~~~~~~~~~~~

- ``api_key`` - Drime API authentication key (required)
- ``workspace_id`` - Workspace ID (default: 0 for personal workspace)

Read the configuration from backends.toml:

.. code-block:: bash

   pyrestserver serve --backend-config mydrime

Storage Structure
~~~~~~~~~~~~~~~~~

The Drime backend creates the same structure as local backend, but in Drime Cloud:

.. code-block:: text

   Workspace 0/
   ├── repo1/
   │   ├── config
   │   ├── data/
   │   │   ├── 00/
   │   │   └── ...
   │   ├── index/
   │   ├── keys/
   │   ├── locks/
   │   └── snapshots/
   └── repo2/
       └── ...

Features
~~~~~~~~

- **Folder caching** - Reduces API calls by caching folder IDs
- **Workspace support** - Use different workspaces for organization
- **Automatic folder creation** - Creates repository structure automatically
- **Hash-based deduplication** - Drime's content-addressable storage

Pros and Cons
~~~~~~~~~~~~~

**Advantages:**

✅ Cloud storage - accessible from anywhere
✅ Built-in redundancy
✅ No local disk space needed
✅ Automatic backups and versioning (Drime features)
✅ Scalable storage

**Disadvantages:**

❌ Requires internet connection
❌ API rate limits may apply
❌ Depends on Drime service availability
❌ Additional cost for storage

Best For
~~~~~~~~

- Remote backups
- Multi-location backups
- Cloud-first deployments
- Organizations using Drime

Performance
~~~~~~~~~~~

The Drime backend includes optimizations:

- **Folder ID caching** - Reduces API calls for repeated operations
- **Batch operations** - Where supported by Drime API
- **Connection pooling** - Reuses HTTP connections

Typical performance (depends on network and API):

- Upload: 5-20 MB/s
- Download: 10-30 MB/s
- Small file operations: 50-200 per second

Backend Comparison
------------------

.. list-table::
   :header-rows: 1
   :widths: 20 20 20 20 20

   * - Feature
     - Local
     - Drime
   * - Setup Complexity
     - Simple
     - Moderate
   * - Performance
     - Fast
     - Medium
   * - Cost
     - Disk space
     - Storage + API
   * - Redundancy
     - Manual
     - Built-in
   * - Remote Access
     - No
     - Yes
   * - Dependencies
     - None
     - pydrime

Backend Selection
-----------------

Choose based on your requirements:

**Use Local backend if:**

- You have a dedicated backup server
- You want maximum performance
- You're backing up to NAS/SAN
- You prefer offline/air-gapped backups
- Cost is a primary concern

**Use Drime backend if:**

- You need cloud storage
- You want off-site backups
- You're already using Drime
- You need multi-location access
- You want managed storage

**Hybrid Approach:**

You can use both backends:

.. code-block:: bash

   # Primary backup to local
   restic -r rest:http://localhost:8000/main backup /data

   # Secondary backup to cloud
   restic -r rest:http://localhost:8001/cloud backup /data

Storage Provider Interface
--------------------------

All backends implement the ``StorageProvider`` abstract base class.

Core Methods
~~~~~~~~~~~~

.. code-block:: python

   class StorageProvider(ABC):
       def repository_exists(self, repo_path: str) -> bool:
           """Check if a repository exists."""

       def config_exists(self, repo_path: str) -> tuple[bool, int]:
           """Check if config exists, return (exists, size)."""

       def create_repository(self, repo_path: str) -> bool:
           """Create repository structure."""

       def get_config(self, repo_path: str) -> bytes | None:
           """Get repository config content."""

       def save_config(self, repo_path: str, data: bytes) -> bool:
           """Save repository config."""

       def list_blobs(self, repo_path: str, blob_type: str) -> list[dict] | None:
           """List blobs of a type."""

       def blob_exists(self, repo_path: str, blob_type: str, name: str) -> tuple[bool, int]:
           """Check if blob exists, return (exists, size)."""

       def get_blob(self, repo_path: str, blob_type: str, name: str) -> bytes | None:
           """Get blob content."""

       def save_blob(self, repo_path: str, blob_type: str, name: str, data: bytes) -> bool:
           """Save blob content."""

       def delete_blob(self, repo_path: str, blob_type: str, name: str) -> bool:
           """Delete a blob."""

       def is_readonly(self) -> bool:
           """Check if provider is read-only."""

Creating Custom Backends
~~~~~~~~~~~~~~~~~~~~~~~~~

See :doc:`custom_backends` for details on implementing your own storage backend.

Configuration Management
------------------------

Backend configurations are stored using vaultconfig with custom cipher keys.

Configuration File
~~~~~~~~~~~~~~~~~~

Location: ``~/.config/pyrestserver/backends.toml``

Format:

.. code-block:: toml

   [backend-name]
   type = "local"  # or "drime"
   # Backend-specific options

   [another-backend]
   type = "drime"
   api_key = "obscured-value"
   workspace_id = 0

Security
~~~~~~~~

- Sensitive values (API keys, passwords) are automatically obscured
- Custom cipher key unique to pyrestserver
- File permissions protect configuration
- See :doc:`security` for more details

Managing Multiple Backends
---------------------------

You can configure multiple backends and switch between them:

.. code-block:: bash

   # Configure backends
   pyrestserver config add local-main --type local --path /srv/restic
   pyrestserver config add local-archive --type local --path /archive/restic
   pyrestserver config add cloud-backup --type drime --api-key "key"

   # Start with different backends
   pyrestserver serve --backend-config local-main
   pyrestserver serve --backend-config cloud-backup --listen :8001

This allows you to:

- Run multiple instances on different ports
- Separate production/staging/development
- Implement backup strategies with multiple destinations

Next Steps
----------

- Learn to implement :doc:`custom_backends`
- Review :doc:`security` for production deployments
- Check :doc:`benchmarks` for performance testing
