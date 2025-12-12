Configuration
=============

PyRestServer offers flexible configuration through command-line options, configuration files, and environment variables.

Backend Configuration
---------------------

PyRestServer uses vaultconfig to manage backend configurations with secure password obscuring.

Configuration Location
~~~~~~~~~~~~~~~~~~~~~~

Backend configurations are stored in:

- Linux/macOS: ``~/.config/pyrestserver/backends.toml``
- Windows: ``%APPDATA%\pyrestserver\backends.toml``

Interactive Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~

The easiest way to configure backends is using the interactive wizard:

.. code-block:: bash

   pyrestserver config

This launches an interactive session where you can:

- Add new backends
- List existing backends
- Remove backends
- Update backend settings

Managing Backends
~~~~~~~~~~~~~~~~~

**Add a backend:**

.. code-block:: bash

   # Local filesystem backend
   pyrestserver config add mylocal \
       --type local \
       --path /srv/restic

   # Drime Cloud backend
   pyrestserver config add mydrime \
       --type drime \
       --api-key "your-api-key" \
       --workspace-id 0

**List backends:**

.. code-block:: bash

   pyrestserver config list

**Remove a backend:**

.. code-block:: bash

   pyrestserver config remove mylocal

**Show backend details:**

.. code-block:: bash

   pyrestserver config show mylocal

Password Obscuring
~~~~~~~~~~~~~~~~~~

PyRestServer automatically obscures sensitive values (passwords, API keys) in configuration files using a custom cipher key.

**Important:** This is obfuscation, not encryption. It prevents casual viewing but is not cryptographically secure. For production security, use proper access controls and file permissions.

The obscuring uses a randomly generated cipher key unique to pyrestserver:

.. code-block:: python

   # In pyrestserver/config.py
   _PYRESTSERVER_CIPHER_KEY = "0a34b62682e9bae989fc36e770382b38..."

This means:

- Other applications cannot reveal pyrestserver passwords
- Passwords are not stored in plain text
- The cipher key is embedded in the package

Manual Configuration
~~~~~~~~~~~~~~~~~~~~

You can also manually edit the TOML configuration file:

.. code-block:: toml

   [mylocal]
   type = "local"
   path = "/srv/restic"

   [mydrime]
   type = "drime"
   api_key = "qO-l2HqnGGNrZM3ga4UI50iwySHFTmVl1pe2NW0oOxKQqBZWUw4"  # Obscured
   workspace_id = 0

Server Configuration
--------------------

Command-Line Options
~~~~~~~~~~~~~~~~~~~~

The ``pyrestserver serve`` command accepts various options:

**Storage Options:**

- ``--path PATH`` - Data directory for local backend
- ``--backend {local,drime}`` - Storage backend type
- ``--backend-config NAME`` - Use named backend from configuration

**Network Options:**

- ``--listen ADDRESS`` - Listen address (default: ``localhost:8000``)
- ``--tls`` - Enable TLS/SSL
- ``--tls-cert PATH`` - TLS certificate file
- ``--tls-key PATH`` - TLS private key file

**Authentication:**

- ``--no-auth`` - Disable authentication
- ``--htpasswd-file PATH`` - Path to htpasswd file
- ``--prometheus-no-auth`` - Disable auth for /metrics endpoint

**Repository Options:**

- ``--append-only`` - Enable append-only mode (prevents deletion)
- ``--private-repos`` - Enable private repositories per user

**Upload Verification:**

- ``--no-verify-upload`` - Disable upload integrity checking (not recommended)

**Monitoring:**

- ``--prometheus`` - Enable Prometheus metrics at /metrics
- ``--log PATH`` - Log file path (use "-" for stdout)

**Debug:**

- ``--debug`` - Enable debug logging

Environment Variables
~~~~~~~~~~~~~~~~~~~~~

PyRestServer respects several environment variables:

**Drime Backend:**

- ``DRIME_API_KEY`` - Drime API key
- ``DRIME_USERNAME`` - Drime username (if using username/password)
- ``DRIME_PASSWORD`` - Drime password (if using username/password)

**Restic Client:**

- ``RESTIC_PASSWORD`` - Repository password
- ``RESTIC_REST_USERNAME`` - HTTP Basic auth username
- ``RESTIC_REST_PASSWORD`` - HTTP Basic auth password

**Configuration:**

- ``PYRESTSERVER_CONFIG_DIR`` - Override default config directory

Authentication Setup
--------------------

htpasswd File
~~~~~~~~~~~~~

PyRestServer uses Apache-style htpasswd files for authentication.

**Create with htpasswd tool:**

.. code-block:: bash

   # Install htpasswd (from apache2-utils on Debian/Ubuntu)
   sudo apt-get install apache2-utils

   # Create htpasswd file
   htpasswd -B -c /etc/restic/htpasswd myuser

   # Add more users
   htpasswd -B /etc/restic/htpasswd anotheruser

**Create with Python:**

.. code-block:: python

   import bcrypt

   username = "myuser"
   password = b"mypassword"

   hashed = bcrypt.hashpw(password, bcrypt.gensalt())
   print(f"{username}:{hashed.decode()}")

**Use the obscure command:**

.. code-block:: bash

   # Obscure a password for configuration
   pyrestserver obscure
   Enter password: ********
   Obscured: qO-l2HqnGGNrZM3ga4UI50iwywySHFTmVl1pe2NW0oOxKQqBZWUw4

TLS/SSL Configuration
---------------------

Generate Self-Signed Certificate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For testing:

.. code-block:: bash

   openssl req -x509 -newkey rsa:4096 \
       -keyout key.pem \
       -out cert.pem \
       -days 365 \
       -nodes \
       -subj "/CN=localhost"

Start Server with TLS
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   pyrestserver serve --path /srv/restic \
       --tls \
       --tls-cert cert.pem \
       --tls-key key.pem

Use with restic:

.. code-block:: bash

   # With self-signed cert, disable verification or add to trust store
   restic -r rest:https://localhost:8000/myrepo \
       --cacert cert.pem \
       snapshots

Let's Encrypt
~~~~~~~~~~~~~

For production, use Let's Encrypt certificates:

.. code-block:: bash

   # Get certificate with certbot
   sudo certbot certonly --standalone -d backup.example.com

   # Start server
   pyrestserver serve --path /srv/restic \
       --listen :443 \
       --tls \
       --tls-cert /etc/letsencrypt/live/backup.example.com/fullchain.pem \
       --tls-key /etc/letsencrypt/live/backup.example.com/privkey.pem

Append-Only Mode
----------------

In append-only mode, backups can be created but not deleted. This protects against:

- Accidental deletion
- Ransomware that tries to delete backups
- Unauthorized backup removal

Enable append-only mode:

.. code-block:: bash

   pyrestserver serve --path /srv/restic --append-only

With append-only mode:

- ✅ ``restic backup`` works
- ✅ ``restic snapshots`` works
- ✅ ``restic restore`` works
- ❌ ``restic forget`` fails
- ❌ ``restic prune`` fails

**Note:** Repository administrators can still delete backups by accessing the storage directly.

Upload Verification
-------------------

By default, PyRestServer verifies uploaded data blobs by checking SHA-256 hashes.

Configuration:

.. code-block:: bash

   # Enabled by default
   pyrestserver serve --path /srv/restic

   # Disable (not recommended)
   pyrestserver serve --path /srv/restic --no-verify-upload

When verification is enabled:

- Data uploads are checked against their filename hash
- Corrupted uploads are rejected with HTTP 400
- Failures are logged and counted in metrics

**Performance Impact:** Minimal on modern CPUs. Only disable on very low-power devices.

Prometheus Metrics
------------------

Enable metrics collection:

.. code-block:: bash

   pyrestserver serve --path /srv/restic --prometheus

Access metrics:

.. code-block:: bash

   curl http://localhost:8000/metrics

Disable authentication for metrics endpoint:

.. code-block:: bash

   pyrestserver serve --path /srv/restic \
       --prometheus \
       --prometheus-no-auth

Available metrics:

- ``restic_repo_read_total`` - Repository read operations
- ``restic_repo_write_total`` - Repository write operations
- ``restic_upload_verification_failures_total`` - Failed upload verifications

Logging
-------

Configure logging:

.. code-block:: bash

   # Log to file
   pyrestserver serve --path /srv/restic --log /var/log/pyrestserver.log

   # Log to stdout
   pyrestserver serve --path /srv/restic --log -

   # Enable debug logging
   pyrestserver serve --path /srv/restic --debug

Log format follows the Apache Combined Log Format for HTTP requests.

Example Configuration Files
----------------------------

Production Setup
~~~~~~~~~~~~~~~~

**systemd service file** (``/etc/systemd/system/pyrestserver.service``):

.. code-block:: ini

   [Unit]
   Description=PyRestServer - REST server for restic
   After=network.target

   [Service]
   Type=simple
   User=restic
   Group=restic
   ExecStart=/usr/local/bin/pyrestserver serve \
       --path /srv/restic \
       --htpasswd-file /etc/restic/htpasswd \
       --listen :8000 \
       --tls \
       --tls-cert /etc/letsencrypt/live/backup.example.com/fullchain.pem \
       --tls-key /etc/letsencrypt/live/backup.example.com/privkey.pem \
       --append-only \
       --prometheus \
       --log /var/log/pyrestserver.log
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target

**Backend configuration** (``~/.config/pyrestserver/backends.toml``):

.. code-block:: toml

   [production-local]
   type = "local"
   path = "/srv/restic"

   [production-drime]
   type = "drime"
   api_key = "qO-l2HqnGGNrZM3ga4UI50iwySHFTmVl1pe2NW0oOxKQqBZWUw4"
   workspace_id = 0

   [backup-local]
   type = "local"
   path = "/backup/restic"

Development Setup
~~~~~~~~~~~~~~~~~

For local development:

.. code-block:: bash

   #!/bin/bash
   # dev-server.sh

   export RESTIC_PASSWORD="development"

   pyrestserver serve \
       --path /tmp/restic-dev \
       --no-auth \
       --debug \
       --log -

Next Steps
----------

- Learn about :doc:`backends` for storage options
- Read :doc:`security` for production deployment
- See :doc:`cli` for complete command reference
