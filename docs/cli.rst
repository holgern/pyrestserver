Command Line Interface
======================

PyRestServer provides a command-line interface for managing the REST server and backend configurations.

Main Commands
-------------

pyrestserver
~~~~~~~~~~~~

The main entry point provides access to subcommands:

.. code-block:: bash

   pyrestserver [OPTIONS] COMMAND [ARGS]...

**Options:**

- ``--version`` - Show version and exit
- ``--help`` - Show help message

**Commands:**

- ``serve`` - Start the REST server
- ``config`` - Manage backend configurations
- ``obscure`` - Obscure passwords

serve Command
-------------

Start the REST server for restic.

Synopsis
~~~~~~~~

.. code-block:: bash

   pyrestserver serve [OPTIONS]

Options
~~~~~~~

**Storage Options:**

``--path TEXT``
  Data directory for local filesystem backend.

  Default: ``/tmp/restic``

``--backend {local,drime}``
  Storage backend type.

  Default: ``local``

``--backend-config TEXT``
  Use a named backend from configuration file.

  Example: ``--backend-config production-local``

**Network Options:**

``--listen TEXT``
  Listen address in format ``HOST:PORT`` or ``:PORT``.

  Default: ``localhost:8000``

  Examples:

  - ``:8000`` - All interfaces, port 8000
  - ``192.168.1.100:8000`` - Specific IP
  - ``localhost:8000`` - Localhost only

``--tls``
  Enable TLS/SSL encryption.

``--tls-cert TEXT``
  Path to TLS certificate file (PEM format).

  Required when ``--tls`` is enabled.

``--tls-key TEXT``
  Path to TLS private key file (PEM format).

  Required when ``--tls`` is enabled.

**Authentication Options:**

``--no-auth``
  Disable authentication. **Use only for development/testing.**

``--htpasswd-file TEXT``
  Path to htpasswd file for authentication.

  Default: ``<data_directory>/.htpasswd``

**Repository Options:**

``--append-only``
  Enable append-only mode (prevents deletion of backups).

``--private-repos``
  Enable private repositories per user.

  Each user can only access repositories in their own subdirectory.

**Upload Verification:**

``--no-verify-upload``
  Disable upload integrity verification.

  **Warning:** Only use on very low-power devices.

**Monitoring Options:**

``--prometheus``
  Enable Prometheus metrics endpoint at ``/metrics``.

``--prometheus-no-auth``
  Disable authentication for the ``/metrics`` endpoint.

``--log TEXT``
  Write HTTP requests to log file in Combined Log Format.

  Use ``-`` for stdout.

``--debug``
  Enable debug logging for troubleshooting.

Examples
~~~~~~~~

**Basic local server:**

.. code-block:: bash

   pyrestserver serve --path /srv/restic --no-auth

**Production server with authentication:**

.. code-block:: bash

   pyrestserver serve \
       --path /srv/restic \
       --htpasswd-file /etc/restic/htpasswd \
       --listen :8000

**Server with TLS:**

.. code-block:: bash

   pyrestserver serve \
       --path /srv/restic \
       --listen :443 \
       --tls \
       --tls-cert /etc/letsencrypt/live/backup.example.com/fullchain.pem \
       --tls-key /etc/letsencrypt/live/backup.example.com/privkey.pem

**Append-only server:**

.. code-block:: bash

   pyrestserver serve \
       --path /srv/restic \
       --append-only \
       --prometheus

**Drime cloud backend:**

.. code-block:: bash

   pyrestserver serve \
       --backend-config drime-production \
       --no-auth

config Command
--------------

Manage backend configurations interactively or via subcommands.

Synopsis
~~~~~~~~

.. code-block:: bash

   pyrestserver config [SUBCOMMAND] [OPTIONS]

Interactive Mode
~~~~~~~~~~~~~~~~

Run without subcommands for interactive configuration:

.. code-block:: bash

   pyrestserver config

This launches an interactive wizard for managing backends.

Subcommands
~~~~~~~~~~~

add
^^^

Add a new backend configuration:

.. code-block:: bash

   pyrestserver config add NAME --type TYPE [OPTIONS]

**Arguments:**

- ``NAME`` - Backend name (identifier)

**Options:**

- ``--type {local,drime}`` - Backend type (required)

**Local backend options:**

- ``--path TEXT`` - Data directory path

**Drime backend options:**

- ``--api-key TEXT`` - Drime API key
- ``--workspace-id INT`` - Workspace ID (default: 0)

**Examples:**

.. code-block:: bash

   # Add local backend
   pyrestserver config add mylocal \
       --type local \
       --path /srv/restic

   # Add Drime backend
   pyrestserver config add mydrime \
       --type drime \
       --api-key "your-key" \
       --workspace-id 0

list
^^^^

List all configured backends:

.. code-block:: bash

   pyrestserver config list

Output shows backend names and types.

show
^^^^

Show details of a specific backend:

.. code-block:: bash

   pyrestserver config show NAME

**Example:**

.. code-block:: bash

   pyrestserver config show mylocal

remove
^^^^^^

Remove a backend configuration:

.. code-block:: bash

   pyrestserver config remove NAME

**Example:**

.. code-block:: bash

   pyrestserver config remove mylocal

obscure Command
---------------

Obscure a password for use in configuration files.

Synopsis
~~~~~~~~

.. code-block:: bash

   pyrestserver obscure [PASSWORD]

Description
~~~~~~~~~~~

Obscures a password using PyRestServer's custom cipher key. The obscured password can be used in configuration files.

**Note:** This is obfuscation, not encryption. It prevents casual viewing but is not cryptographically secure.

Interactive Mode
~~~~~~~~~~~~~~~~

Without arguments, prompts for password:

.. code-block:: bash

   pyrestserver obscure
   Enter password: ********
   Obscured: qO-l2HqnGGNrZM3ga4UI50iwySHFTmVl1pe2NW0oOxKQqBZWUw4

With Argument
~~~~~~~~~~~~~

Pass password as argument (less secure - visible in shell history):

.. code-block:: bash

   pyrestserver obscure "my-password"
   Obscured: qO-l2HqnGGNrZM3ga4UI50iwySHFTmVl1pe2NW0oOxKQqBZWUw4

From stdin
~~~~~~~~~~

Pipe password via stdin:

.. code-block:: bash

   echo "my-password" | pyrestserver obscure
   Obscured: qO-l2HqnGGNrZM3ga4UI50iwySHFTmVl1pe2NW0oOxKQqBZWUw4

Environment Variables
---------------------

PyRestServer respects the following environment variables:

Authentication
~~~~~~~~~~~~~~

``RESTIC_REST_USERNAME``
  HTTP Basic auth username for client requests.

``RESTIC_REST_PASSWORD``
  HTTP Basic auth password for client requests.

Drime Backend
~~~~~~~~~~~~~

``DRIME_API_KEY``
  Drime API authentication key.

``DRIME_USERNAME``
  Drime username (if using username/password auth).

``DRIME_PASSWORD``
  Drime password (if using username/password auth).

Repository
~~~~~~~~~~

``RESTIC_PASSWORD``
  Repository encryption password (used by restic client).

``RESTIC_PASSWORD_FILE``
  Path to file containing repository password.

Configuration
~~~~~~~~~~~~~

``PYRESTSERVER_CONFIG_DIR``
  Override default configuration directory.

  Default: ``~/.config/pyrestserver``

Exit Codes
----------

PyRestServer uses standard exit codes:

- ``0`` - Success
- ``1`` - General error
- ``2`` - Command-line usage error
- ``130`` - Interrupted by Ctrl+C

Logging Output
--------------

HTTP Access Logs
~~~~~~~~~~~~~~~~

When ``--log`` is specified, HTTP requests are logged in Apache Combined Log Format:

.. code-block:: text

   127.0.0.1 - user [10/Jan/2025:12:34:56 +0000] "GET /myrepo/config HTTP/1.1" 200 512 "-" "restic/0.18.1"

Format:

- Remote IP
- Identity (always ``-``)
- Username (or ``-`` if no auth)
- Timestamp
- Request line
- Status code
- Response size
- Referer (usually ``-``)
- User agent

Debug Output
~~~~~~~~~~~~

With ``--debug``, additional information is logged:

.. code-block:: text

   DEBUG: Checking repository: myrepo
   DEBUG: Config exists: True, size: 512
   INFO: GET /myrepo/config - 200

Integration Examples
--------------------

systemd Service
~~~~~~~~~~~~~~~

Create a systemd service file (``/etc/systemd/system/pyrestserver.service``):

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
       --prometheus \
       --log /var/log/pyrestserver.log
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target

Enable and start:

.. code-block:: bash

   sudo systemctl enable pyrestserver
   sudo systemctl start pyrestserver
   sudo systemctl status pyrestserver

Docker
~~~~~~

Example Dockerfile:

.. code-block:: dockerfile

   FROM python:3.11-slim

   RUN pip install pyrestserver

   RUN useradd -r -s /bin/false restic
   USER restic

   EXPOSE 8000

   ENTRYPOINT ["pyrestserver", "serve"]
   CMD ["--path", "/data", "--listen", ":8000"]

Run container:

.. code-block:: bash

   docker build -t pyrestserver .

   docker run -d \
       -p 8000:8000 \
       -v /srv/restic:/data \
       --name pyrestserver \
       pyrestserver

Docker Compose
~~~~~~~~~~~~~~

Example ``docker-compose.yml``:

.. code-block:: yaml

   version: '3.8'

   services:
     pyrestserver:
       image: pyrestserver:latest
       ports:
         - "8000:8000"
       volumes:
         - ./data:/data
         - ./htpasswd:/etc/restic/htpasswd:ro
       command:
         - --path
         - /data
         - --htpasswd-file
         - /etc/restic/htpasswd
         - --prometheus
       restart: unless-stopped

Cron Jobs
~~~~~~~~~

Automated backup script:

.. code-block:: bash

   #!/bin/bash
   # /etc/cron.daily/restic-backup

   export RESTIC_PASSWORD_FILE=/etc/restic/repo_password
   export RESTIC_REST_USERNAME=backup
   export RESTIC_REST_PASSWORD_FILE=/etc/restic/rest_password

   # Backup
   restic -r rest:http://localhost:8000/myrepo backup \
       /home \
       /etc \
       --exclude /home/*/.cache

   # Forget old backups
   restic -r rest:http://localhost:8000/myrepo forget \
       --keep-daily 7 \
       --keep-weekly 4 \
       --keep-monthly 12 \
       --prune

Make executable:

.. code-block:: bash

   sudo chmod +x /etc/cron.daily/restic-backup

Troubleshooting
---------------

Common Issues
~~~~~~~~~~~~~

**Server won't start:**

.. code-block:: bash

   # Check if port is in use
   sudo netstat -tulpn | grep 8000

   # Try a different port
   pyrestserver serve --listen :8001

**Authentication fails:**

.. code-block:: bash

   # Verify htpasswd file
   cat /etc/restic/htpasswd

   # Check file permissions
   ls -l /etc/restic/htpasswd

   # Test with no auth
   pyrestserver serve --no-auth

**TLS certificate errors:**

.. code-block:: bash

   # Verify certificate files exist
   ls -l /etc/restic/cert.pem /etc/restic/key.pem

   # Check certificate validity
   openssl x509 -in /etc/restic/cert.pem -text -noout

**Permission denied:**

.. code-block:: bash

   # Check data directory permissions
   ls -ld /srv/restic

   # Fix ownership
   sudo chown -R restic:restic /srv/restic

Enable Debug Mode
~~~~~~~~~~~~~~~~~

For detailed troubleshooting:

.. code-block:: bash

   pyrestserver serve --path /srv/restic --debug --log -

This outputs all debug information to stdout.

Next Steps
----------

- Review :doc:`configuration` for detailed setup
- Check :doc:`security` for production best practices
- See :doc:`backends` for storage options
