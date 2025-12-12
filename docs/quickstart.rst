Quick Start Guide
=================

This guide will help you get started with PyRestServer in just a few minutes.

Starting the Server
-------------------

Local Filesystem Backend
~~~~~~~~~~~~~~~~~~~~~~~~~

The simplest way to start PyRestServer is with a local filesystem backend:

.. code-block:: bash

   pyrestserver serve --path /tmp/restic --no-auth

This starts a server on ``http://localhost:8000`` with:

- No authentication
- Data stored in ``/tmp/restic``
- Upload verification enabled

With Authentication
~~~~~~~~~~~~~~~~~~~

For production use, enable authentication:

.. code-block:: bash

   # Create htpasswd file first
   htpasswd -c /etc/restic/htpasswd myuser

   # Start server with authentication
   pyrestserver serve --path /srv/restic --htpasswd-file /etc/restic/htpasswd

Custom Port and Address
~~~~~~~~~~~~~~~~~~~~~~~

To use a different port or bind address:

.. code-block:: bash

   pyrestserver serve --path /srv/restic --listen 192.168.1.100:8080

Using with restic
-----------------

Initialize a Repository
~~~~~~~~~~~~~~~~~~~~~~~

Once the server is running, initialize a restic repository:

.. code-block:: bash

   # Set repository password
   export RESTIC_PASSWORD="your-secure-password"

   # Initialize repository
   restic -r rest:http://localhost:8000/myrepo init

This creates a new repository called ``myrepo`` on the server.

Create a Backup
~~~~~~~~~~~~~~~

Backup your data:

.. code-block:: bash

   restic -r rest:http://localhost:8000/myrepo backup /home/user/documents

You can backup multiple paths:

.. code-block:: bash

   restic -r rest:http://localhost:8000/myrepo backup \
       /home/user/documents \
       /home/user/photos \
       /home/user/config

List Snapshots
~~~~~~~~~~~~~~

View your backups:

.. code-block:: bash

   restic -r rest:http://localhost:8000/myrepo snapshots

Restore Data
~~~~~~~~~~~~

Restore from a backup:

.. code-block:: bash

   # Restore latest snapshot
   restic -r rest:http://localhost:8000/myrepo restore latest --target /restore/path

   # Restore specific snapshot
   restic -r rest:http://localhost:8000/myrepo restore abc123de --target /restore/path

   # Restore specific files
   restic -r rest:http://localhost:8000/myrepo restore latest \
       --target /restore/path \
       --include /home/user/documents/important.pdf

With Authentication
~~~~~~~~~~~~~~~~~~~

If the server requires authentication:

.. code-block:: bash

   # Set credentials
   export RESTIC_PASSWORD="your-secure-password"
   export RESTIC_REST_USERNAME="myuser"
   export RESTIC_REST_PASSWORD="mypassword"

   # Now use restic normally
   restic -r rest:http://localhost:8000/myrepo snapshots

Or use the URL format:

.. code-block:: bash

   restic -r rest:http://myuser:mypassword@localhost:8000/myrepo snapshots

Configuration Management
------------------------

PyRestServer includes a configuration manager for backend settings.

Interactive Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~

Launch the interactive configuration wizard:

.. code-block:: bash

   pyrestserver config

This guides you through setting up backends with password obscuring.

Adding a Backend
~~~~~~~~~~~~~~~~

From the command line:

.. code-block:: bash

   # Add a local backend
   pyrestserver config add local-backup \
       --type local \
       --path /srv/restic

   # Add a Drime backend
   pyrestserver config add drime-backup \
       --type drime \
       --api-key "your-api-key" \
       --workspace-id 0

Listing Backends
~~~~~~~~~~~~~~~~

View configured backends:

.. code-block:: bash

   pyrestserver config list

Using a Configured Backend
~~~~~~~~~~~~~~~~~~~~~~~~~~

Start the server with a configured backend:

.. code-block:: bash

   pyrestserver serve --backend-config local-backup

Drime Cloud Backend
-------------------

PyRestServer supports Drime Cloud as a backend storage provider.

Prerequisites
~~~~~~~~~~~~~

Install with Drime support:

.. code-block:: bash

   pip install pyrestserver[drime]

Starting with Drime
~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Configure backend
   pyrestserver config add drime-main \
       --type drime \
       --api-key "your-api-key" \
       --workspace-id 0

   # Start server
   pyrestserver serve --backend-config drime-main --no-auth

Or directly with environment variables:

.. code-block:: bash

   export DRIME_API_KEY="your-api-key"

   pyrestserver serve --backend drime \
       --workspace-id 0 \
       --no-auth

Common Tasks
------------

Enabling TLS
~~~~~~~~~~~~

For secure communication:

.. code-block:: bash

   pyrestserver serve --path /srv/restic \
       --tls \
       --tls-cert /etc/restic/cert.pem \
       --tls-key /etc/restic/key.pem

Then use HTTPS with restic:

.. code-block:: bash

   restic -r rest:https://localhost:8000/myrepo snapshots

Append-Only Mode
~~~~~~~~~~~~~~~~

Prevent deletion of backups:

.. code-block:: bash

   pyrestserver serve --path /srv/restic --append-only

In this mode, restic can create new backups but cannot delete old ones.

Enable Metrics
~~~~~~~~~~~~~~

For monitoring with Prometheus:

.. code-block:: bash

   pyrestserver serve --path /srv/restic --prometheus

Metrics are available at ``http://localhost:8000/metrics``

Debug Mode
~~~~~~~~~~

Enable detailed logging for troubleshooting:

.. code-block:: bash

   pyrestserver serve --path /srv/restic --debug

Next Steps
----------

- Read the :doc:`configuration` guide for detailed configuration options
- Learn about :doc:`backends` for different storage options
- Check :doc:`security` for production deployment best practices
- See :doc:`cli` for complete command reference
