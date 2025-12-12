Installation
============

PyRestServer can be installed in several ways depending on your needs.

Basic Installation
------------------

For local filesystem backend only:

.. code-block:: bash

   pip install pyrestserver

This installs the core package with support for local filesystem storage.

With Cloud Storage Support
---------------------------

To use the Drime Cloud backend:

.. code-block:: bash

   pip install pyrestserver[drime]

This includes the ``pydrime`` package for Drime Cloud integration.

Development Installation
-------------------------

For development or to get the latest features:

.. code-block:: bash

   git clone https://github.com/yourusername/pyrestserver.git
   cd pyrestserver
   pip install -e ".[dev,drime]"

This installs the package in editable mode with development dependencies.

Requirements
------------

- Python 3.8 or later
- For Drime backend: ``pydrime`` package
- For authentication: ``passlib`` with ``bcrypt`` support

System Requirements
-------------------

PyRestServer is designed to work on:

- Linux (tested on Ubuntu, Debian, RHEL)
- macOS
- Windows (with some limitations)

For production use, we recommend:

- 2+ CPU cores
- 512MB+ RAM (more for large repositories)
- SSD storage for better performance

Installing restic
-----------------

PyRestServer is a server for restic. You'll need to install restic separately:

**Linux:**

.. code-block:: bash

   # Ubuntu/Debian
   sudo apt-get install restic

   # Or download the latest release
   wget https://github.com/restic/restic/releases/download/v0.18.1/restic_0.18.1_linux_amd64.bz2
   bunzip2 restic_0.18.1_linux_amd64.bz2
   chmod +x restic_0.18.1_linux_amd64
   sudo mv restic_0.18.1_linux_amd64 /usr/local/bin/restic

**macOS:**

.. code-block:: bash

   brew install restic

**Windows:**

Download from the `restic releases page <https://github.com/restic/restic/releases>`_.

Verifying Installation
----------------------

Check that pyrestserver is installed correctly:

.. code-block:: bash

   pyrestserver --version

You should see the version number displayed.

Upgrading
---------

To upgrade to the latest version:

.. code-block:: bash

   pip install --upgrade pyrestserver

To upgrade with Drime support:

.. code-block:: bash

   pip install --upgrade pyrestserver[drime]

Uninstalling
------------

To remove pyrestserver:

.. code-block:: bash

   pip uninstall pyrestserver

This will also remove dependencies if they were installed with pyrestserver and are not used by other packages.
