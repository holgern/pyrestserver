PyRestServer Documentation
==========================

**PyRestServer** is a REST API server for `restic <https://restic.net/>`_ backup software with pluggable storage backends.

This package provides a Python implementation of the restic REST API with support for multiple storage backends, including local filesystem and Drime Cloud storage.

.. image:: https://img.shields.io/pypi/v/pyrestserver.svg
   :target: https://pypi.org/project/pyrestserver/
   :alt: PyPI version

.. image:: https://img.shields.io/pypi/pyversions/pyrestserver.svg
   :target: https://pypi.org/project/pyrestserver/
   :alt: Python versions

Features
--------

- **REST API compatible with restic** - Drop-in replacement for rest-server
- **Upload verification** - SHA-256 hash verification for data integrity
- **Pluggable storage backends** - Local filesystem and cloud storage (Drime)
- **Authentication** - htpasswd-based authentication support
- **Append-only mode** - Prevent deletion of existing backups
- **TLS support** - Secure communication with TLS/SSL
- **Prometheus metrics** - Built-in metrics endpoint
- **Secure configuration** - Custom cipher keys for password obscuring

Quick Start
-----------

Install pyrestserver:

.. code-block:: bash

   pip install pyrestserver

Start a server with local storage:

.. code-block:: bash

   pyrestserver serve --path /tmp/restic --no-auth

Use with restic:

.. code-block:: bash

   restic -r rest:http://localhost:8000/myrepo init
   restic -r rest:http://localhost:8000/myrepo backup /path/to/data

Contents
--------

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   installation
   quickstart
   configuration
   backends
   security
   cli

.. toctree::
   :maxdepth: 2
   :caption: Developer Guide

   api
   architecture
   custom_backends
   benchmarks

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   api/modules
   api/server
   api/providers
   api/config

.. toctree::
   :maxdepth: 1
   :caption: Additional Information

   changelog
   contributing
   license

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
