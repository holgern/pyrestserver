Security Best Practices
=======================

This guide covers security best practices for deploying PyRestServer in production.

Authentication
--------------

Never run without authentication in production.

htpasswd Configuration
~~~~~~~~~~~~~~~~~~~~~~

Use strong passwords with bcrypt hashing:

.. code-block:: bash

   # Create htpasswd file with bcrypt (-B flag)
   htpasswd -B -c /etc/restic/htpasswd backup_user

   # Use a strong password generator
   openssl rand -base64 32

File permissions:

.. code-block:: bash

   chmod 600 /etc/restic/htpasswd
   chown restic:restic /etc/restic/htpasswd

Password Guidelines
~~~~~~~~~~~~~~~~~~~

For both restic repository passwords and server authentication:

- Minimum 16 characters
- Mix of uppercase, lowercase, numbers, symbols
- Use a password manager
- Unique per repository/server
- Rotate periodically

TLS/SSL Encryption
------------------

Always use TLS for production deployments.

Let's Encrypt
~~~~~~~~~~~~~

Recommended for public servers:

.. code-block:: bash

   # Get certificate
   sudo certbot certonly --standalone -d backup.example.com

   # Start server with TLS
   pyrestserver serve --path /srv/restic \
       --listen :443 \
       --tls \
       --tls-cert /etc/letsencrypt/live/backup.example.com/fullchain.pem \
       --tls-key /etc/letsencrypt/live/backup.example.com/privkey.pem

Self-Signed Certificates
~~~~~~~~~~~~~~~~~~~~~~~~~

For internal/testing use:

.. code-block:: bash

   # Generate certificate
   openssl req -x509 -newkey rsa:4096 \
       -keyout /etc/restic/key.pem \
       -out /etc/restic/cert.pem \
       -days 365 -nodes \
       -subj "/CN=backup.internal.example.com"

   # Secure permissions
   chmod 600 /etc/restic/key.pem
   chmod 644 /etc/restic/cert.pem

File System Security
--------------------

Directory Permissions
~~~~~~~~~~~~~~~~~~~~~

Secure the data directory:

.. code-block:: bash

   # Create dedicated user
   sudo useradd -r -s /bin/false restic

   # Set ownership and permissions
   sudo chown -R restic:restic /srv/restic
   sudo chmod 700 /srv/restic

The application creates files with:

- Directories: ``0700`` (owner only)
- Files: ``0600`` (owner only)

Mount Options
~~~~~~~~~~~~~

For extra security, mount backup storage with ``noexec`` and ``nosuid``:

.. code-block:: bash

   # /etc/fstab
   /dev/sdb1  /srv/restic  ext4  defaults,noexec,nosuid  0  2

Configuration Security
----------------------

Password Obscuring
~~~~~~~~~~~~~~~~~~

PyRestServer uses custom cipher keys for password obscuring:

.. code-block:: python

   # Automatically applied to:
   # - api_key
   # - password
   # - drime_password

**Important:** This is obfuscation, not encryption. Protect config files:

.. code-block:: bash

   chmod 600 ~/.config/pyrestserver/backends.toml

Environment Variables
~~~~~~~~~~~~~~~~~~~~~

Avoid putting secrets in command-line arguments (visible in process list):

.. code-block:: bash

   # Bad - visible in ps
   pyrestserver serve --api-key "secret123"

   # Good - use environment variables
   export DRIME_API_KEY="secret123"
   pyrestserver serve --backend drime

Or use configuration files:

.. code-block:: bash

   # Best - use config file
   pyrestserver serve --backend-config mydrime

Network Security
----------------

Firewall Configuration
~~~~~~~~~~~~~~~~~~~~~~

Limit access to PyRestServer:

.. code-block:: bash

   # UFW (Ubuntu/Debian)
   sudo ufw allow from 192.168.1.0/24 to any port 8000

   # iptables
   sudo iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 8000 -j ACCEPT
   sudo iptables -A INPUT -p tcp --dport 8000 -j DROP

Bind to Specific Interface
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Don't expose to the internet unless necessary:

.. code-block:: bash

   # Listen only on internal network
   pyrestserver serve --listen 192.168.1.100:8000

   # Listen only on localhost (for SSH tunneling)
   pyrestserver serve --listen 127.0.0.1:8000

SSH Tunneling
~~~~~~~~~~~~~

For remote access without exposing the server:

.. code-block:: bash

   # On client machine, create tunnel
   ssh -L 8000:localhost:8000 user@backup-server.example.com

   # Then use restic with localhost
   restic -r rest:http://localhost:8000/myrepo snapshots

Append-Only Mode
----------------

Protect against ransomware and accidental deletion:

.. code-block:: bash

   pyrestserver serve --path /srv/restic --append-only

In append-only mode:

- Backups can be created
- Old backups cannot be deleted
- Repository cannot be modified

**Note:** Admins can still delete via filesystem access. For true immutability, use:

- Separate append-only account
- Immutable filesystem flags (``chattr +i``)
- Write-once storage (WORM drives)

Repository Security
-------------------

Repository Encryption
~~~~~~~~~~~~~~~~~~~~~

Restic encrypts all data by default. Protect your repository password:

.. code-block:: bash

   # Generate strong password
   RESTIC_PASSWORD=$(openssl rand -base64 32)
   echo "$RESTIC_PASSWORD" | sudo tee /etc/restic/repo_password
   sudo chmod 600 /etc/restic/repo_password

   # Use with restic
   export RESTIC_PASSWORD_FILE=/etc/restic/repo_password
   restic -r rest:http://localhost:8000/myrepo backup /data

Key Management
~~~~~~~~~~~~~~

- Store repository keys separately from data
- Use hardware security modules (HSM) for enterprise
- Maintain secure key backups
- Document key recovery procedures

Access Control
~~~~~~~~~~~~~~

Limit who can access repositories:

.. code-block:: bash

   # Create separate users for different repos
   htpasswd -B /etc/restic/htpasswd user1
   htpasswd -B /etc/restic/htpasswd user2

   # Use --private-repos to isolate users (when implemented)
   pyrestserver serve --private-repos

Monitoring and Auditing
------------------------

Enable Logging
~~~~~~~~~~~~~~

Log all access for security auditing:

.. code-block:: bash

   pyrestserver serve --path /srv/restic \
       --log /var/log/pyrestserver.log

Log file permissions:

.. code-block:: bash

   touch /var/log/pyrestserver.log
   chmod 640 /var/log/pyrestserver.log
   chown restic:adm /var/log/pyrestserver.log

Prometheus Metrics
~~~~~~~~~~~~~~~~~~

Monitor for unusual activity:

.. code-block:: bash

   pyrestserver serve --path /srv/restic --prometheus

Watch for:

- Unusual number of writes
- Failed authentication attempts
- Upload verification failures
- Unexpected deletions (if not append-only)

Log Rotation
~~~~~~~~~~~~

Configure logrotate:

.. code-block:: bash

   # /etc/logrotate.d/pyrestserver
   /var/log/pyrestserver.log {
       daily
       rotate 30
       compress
       delaycompress
       notifempty
       create 640 restic adm
       sharedscripts
       postrotate
           systemctl reload pyrestserver
       endscript
   }

Backup Security
---------------

3-2-1 Backup Rule
~~~~~~~~~~~~~~~~~

- **3** copies of data
- **2** different storage types
- **1** off-site copy

Implementation:

.. code-block:: bash

   # Primary backup to local
   restic -r rest:http://local:8000/main backup /data

   # Secondary to cloud
   restic -r rest:https://cloud:8000/backup backup /data

   # Archive to external drive
   restic -r /mnt/external/restic backup /data

Test Restores
~~~~~~~~~~~~~

Regularly verify backups can be restored:

.. code-block:: bash

   # Monthly restore test
   #!/bin/bash
   RESTORE_DIR="/tmp/restore-test-$(date +%Y%m%d)"
   restic -r rest:http://localhost:8000/myrepo restore latest --target "$RESTORE_DIR"

   # Verify critical files
   test -f "$RESTORE_DIR/etc/passwd"
   test -f "$RESTORE_DIR/home/user/important.doc"

   # Cleanup
   rm -rf "$RESTORE_DIR"

Disaster Recovery
~~~~~~~~~~~~~~~~~

Document recovery procedures:

1. Repository password location
2. Server configuration backup
3. Backend configuration backup
4. Contact information
5. Step-by-step restore process

Compliance
----------

Data Residency
~~~~~~~~~~~~~~

Know where your data is stored:

- **Local backend:** Check filesystem mount point
- **Drime backend:** Check workspace location/region
- Document for compliance (GDPR, HIPAA, etc.)

Data Retention
~~~~~~~~~~~~~~

Implement retention policies:

.. code-block:: bash

   # Automated retention policy
   #!/bin/bash
   restic -r rest:http://localhost:8000/myrepo forget \
       --keep-daily 7 \
       --keep-weekly 4 \
       --keep-monthly 12 \
       --keep-yearly 3 \
       --prune

Access Logs
~~~~~~~~~~~

Maintain logs for compliance audits:

- All access attempts
- Configuration changes
- Backup/restore operations
- Authentication failures

Security Checklist
------------------

Deployment Checklist
~~~~~~~~~~~~~~~~~~~~

Before going to production:

☐ Authentication enabled (htpasswd)
☐ TLS/SSL configured
☐ Firewall rules configured
☐ File permissions secured (0600/0700)
☐ Dedicated service user created
☐ Logging enabled
☐ Log rotation configured
☐ Monitoring/metrics enabled
☐ Strong passwords used
☐ Repository keys backed up
☐ Disaster recovery documented
☐ Restore procedure tested
☐ Append-only mode considered
☐ Network access restricted
☐ Config files protected (0600)

Regular Maintenance
~~~~~~~~~~~~~~~~~~~

Monthly tasks:

☐ Review access logs
☐ Test restores
☐ Rotate passwords (quarterly)
☐ Update certificates
☐ Check disk space
☐ Review firewall rules
☐ Update software
☐ Verify backups

Common Vulnerabilities
----------------------

Avoid These Mistakes
~~~~~~~~~~~~~~~~~~~~

**❌ Running without authentication:**

.. code-block:: bash

   # Never in production!
   pyrestserver serve --no-auth

**❌ Weak passwords:**

.. code-block:: bash

   # Too short, easily guessed
   password="backup123"

**❌ World-readable config:**

.. code-block:: bash

   # Exposes secrets
   chmod 644 ~/.config/pyrestserver/backends.toml

**❌ Unencrypted network traffic:**

.. code-block:: bash

   # Passwords sent in clear
   restic -r rest:http://public.example.com/repo backup /data

**✅ Correct approach:**

.. code-block:: bash

   # Strong authentication
   htpasswd -B /etc/restic/htpasswd user

   # TLS encryption
   pyrestserver serve --tls --tls-cert cert.pem --tls-key key.pem

   # Secure permissions
   chmod 600 /etc/restic/htpasswd

   # Strong repository password
   export RESTIC_PASSWORD=$(openssl rand -base64 32)

Incident Response
-----------------

If You Suspect a Breach
~~~~~~~~~~~~~~~~~~~~~~~

1. **Immediate actions:**
   - Stop the server
   - Preserve logs
   - Document the incident

2. **Investigation:**
   - Review access logs
   - Check for unauthorized access
   - Verify data integrity
   - Check for modified configs

3. **Remediation:**
   - Change all passwords
   - Rotate keys
   - Update access controls
   - Patch vulnerabilities

4. **Recovery:**
   - Restore from clean backup
   - Verify restoration
   - Resume operations
   - Update procedures

Next Steps
----------

- Review :doc:`configuration` for secure setup options
- Check :doc:`backends` for storage security
- See :doc:`cli` for all security-related options
