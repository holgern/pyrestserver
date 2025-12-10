"""Command-line interface for pyrestserver.

This CLI matches the interface of the original rest-server (Go implementation),
providing a familiar experience for users migrating from rest-server.
"""

import logging
import sys
import tempfile
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.logging import RichHandler

from pyrestserver.constants import DEFAULT_PORT

console = Console()


@click.command()
@click.option(
    "--path",
    default=str(Path(tempfile.gettempdir()) / "restic"),
    help="data directory",
)
@click.option("--listen", default=f":{DEFAULT_PORT}", help="listen address")
@click.option("--no-auth", is_flag=True, help="disable .htpasswd authentication")
@click.option(
    "--htpasswd-file",
    default=None,
    help='location of .htpasswd file (default: "<data directory>/.htpasswd")',
)
@click.option("--tls", is_flag=True, help="turn on TLS support")
@click.option("--tls-cert", default=None, help="TLS certificate path")
@click.option("--tls-key", default=None, help="TLS key path")
@click.option("--append-only", is_flag=True, help="enable append only mode")
@click.option(
    "--private-repos", is_flag=True, help="users can only access their private repo"
)
@click.option("--debug", is_flag=True, help="output debug messages")
@click.option(
    "--log",
    default=None,
    help=(
        "write HTTP requests in the combined log format to the specified "
        'filename (use "-" for logging to stdout)'
    ),
)
@click.option("--prometheus", is_flag=True, help="enable Prometheus metrics")
@click.option(
    "--prometheus-no-auth",
    is_flag=True,
    help="disable auth for Prometheus /metrics endpoint",
)
@click.option(
    "--no-verify-upload",
    is_flag=True,
    help=(
        "do not verify the integrity of uploaded data. DO NOT enable "
        "unless the rest-server runs on a very low-power device"
    ),
)
@click.option(
    "--backend",
    type=click.Choice(["local", "drime"]),
    default="local",
    help="storage backend to use (default: local)",
)
@click.option(
    "--workspace-id",
    default=0,
    type=int,
    help="[Drime only] workspace ID to use (0 for personal)",
)
@click.version_option()
def main(
    path: str,
    listen: str,
    no_auth: bool,
    htpasswd_file: Optional[str],
    tls: bool,
    tls_cert: Optional[str],
    tls_key: Optional[str],
    append_only: bool,
    private_repos: bool,
    debug: bool,
    log: Optional[str],
    prometheus: bool,
    prometheus_no_auth: bool,
    no_verify_upload: bool,
    backend: str,
    workspace_id: int,
) -> None:
    """Run a REST server for use with restic."""

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_time=False)],
    )

    logger = logging.getLogger(__name__)

    # Print data directory (matching rest-server behavior)
    console.print(f"Data directory: {path}")

    # Create storage provider based on backend
    if backend == "local":
        from pyrestserver.providers.local import LocalStorageProvider

        provider = LocalStorageProvider(
            base_path=Path(path),
            readonly=append_only,  # append-only = readonly deletes
        )
    elif backend == "drime":
        provider = _create_drime_provider(workspace_id, append_only)
    else:
        console.print(f"[red]Unknown backend: {backend}[/red]")
        sys.exit(1)

    # Setup authentication
    username: Optional[str] = None
    password: Optional[str] = None

    if no_auth:
        console.print("Authentication disabled")
    else:
        # Determine htpasswd file path
        if htpasswd_file is None:
            htpasswd_path = Path(path) / ".htpasswd"
        else:
            htpasswd_path = Path(htpasswd_file)

        # Load authentication from htpasswd file
        username, password = _load_htpasswd(htpasswd_path)

        if username and password:
            console.print("Authentication enabled")
        else:
            console.print(
                "[yellow]Warning: Authentication enabled but no valid "
                ".htpasswd file found[/yellow]"
            )
            console.print("Authentication disabled")
            username, password = None, None

    # Parse listen address
    if listen.startswith(":"):
        host = "0.0.0.0"
        port = int(listen[1:])
    else:
        if ":" in listen:
            host, port_str = listen.rsplit(":", 1)
            port = int(port_str)
        else:
            host = listen
            port = DEFAULT_PORT

    # Setup TLS
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None

    if tls:
        # Determine cert and key paths
        if tls_cert:
            ssl_cert_path = tls_cert
        else:
            ssl_cert_path = str(Path(path) / "public_key")

        if tls_key:
            ssl_key_path = tls_key
        else:
            ssl_key_path = str(Path(path) / "private_key")

        console.print(
            f"TLS enabled, private key {ssl_key_path}, pubkey {ssl_cert_path}"
        )

    # Log append-only mode (matching rest-server behavior)
    if append_only:
        console.print("Append only mode enabled")
    else:
        console.print("Append only mode disabled")

    # Log private repos (matching rest-server behavior)
    if private_repos:
        console.print("Private repositories enabled")
        console.print(
            "[yellow]Warning: Private repositories not yet implemented[/yellow]"
        )
    else:
        console.print("Private repositories disabled")

    # Prometheus metrics
    if prometheus:
        console.print("Prometheus metrics enabled")
        console.print(
            "[yellow]Warning: Prometheus metrics not yet implemented[/yellow]"
        )

    # Log upload verification status (matching rest-server behavior)
    if no_verify_upload:
        console.print(
            "[yellow]Upload verification disabled - DO NOT use in "
            "production unless on low-power device[/yellow]"
        )
    else:
        console.print("Upload verification enabled")

    # Start server
    from pyrestserver.server import run_rest_server

    try:
        run_rest_server(
            provider=provider,
            host=host,
            port=port,
            username=username,
            password=password,
            ssl_cert=ssl_cert_path,
            ssl_key=ssl_key_path,
            no_verify_upload=no_verify_upload,
        )
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.exception("Server error")
        sys.exit(1)


def _create_drime_provider(workspace_id: int, readonly: bool):
    """Create a Drime storage provider.

    Args:
        workspace_id: Workspace ID to use
        readonly: Whether to enable readonly mode

    Returns:
        DrimeStorageProvider instance
    """
    try:
        from pydrime import DrimeClient

        from pyrestserver.providers.drime import DrimeStorageProvider
    except ImportError:
        console.print("[red]Drime backend requires pydrime package.[/red]")
        console.print("Install with: pip install pyrestserver[drime]")
        sys.exit(1)

    # Initialize Drime client
    try:
        client = DrimeClient.from_env()
    except Exception as e:
        console.print(f"[red]Failed to initialize Drime client: {e}[/red]")
        console.print("\nMake sure the following environment variables are set:")
        console.print("  DRIME_EMAIL")
        console.print("  DRIME_PASSWORD")
        sys.exit(1)

    return DrimeStorageProvider(
        client=client, workspace_id=workspace_id, readonly=readonly
    )


def _load_htpasswd(htpasswd_path: Path) -> tuple[Optional[str], Optional[str]]:
    """Load username and password from .htpasswd file.

    This is a simplified implementation that reads the first valid entry.
    For production use, consider using a proper htpasswd library.

    Args:
        htpasswd_path: Path to .htpasswd file

    Returns:
        Tuple of (username, password_hash) or (None, None) if file doesn't exist
    """
    if not htpasswd_path.exists():
        return None, None

    try:
        content = htpasswd_path.read_text()
        lines = content.strip().split("\n")

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if ":" in line:
                username, password_hash = line.split(":", 1)
                # For now, we return the hash as-is
                # TODO: Implement proper bcrypt/SHA password verification
                console.print(
                    "[yellow]Warning: htpasswd authentication not fully "
                    "implemented[/yellow]"
                )
                console.print(
                    "[yellow]Using simple username:password from file[/yellow]"
                )
                return username.strip(), password_hash.strip()

        return None, None
    except Exception as e:
        console.print(f"[yellow]Warning: Error reading .htpasswd file: {e}[/yellow]")
        return None, None


if __name__ == "__main__":
    main()
