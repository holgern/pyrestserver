"""Command-line interface for pyrestserver.

This CLI matches the interface of the original rest-server (Go implementation),
providing a familiar experience for users migrating from rest-server.
"""

import logging
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

import click
from rich.console import Console
from rich.logging import RichHandler

from pyrestserver.constants import DEFAULT_PORT

console = Console()


@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option()
def cli(ctx: click.Context) -> None:
    """PyRestServer - REST server for restic backups.

    Run 'pyrestserver serve' to start the server.
    Run 'pyrestserver config' for configuration management.
    """
    # If no subcommand, show help
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
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
    "--backend-config",
    default=None,
    help="backend configuration name (from ~/.config/pyrestserver/backends.toml)",
)
def serve(
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
    backend_config: Optional[str],
) -> None:
    """Start the REST server for restic."""

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_time=False)],
    )

    logger = logging.getLogger(__name__)

    # Create storage provider based on backend
    if backend == "local":
        from pyrestserver.providers.local import LocalStorageProvider

        # Print data directory (matching rest-server behavior)
        console.print(f"Data directory: {path}")

        provider = LocalStorageProvider(
            base_path=Path(path),
            readonly=append_only,  # append-only = readonly deletes
        )
    elif backend == "drime":
        provider, config_info = _create_drime_provider(backend_config, append_only)
        # Print backend info
        console.print("Storage backend: Drime Cloud")
        console.print(f"Workspace ID: {config_info.get('workspace_id', 0)}")
        if backend_config:
            console.print(f"Configuration: {backend_config}")
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


def _create_drime_provider(
    backend_config_name: Optional[str], readonly: bool
) -> tuple[Any, dict[str, Any]]:
    """Create a Drime storage provider.

    Args:
        backend_config_name: Name of backend config to use (or None to use env vars)
        readonly: Whether to enable readonly mode

    Returns:
        Tuple of (DrimeStorageProvider instance, config dict)
    """
    try:
        from pydrime import DrimeClient  # type: ignore[import-untyped]

        from pyrestserver.providers.drime import DrimeStorageProvider
    except ImportError:
        console.print("[red]Drime backend requires pydrime package.[/red]")
        console.print("Install with: pip install pyrestserver[drime]")
        sys.exit(1)

    config: dict[str, Any] = {}

    # Load config from backend config if provided
    if backend_config_name:
        from pyrestserver.config import get_config_manager

        config_manager = get_config_manager()
        backend_cfg = config_manager.get_backend(backend_config_name)

        if not backend_cfg:
            console.print(
                f"[red]Backend config '{backend_config_name}' not found.[/red]"
            )
            console.print("Available backends:")
            for name in config_manager.list_backends():
                console.print(f"  - {name}")
            sys.exit(1)

        if backend_cfg.backend_type != "drime":
            console.print(
                f"[red]Backend '{backend_config_name}' is not a drime backend.[/red]"
            )
            sys.exit(1)

        config = backend_cfg.get_all()

        # Initialize Drime client with API key from config
        try:
            api_key = config.get("api_key")

            if not api_key:
                console.print("[red]Drime backend config must include 'api_key'.[/red]")
                sys.exit(1)

            client = DrimeClient(api_key=api_key)
        except Exception as e:
            console.print(f"[red]Failed to initialize Drime client: {e}[/red]")
            sys.exit(1)
    else:
        # Initialize Drime client from environment (uses DRIME_API_KEY)
        try:
            client = DrimeClient()
            # Get workspace_id from environment if available
            import os

            workspace_id = os.environ.get("DRIME_WORKSPACE_ID", "0")
            config["workspace_id"] = int(workspace_id)
        except Exception as e:
            console.print(f"[red]Failed to initialize Drime client: {e}[/red]")
            console.print("\nMake sure DRIME_API_KEY environment variable is set.")
            console.print("Or use --backend-config to specify a backend config.")
            sys.exit(1)

    provider = DrimeStorageProvider(client=client, config=config, readonly=readonly)
    return provider, config


@cli.command()
@click.argument("password", required=False)
def obscure(password: Optional[str]) -> None:
    """Obscure a password for use in the pyrestserver config file.

    If PASSWORD is not provided, will prompt for it interactively.
    """
    from vaultconfig import obscure as obscure_module  # type: ignore[import-untyped]

    if password is None:
        password = click.prompt("Enter password to obscure", hide_input=True)

    if not password:
        console.print("[red]Error: Password cannot be empty[/red]")
        sys.exit(1)

    obscured = obscure_module.obscure(password)
    console.print(f"\n[green]Obscured password:[/green] {obscured}")
    console.print("\n[yellow]Note:[/yellow] This can be used in the config file.")
    console.print(
        "The password will be automatically revealed when the config is loaded."
    )


@cli.command()
def config() -> None:
    """Enter an interactive configuration session.

    Allows you to manage backend configurations interactively.
    """
    from pyrestserver.config import get_config_manager

    config_manager = get_config_manager()

    console.print("\n[bold cyan]PyRestServer Configuration Manager[/bold cyan]\n")

    while True:
        console.print("[bold]Available commands:[/bold]")
        console.print("  1. List backends")
        console.print("  2. Add backend")
        console.print("  3. Show backend")
        console.print("  4. Remove backend")
        console.print("  5. Exit")

        choice = click.prompt("\nEnter choice", type=int, default=5)

        if choice == 1:
            # List backends
            backends = config_manager.list_backends()
            if not backends:
                console.print("\n[yellow]No backends configured[/yellow]\n")
            else:
                console.print("\n[bold]Configured backends:[/bold]")
                for name in backends:
                    backend = config_manager.get_backend(name)
                    if backend:
                        console.print(f"  • {name} ({backend.backend_type})")
                console.print()

        elif choice == 2:
            # Add backend
            console.print("\n[bold]Add new backend[/bold]")
            name = click.prompt("Backend name")
            backend_type = click.prompt(
                "Backend type", type=click.Choice(["local", "drime"])
            )

            config_data: dict[str, Any] = {}

            if backend_type == "local":
                path = click.prompt("Base path")
                config_data["path"] = path

            elif backend_type == "drime":
                api_key = click.prompt("Drime API key", hide_input=True)
                workspace_id = click.prompt(
                    "Workspace ID (0 for personal)", type=int, default=0
                )
                config_data["api_key"] = api_key
                config_data["workspace_id"] = workspace_id

            config_manager.add_backend(name, backend_type, config_data)
            console.print(f"\n[green]✓[/green] Backend '{name}' added successfully\n")

        elif choice == 3:
            # Show backend
            name = click.prompt("\nBackend name")
            backend = config_manager.get_backend(name)

            if not backend:
                console.print(f"\n[red]Error:[/red] Backend '{name}' not found\n")
            else:
                console.print(f"\n[bold]Backend: {name}[/bold]")
                console.print(f"Type: {backend.backend_type}")
                console.print("\nConfiguration:")
                config_data = backend.get_all()
                for key, value in config_data.items():
                    # Hide sensitive values
                    if key in ("api_key", "password"):
                        console.print(f"  {key}: [dim]<hidden>[/dim]")
                    else:
                        console.print(f"  {key}: {value}")
                console.print()

        elif choice == 4:
            # Remove backend
            name = click.prompt("\nBackend name")
            if config_manager.has_backend(name):
                if click.confirm(f"Remove backend '{name}'?"):
                    config_manager.remove_backend(name)
                    console.print(f"\n[green]✓[/green] Backend '{name}' removed\n")
            else:
                console.print(f"\n[red]Error:[/red] Backend '{name}' not found\n")

        elif choice == 5:
            console.print("\nExiting configuration manager.\n")
            break


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


def main() -> None:
    """Entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
