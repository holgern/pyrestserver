"""Common utilities and functions for benchmark scripts.

This module contains shared components used by both local and Drime
benchmark scripts for testing pyrestserver with restic.
"""

from __future__ import annotations

import hashlib
import os
import random
import shutil
import signal
import string
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class BenchmarkResult:
    """Results from a benchmark run."""

    total_files: int
    total_size: int
    init_time: float
    backup_time: float
    restore_time: float
    comparison_success: bool
    backend_type: str
    config_summary: dict[str, str | int]
    error: str | None = None


def print_header(text: str) -> None:
    """Print a formatted header."""
    print(f"\n{'=' * 70}")
    print(f"  {text}")
    print(f"{'=' * 70}\n")


def print_step(text: str) -> None:
    """Print a step description."""
    print(f"→ {text}")


def format_bytes(size: int) -> str:
    """Format bytes to human-readable string."""
    size_float = float(size)
    for unit in ["B", "KB", "MB", "GB"]:
        if size_float < 1024:
            return f"{size_float:.2f} {unit}"
        size_float /= 1024
    return f"{size_float:.2f} TB"


def format_time(seconds: float) -> str:
    """Format time to human-readable string."""
    if seconds < 1:
        return f"{seconds * 1000:.2f} ms"
    elif seconds < 60:
        return f"{seconds:.2f} s"
    else:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"


def generate_random_content(size: int) -> bytes:
    """Generate random binary content of specified size."""
    # Use a mix of random bytes and compressible patterns
    if random.random() > 0.5:
        # Compressible pattern (repeated characters)
        char = random.choice(string.ascii_letters).encode()
        return char * size
    else:
        # Random bytes (less compressible)
        return os.urandom(size)


def create_test_files(
    base_dir: Path,
    num_files: int,
    min_file_size: int,
    max_file_size: int,
    num_subdirs: int,
) -> tuple[int, int]:
    """Create random test files in the specified directory.

    Args:
        base_dir: Base directory to create files in
        num_files: Number of files to create
        min_file_size: Minimum file size in bytes
        max_file_size: Maximum file size in bytes
        num_subdirs: Number of subdirectories to create

    Returns:
        Tuple of (file_count, total_size)
    """
    print_step(f"Creating {num_files} test files...")

    # Create subdirectories
    subdirs = [base_dir]
    for i in range(num_subdirs):
        subdir = base_dir / f"subdir_{i}"
        subdir.mkdir(exist_ok=True)
        subdirs.append(subdir)

    total_size = 0
    file_count = 0

    for i in range(num_files):
        # Choose random directory
        target_dir = random.choice(subdirs)

        # Generate random file
        size = random.randint(min_file_size, max_file_size)
        content = generate_random_content(size)

        # Random filename
        name = f"file_{i}_{random.randint(1000, 9999)}.dat"
        file_path = target_dir / name

        file_path.write_bytes(content)
        total_size += size
        file_count += 1

        if (i + 1) % 20 == 0:
            print(f"  Created {i + 1}/{num_files} files...")

    print(f"  ✓ Created {file_count} files ({format_bytes(total_size)})")
    return file_count, total_size


def get_restic_command() -> str:
    """Get the correct restic command for the current platform.

    Returns:
        Command name to use for restic
    """
    # On Windows, try to find restic.exe
    if sys.platform == "win32":
        # Check if restic.exe exists in PATH
        import shutil as sh

        restic_path = sh.which("restic.exe")
        if restic_path:
            return "restic.exe"
        # Fall back to just "restic"
        return "restic"
    else:
        return "restic"


def stop_server(process: subprocess.Popen) -> None:
    """Stop the server process.

    Args:
        process: Server process handle
    """
    print_step("Stopping server...")

    try:
        # Try graceful shutdown first
        if hasattr(os, "killpg"):
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        else:
            process.terminate()

        # Wait up to 5 seconds
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Force kill if needed
            if hasattr(os, "killpg"):
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            else:
                process.kill()
            process.wait()

        print("  ✓ Server stopped")
    except Exception as e:
        print(f"  ⚠ Error stopping server: {e}")


def run_restic_command(
    cmd: list[str], env: dict[str, str], timeout: int = 300
) -> tuple[bool, str, float]:
    """Run a restic command and measure execution time.

    Args:
        cmd: Command to run
        env: Environment variables
        timeout: Command timeout in seconds

    Returns:
        Tuple of (success, output, elapsed_time)
    """
    start_time = time.time()

    try:
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        elapsed = time.time() - start_time

        success = result.returncode == 0
        output = result.stdout + result.stderr

        return success, output, elapsed
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_time
        return False, f"Command timed out after {timeout}s", elapsed
    except FileNotFoundError as e:
        elapsed = time.time() - start_time
        return (
            False,
            f"Command not found: {cmd[0]}. Please ensure restic is "
            f"installed and in your PATH. Error: {e}",
            elapsed,
        )
    except Exception as e:
        elapsed = time.time() - start_time
        return False, f"Error running command: {e}", elapsed


def init_restic_repo(
    server_host: str, server_port: int, repo_name: str, restic_password: str
) -> tuple[bool, float, str]:
    """Initialize restic repository.

    Args:
        server_host: Server hostname
        server_port: Server port
        repo_name: Repository name
        restic_password: Restic repository password

    Returns:
        Tuple of (success, elapsed_time, error_message)
    """
    print_step("Initializing restic repository...")

    repo_url = f"rest:http://{server_host}:{server_port}/{repo_name}"

    env = os.environ.copy()
    env["RESTIC_PASSWORD"] = restic_password

    restic_cmd = get_restic_command()
    cmd = [restic_cmd, "-r", repo_url, "init"]

    success, output, elapsed = run_restic_command(cmd, env)

    if success:
        print(f"  ✓ Repository initialized ({format_time(elapsed)})")
        return True, elapsed, ""
    else:
        print(f"  ✗ Initialization failed: {output}")
        return False, elapsed, output


def backup_with_restic(
    server_host: str,
    server_port: int,
    repo_name: str,
    restic_password: str,
    source_dir: Path,
) -> tuple[bool, float, str]:
    """Backup directory with restic.

    Args:
        server_host: Server hostname
        server_port: Server port
        repo_name: Repository name
        restic_password: Restic repository password
        source_dir: Directory to backup

    Returns:
        Tuple of (success, elapsed_time, error_message)
    """
    print_step("Backing up with restic...")

    repo_url = f"rest:http://{server_host}:{server_port}/{repo_name}"

    env = os.environ.copy()
    env["RESTIC_PASSWORD"] = restic_password

    restic_cmd = get_restic_command()
    cmd = [restic_cmd, "-r", repo_url, "backup", str(source_dir)]

    success, output, elapsed = run_restic_command(cmd, env)

    if success:
        print(f"  ✓ Backup completed ({format_time(elapsed)})")
        return True, elapsed, ""
    else:
        print(f"  ✗ Backup failed: {output}")
        return False, elapsed, output


def restore_with_restic(
    server_host: str,
    server_port: int,
    repo_name: str,
    restic_password: str,
    restore_dir: Path,
) -> tuple[bool, float, str]:
    """Restore latest snapshot with restic.

    Args:
        server_host: Server hostname
        server_port: Server port
        repo_name: Repository name
        restic_password: Restic repository password
        restore_dir: Directory to restore to

    Returns:
        Tuple of (success, elapsed_time, error_message)
    """
    print_step("Restoring with restic...")

    repo_url = f"rest:http://{server_host}:{server_port}/{repo_name}"

    env = os.environ.copy()
    env["RESTIC_PASSWORD"] = restic_password

    restic_cmd = get_restic_command()
    cmd = [
        restic_cmd,
        "-r",
        repo_url,
        "restore",
        "latest",
        "--target",
        str(restore_dir),
    ]

    success, output, elapsed = run_restic_command(cmd, env)

    # On Windows, timestamp restoration failures are common due to
    # permission restrictions. These are non-critical errors - check if
    # restore actually succeeded despite the error.
    if not success and sys.platform == "win32":
        # Check if the error is only about timestamp/permission issues
        if (
            "failed to restore timestamp" in output.lower()
            or "access is denied" in output.lower()
        ):
            # Verify if files were actually restored despite the error
            restored_files = list(restore_dir.rglob("*"))
            if len(restored_files) > 0:
                print("  ⚠ Timestamp restoration failed on Windows (non-critical)")
                print("  ✓ Files restored successfully despite timestamp warnings")
                # Treat as success since files are there
                return True, elapsed, ""

    if success:
        print(f"  ✓ Restore completed ({format_time(elapsed)})")
        return True, elapsed, ""
    else:
        print(f"  ✗ Restore failed: {output}")
        return False, elapsed, output


def compute_file_hash(file_path: Path) -> str:
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def compare_directories(dir1: Path, dir2: Path) -> tuple[bool, list[str]]:
    """Compare two directories recursively.

    Args:
        dir1: First directory
        dir2: Second directory

    Returns:
        Tuple of (match, differences)
    """
    print_step("Comparing directories...")

    differences = []

    # Get all files in both directories
    files1 = {p.relative_to(dir1): p for p in dir1.rglob("*") if p.is_file()}
    files2 = {p.relative_to(dir2): p for p in dir2.rglob("*") if p.is_file()}

    # Check for missing files
    only_in_1 = set(files1.keys()) - set(files2.keys())
    only_in_2 = set(files2.keys()) - set(files1.keys())

    if only_in_1:
        differences.append(f"Files only in original: {only_in_1}")
    if only_in_2:
        differences.append(f"Files only in restore: {only_in_2}")

    # Compare common files
    common_files = set(files1.keys()) & set(files2.keys())
    for rel_path in common_files:
        file1 = files1[rel_path]
        file2 = files2[rel_path]

        # Compare sizes
        if file1.stat().st_size != file2.stat().st_size:
            differences.append(
                f"Size mismatch for {rel_path}: "
                f"{file1.stat().st_size} vs {file2.stat().st_size}"
            )
            continue

        # Compare content (hash)
        hash1 = compute_file_hash(file1)
        hash2 = compute_file_hash(file2)

        if hash1 != hash2:
            differences.append(f"Content mismatch for {rel_path}")

    if not differences:
        print(f"  ✓ Directories match perfectly ({len(common_files)} files)")
        return True, []
    else:
        print(f"  ✗ Found {len(differences)} differences")
        for diff in differences[:5]:  # Show first 5
            print(f"    - {diff}")
        if len(differences) > 5:
            print(f"    ... and {len(differences) - 5} more")
        return False, differences


def cleanup(paths: list[Path]) -> None:
    """Clean up test directories.

    Args:
        paths: List of paths to remove
    """
    print_step("Cleaning up...")

    for path in paths:
        try:
            if path.exists():
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
                print(f"  ✓ Removed {path}")
        except Exception as e:
            print(f"  ⚠ Failed to remove {path}: {e}")


def print_report(result: BenchmarkResult) -> None:
    """Print benchmark report.

    Args:
        result: Benchmark results
    """
    print_header("BENCHMARK REPORT")

    print("Configuration:")
    for key, value in result.config_summary.items():
        print(f"  {key}: {value}")

    print("\nTest Data:")
    print(f"  Total files:     {result.total_files}")
    print(f"  Total size:      {format_bytes(result.total_size)}")

    print("\nPerformance:")
    print(f"  Init time:       {format_time(result.init_time)}")
    print(f"  Backup time:     {format_time(result.backup_time)}")
    print(f"  Restore time:    {format_time(result.restore_time)}")
    total_time = result.init_time + result.backup_time + result.restore_time
    print(f"  Total time:      {format_time(total_time)}")

    if result.backup_time > 0:
        throughput = result.total_size / result.backup_time
        print(f"  Backup rate:     {format_bytes(int(throughput))}/s")

    if result.restore_time > 0:
        throughput = result.total_size / result.restore_time
        print(f"  Restore rate:    {format_bytes(int(throughput))}/s")

    print("\nVerification:")
    if result.comparison_success:
        print("  ✓ Backup and restore successful - all files match!")
    else:
        print("  ✗ Verification failed - files don't match")

    if result.error:
        print(f"\nError: {result.error}")

    print(f"\n{'=' * 70}\n")


def find_restored_directory(restore_dir: Path, source_dir: Path) -> Path | None:
    """Find the actual restored directory path.

    restic restores to target/hostname/path, so we need to find
    the actual restore path.

    Args:
        restore_dir: Base restore directory
        source_dir: Original source directory

    Returns:
        Path to restored directory or None if not found
    """
    restored_paths = list(restore_dir.rglob(source_dir.name))
    if not restored_paths:
        # Try finding any subdirectory with files
        for path in restore_dir.rglob("*"):
            if path.is_dir() and any(path.iterdir()):
                return path
        return None
    return restored_paths[0]
