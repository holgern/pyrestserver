#!/usr/bin/env python3
"""Benchmark script for pyrestserver with local backend and restic.

This script:
1. Starts pyrestserver in the background with local backend
2. Creates a directory with random test files
3. Initializes a restic repository
4. Performs a backup
5. Restores the backup to a different directory
6. Compares both directories
7. Generates a performance report
8. Cleans up all test data
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
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark run."""

    # File generation settings
    num_files: int = 100
    min_file_size: int = 1024  # 1 KB
    max_file_size: int = 1024 * 1024  # 1 MB
    num_subdirs: int = 5

    # Server settings
    server_host: str = "127.0.0.1"
    server_port: int = 8765
    server_user: str = "testuser"
    server_password: str = "testpass"

    # Repository settings
    restic_password: str = "benchmark-password"
    repo_name: str = "benchmark-repo"


@dataclass
class BenchmarkResult:
    """Results from a benchmark run."""

    config: BenchmarkConfig
    total_files: int
    total_size: int
    init_time: float
    backup_time: float
    restore_time: float
    comparison_success: bool
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


def create_test_files(base_dir: Path, config: BenchmarkConfig) -> tuple[int, int]:
    """Create random test files in the specified directory.

    Args:
        base_dir: Base directory to create files in
        config: Benchmark configuration

    Returns:
        Tuple of (file_count, total_size)
    """
    print_step(f"Creating {config.num_files} test files...")

    # Create subdirectories
    subdirs = [base_dir]
    for i in range(config.num_subdirs):
        subdir = base_dir / f"subdir_{i}"
        subdir.mkdir(exist_ok=True)
        subdirs.append(subdir)

    total_size = 0
    file_count = 0

    for i in range(config.num_files):
        # Choose random directory
        target_dir = random.choice(subdirs)

        # Generate random file
        size = random.randint(config.min_file_size, config.max_file_size)
        content = generate_random_content(size)

        # Random filename
        name = f"file_{i}_{random.randint(1000, 9999)}.dat"
        file_path = target_dir / name

        file_path.write_bytes(content)
        total_size += size
        file_count += 1

        if (i + 1) % 20 == 0:
            print(f"  Created {i + 1}/{config.num_files} files...")

    print(f"  ✓ Created {file_count} files ({format_bytes(total_size)})")
    return file_count, total_size


def start_server(
    config: BenchmarkConfig, data_dir: Path, log_file: Path
) -> subprocess.Popen:
    """Start pyrestserver in the background.

    Args:
        config: Benchmark configuration
        data_dir: Directory for server data
        log_file: Path to log file

    Returns:
        Process handle
    """
    print_step("Starting pyrestserver...")

    # For simplicity, we'll use --no-auth mode

    listen_addr = f"{config.server_host}:{config.server_port}"

    cmd = [
        sys.executable,
        "-m",
        "pyrestserver.cli",
        "serve",
        "--listen",
        listen_addr,
        "--backend",
        "local",
        "--path",
        str(data_dir),
        "--no-auth",  # Disable auth for benchmark
    ]

    with log_file.open("w") as log:
        process = subprocess.Popen(
            cmd,
            stdout=log,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )

    # Wait for server to start
    time.sleep(2)

    # Check if server is running
    if process.poll() is not None:
        with log_file.open() as f:
            print(f"Server failed to start. Log:\n{f.read()}")
        raise RuntimeError("Failed to start pyrestserver")

    print(f"  ✓ Server started (PID: {process.pid})")
    return process


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
    except Exception as e:
        elapsed = time.time() - start_time
        return False, str(e), elapsed


def init_restic_repo(config: BenchmarkConfig) -> tuple[bool, float, str]:
    """Initialize restic repository.

    Args:
        config: Benchmark configuration

    Returns:
        Tuple of (success, elapsed_time, error_message)
    """
    print_step("Initializing restic repository...")

    repo_url = (
        f"rest:http://{config.server_host}:{config.server_port}/{config.repo_name}"
    )

    env = os.environ.copy()
    env["RESTIC_PASSWORD"] = config.restic_password

    cmd = ["restic", "-r", repo_url, "init"]

    success, output, elapsed = run_restic_command(cmd, env)

    if success:
        print(f"  ✓ Repository initialized ({format_time(elapsed)})")
        return True, elapsed, ""
    else:
        print(f"  ✗ Initialization failed: {output}")
        return False, elapsed, output


def backup_with_restic(
    config: BenchmarkConfig, source_dir: Path
) -> tuple[bool, float, str]:
    """Backup directory with restic.

    Args:
        config: Benchmark configuration
        source_dir: Directory to backup

    Returns:
        Tuple of (success, elapsed_time, error_message)
    """
    print_step("Backing up with restic...")

    repo_url = (
        f"rest:http://{config.server_host}:{config.server_port}/{config.repo_name}"
    )

    env = os.environ.copy()
    env["RESTIC_PASSWORD"] = config.restic_password

    cmd = ["restic", "-r", repo_url, "backup", str(source_dir)]

    success, output, elapsed = run_restic_command(cmd, env)

    if success:
        print(f"  ✓ Backup completed ({format_time(elapsed)})")
        return True, elapsed, ""
    else:
        print(f"  ✗ Backup failed: {output}")
        return False, elapsed, output


def restore_with_restic(
    config: BenchmarkConfig, restore_dir: Path
) -> tuple[bool, float, str]:
    """Restore latest snapshot with restic.

    Args:
        config: Benchmark configuration
        restore_dir: Directory to restore to

    Returns:
        Tuple of (success, elapsed_time, error_message)
    """
    print_step("Restoring with restic...")

    repo_url = (
        f"rest:http://{config.server_host}:{config.server_port}/{config.repo_name}"
    )

    env = os.environ.copy()
    env["RESTIC_PASSWORD"] = config.restic_password

    cmd = ["restic", "-r", repo_url, "restore", "latest", "--target", str(restore_dir)]

    success, output, elapsed = run_restic_command(cmd, env)

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
    print(f"  Files:           {result.config.num_files}")
    print(
        f"  File size range: {format_bytes(result.config.min_file_size)} - "
        f"{format_bytes(result.config.max_file_size)}"
    )
    print(f"  Subdirectories:  {result.config.num_subdirs}")
    print(f"  Server:          {result.config.server_host}:{result.config.server_port}")

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


def run_benchmark(config: BenchmarkConfig | None = None) -> BenchmarkResult:
    """Run the complete benchmark.

    Args:
        config: Benchmark configuration (uses default if None)

    Returns:
        Benchmark results
    """
    if config is None:
        config = BenchmarkConfig()

    print_header("PYRESTSERVER + RESTIC BENCHMARK")

    # Create temporary directories
    temp_base = Path(tempfile.mkdtemp(prefix="pyrestserver_benchmark_"))
    source_dir = temp_base / "source"
    restore_dir = temp_base / "restore"
    server_data_dir = temp_base / "server_data"
    log_file = temp_base / "server.log"

    source_dir.mkdir()
    restore_dir.mkdir()
    server_data_dir.mkdir()

    server_process = None
    init_time = 0.0
    backup_time = 0.0
    restore_time = 0.0
    comparison_success = False
    error_msg = None
    file_count = 0
    total_size = 0

    try:
        # Create test files
        file_count, total_size = create_test_files(source_dir, config)

        # Start server
        server_process = start_server(config, server_data_dir, log_file)

        # Initialize repository
        success, init_time, error = init_restic_repo(config)
        if not success:
            error_msg = f"Init failed: {error}"
            raise RuntimeError(error_msg)

        # Backup
        success, backup_time, error = backup_with_restic(config, source_dir)
        if not success:
            error_msg = f"Backup failed: {error}"
            raise RuntimeError(error_msg)

        # Restore
        success, restore_time, error = restore_with_restic(config, restore_dir)
        if not success:
            error_msg = f"Restore failed: {error}"
            raise RuntimeError(error_msg)

        # Compare directories
        # restic restores to target/hostname/path,
        # so we need to find the actual restore path
        restored_paths = list(restore_dir.rglob(source_dir.name))
        if not restored_paths:
            # Try finding any subdirectory with files
            for path in restore_dir.rglob("*"):
                if path.is_dir() and any(path.iterdir()):
                    restored_paths = [path]
                    break

        if restored_paths:
            comparison_success, differences = compare_directories(
                source_dir, restored_paths[0]
            )
        else:
            error_msg = "Could not find restored files"
            comparison_success = False

    except Exception as e:
        error_msg = str(e)
        print(f"\n✗ Benchmark failed: {e}")

    finally:
        # Stop server
        if server_process:
            stop_server(server_process)

        # Create result
        result = BenchmarkResult(
            config=config,
            total_files=file_count,
            total_size=total_size,
            init_time=init_time,
            backup_time=backup_time,
            restore_time=restore_time,
            comparison_success=comparison_success,
            error=error_msg,
        )

        # Print report
        print_report(result)

        # Cleanup
        cleanup([temp_base])

    return result


def main() -> int:
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Benchmark pyrestserver with restic",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--files",
        type=int,
        default=100,
        help="Number of files to create",
    )
    parser.add_argument(
        "--min-size",
        type=int,
        default=1024,
        help="Minimum file size in bytes",
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=1024 * 1024,
        help="Maximum file size in bytes",
    )
    parser.add_argument(
        "--subdirs",
        type=int,
        default=5,
        help="Number of subdirectories",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Server port",
    )

    args = parser.parse_args()

    config = BenchmarkConfig(
        num_files=args.files,
        min_file_size=args.min_size,
        max_file_size=args.max_size,
        num_subdirs=args.subdirs,
        server_port=args.port,
    )

    result = run_benchmark(config)

    return 0 if result.comparison_success and result.error is None else 1


if __name__ == "__main__":
    sys.exit(main())
