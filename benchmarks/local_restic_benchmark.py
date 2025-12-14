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

import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

try:
    # Try relative import first (when run as module)
    from .benchmark_common import (
        BenchmarkResult,
        backup_with_restic,
        cleanup,
        compare_directories,
        create_test_files,
        find_restored_directory,
        format_bytes,
        init_restic_repo,
        print_header,
        print_report,
        print_step,
        restore_with_restic,
        stop_server,
    )
except ImportError:
    # Fall back to direct import (when run as script)
    from benchmark_common import (  # type: ignore[import-not-found]
        BenchmarkResult,
        backup_with_restic,
        cleanup,
        compare_directories,
        create_test_files,
        find_restored_directory,
        format_bytes,
        init_restic_repo,
        print_header,
        print_report,
        print_step,
        restore_with_restic,
        stop_server,
    )


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

    # Prepare subprocess arguments based on platform
    log = log_file.open("w")
    kwargs = {
        "stdout": log,
        "stderr": subprocess.STDOUT,
    }

    if hasattr(os, "setsid"):
        # Unix/Linux/macOS
        kwargs["preexec_fn"] = os.setsid
    elif sys.platform == "win32":
        # Windows - create new process group
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]

    process = subprocess.Popen(cmd, **kwargs)

    # Wait for server to start
    time.sleep(2)

    # Check if server is running
    if process.poll() is not None:
        log.close()
        with log_file.open() as f:
            print(f"Server failed to start. Log:\n{f.read()}")
        raise RuntimeError("Failed to start pyrestserver")

    print(f"  ✓ Server started (PID: {process.pid})")
    return process


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
        file_count, total_size = create_test_files(
            source_dir,
            config.num_files,
            config.min_file_size,
            config.max_file_size,
            config.num_subdirs,
        )

        # Start server
        server_process = start_server(config, server_data_dir, log_file)

        # Initialize repository
        success, init_time, error = init_restic_repo(
            config.server_host,
            config.server_port,
            config.repo_name,
            config.restic_password,
        )
        if not success:
            error_msg = f"Init failed: {error}"
            raise RuntimeError(error_msg)

        # Backup
        success, backup_time, error = backup_with_restic(
            config.server_host,
            config.server_port,
            config.repo_name,
            config.restic_password,
            source_dir,
        )
        if not success:
            error_msg = f"Backup failed: {error}"
            raise RuntimeError(error_msg)

        # Restore
        success, restore_time, error = restore_with_restic(
            config.server_host,
            config.server_port,
            config.repo_name,
            config.restic_password,
            restore_dir,
        )
        if not success:
            error_msg = f"Restore failed: {error}"
            raise RuntimeError(error_msg)

        # Compare directories
        restored_path = find_restored_directory(restore_dir, source_dir)
        if restored_path:
            comparison_success, differences = compare_directories(
                source_dir, restored_path
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
            total_files=file_count,
            total_size=total_size,
            init_time=init_time,
            backup_time=backup_time,
            restore_time=restore_time,
            comparison_success=comparison_success,
            backend_type="Local",
            config_summary={
                "Files": config.num_files,
                "File size range": f"{format_bytes(config.min_file_size)} - "
                f"{format_bytes(config.max_file_size)}",
                "Subdirectories": config.num_subdirs,
                "Server": f"{config.server_host}:{config.server_port}",
                "Backend": "Local",
            },
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
