# PyRestServer Benchmarks

This directory contains benchmark scripts for testing pyrestserver performance.

## Available Benchmarks

### local_restic_benchmark.py

A comprehensive benchmark that tests pyrestserver with a local backend and restic
client.

**What it does:**

1. Starts pyrestserver in the background with local backend
2. Creates a directory with random test files
3. Initializes a restic repository
4. Performs a backup
5. Restores the backup to a different directory
6. Compares both directories to verify integrity
7. Generates a performance report
8. Cleans up all test data

**Requirements:**

- restic must be installed and available in PATH
- pyrestserver must be installed

**Usage:**

```bash
# Run with default settings (100 files)
python -m benchmarks.local_restic_benchmark

# Run with custom settings
python -m benchmarks.local_restic_benchmark \
  --files 50 \
  --min-size 1024 \
  --max-size 1048576 \
  --subdirs 5 \
  --port 8765

# Show help
python -m benchmarks.local_restic_benchmark --help
```

**Options:**

- `--files N`: Number of files to create (default: 100)
- `--min-size BYTES`: Minimum file size in bytes (default: 1024)
- `--max-size BYTES`: Maximum file size in bytes (default: 1048576)
- `--subdirs N`: Number of subdirectories (default: 5)
- `--port PORT`: Server port (default: 8765)

**Example Output:**

```
======================================================================
  BENCHMARK REPORT
======================================================================

Configuration:
  Files:           50
  File size range: 1.00 KB - 1.00 MB
  Subdirectories:  3
  Server:          127.0.0.1:8765

Test Data:
  Total files:     50
  Total size:      26.73 MB

Performance:
  Init time:       2.63 s
  Backup time:     1.06 s
  Restore time:    774.18 ms
  Total time:      4.47 s
  Backup rate:     25.16 MB/s
  Restore rate:    34.52 MB/s

Verification:
  ✓ Backup and restore successful - all files match!

======================================================================
```

## Adding New Benchmarks

To add a new benchmark:

1. Create a new Python file in this directory
2. Follow the naming convention: `{backend}_{client}_benchmark.py`
3. Include command-line arguments for configurability
4. Provide clear output and reporting
5. Clean up all test data after completion
6. Add documentation to this README
