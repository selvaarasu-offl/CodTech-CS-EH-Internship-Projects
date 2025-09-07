# File Integrity Checker (SHA-256)

Lightweight Python tool to create and verify file integrity baselines using SHA-256 hashes.

## Features

- Create a baseline snapshot of all files in a directory.
- Verify directory files against the baseline to detect additions, removals, or modifications.
- Update the baseline after intentional changes.
- Supports file exclusion patterns.

## Requirements

- Python 3.6 or higher

## Usage

### Create a baseline

```bash
python file_integrity.py baseline /path/to/dir --out baseline.json
