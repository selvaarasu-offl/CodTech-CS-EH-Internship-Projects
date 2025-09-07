import os
import sys
import json
import argparse
import hashlib
import time
from pathlib import Path

CHUNK = 8192  # Bytes per read during hashing

def file_sha256(path: Path) -> str:
    """Calculate SHA-256 hash of a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()

def scan_dir(root: Path, exclude: list = None):
    """Recursively scan directory and return a dict of file hashes and metadata."""
    exclude = exclude or []
    records = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = Path(dirpath) / fn
            rel = str(p.relative_to(root))
            if any(Path(rel).match(pattern) for pattern in exclude):
                print(f"Excluding: {rel}")
                continue
            print(f"Including: {rel}")

            try:
                records[rel] = {
                    "hash": file_sha256(p),
                    "size": p.stat().st_size,
                    "mtime": p.stat().st_mtime
                }
            except (PermissionError, OSError) as e:
                records[rel] = {"error": str(e)}
    return records

def save_baseline(path: Path, records: dict):
    """Save baseline data to JSON file."""
    payload = {
        "generated": time.time(),
        "records": records
    }
    path.write_text(json.dumps(payload, indent=2))

def load_baseline(path: Path):
    """Load baseline data from JSON file."""
    return json.loads(path.read_text())

def compare(baseline: dict, current: dict):
    """Compare current scan to baseline, return added, removed, modified files."""
    base_records = baseline.get("records", {})
    added, removed, modified = [], [], []

    for f in current:
        if f not in base_records:
            added.append(f)
        else:
            b = base_records[f].get("hash")
            c = current[f].get("hash")
            if b != c:
                modified.append((f, b, c))

    for f in base_records:
        if f not in current:
            removed.append(f)

    return added, removed, modified

def main():
    ap = argparse.ArgumentParser(description="File Integrity Checker (SHA-256)")
    sub = ap.add_subparsers(dest="cmd")

    # Baseline subcommand
    p_base = sub.add_parser("baseline", help="Create or update baseline")
    p_base.add_argument("path", type=Path, help="Directory to scan")
    p_base.add_argument("--out", "-o", type=Path, required=True, help="Output JSON file")
    p_base.add_argument("--exclude", "-e", nargs="*", default=[], help="Patterns to exclude")
    p_base.add_argument("--update", action="store_true", help="Overwrite if baseline exists")

    # Verify subcommand
    p_verify = sub.add_parser("verify", help="Verify directory against baseline")
    p_verify.add_argument("path", type=Path, help="Directory to scan")
    p_verify.add_argument("--baseline", "-b", type=Path, required=True, help="Baseline JSON file")
    p_verify.add_argument("--exclude", "-e", nargs="*", default=[], help="Patterns to exclude")

    args = ap.parse_args()

    # Manual check for required subcommand (for Python < 3.7)
    if not args.cmd:
        ap.print_help()
        sys.exit(1)

    # Handle baseline mode
    if args.cmd == "baseline":
        if args.out.exists() and not args.update:
            print(f"{args.out} exists. Use --update to overwrite.", file=sys.stderr)
            sys.exit(1)
        rec = scan_dir(args.path, exclude=args.exclude)
        save_baseline(args.out, rec)
        print(f"Baseline written to {args.out} ({len(rec)} files).")

    # Handle verify mode
    elif args.cmd == "verify":
        baseline = load_baseline(args.baseline)
        current = scan_dir(args.path, exclude=args.exclude)
        added, removed, modified = compare(baseline, current)

        print("Verification summary:")
        print(f"  Added:    {len(added)}")
        print(f"  Removed:  {len(removed)}")
        print(f"  Modified: {len(modified)}")

        if added:
            print("\nAdded files:")
            for a in added:
                print("  +", a)
        if removed:
            print("\nRemoved files:")
            for r in removed:
                print("  -", r)
        if modified:
            print("\nModified files (filename, baseline-hash, current-hash):")
            for f, bh, ch in modified:
                print("  *", f)
                print("    baseline:", bh)
                print("    current: ", ch)

if __name__ == "__main__":
    main()
