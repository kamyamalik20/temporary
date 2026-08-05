import argparse
import json
import os
import platform
import socket
import stat as stat_module
import tempfile
import time
from pathlib import Path

# -------------------------------------------------
# Project Paths
# -------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

# Create data directory if it doesn't exist
DATA_DIR.mkdir(exist_ok=True)


# -------------------------------------------------
# Default Scan Paths
# -------------------------------------------------
def default_paths():
    system = platform.system()

    if system == "Linux":
        paths = ["/tmp", "/var/log"]

        # Add /backup only if it exists
        if os.path.isdir("/backup"):
            paths.append("/backup")

        return paths

    elif system == "Windows":
        return [tempfile.gettempdir()]

    return [tempfile.gettempdir()]


# -------------------------------------------------
# Command Line Arguments
# -------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Find large, old files and export as JSON."
    )

    parser.add_argument(
        "--path",
        action="append",
        help="Folder(s) to scan. Can be repeated."
    )

    parser.add_argument(
        "--min-size-mb",
        type=float,
        default=50,
        help="Ignore files smaller than this size."
    )

    parser.add_argument(
        "--min-age-days",
        type=int,
        default=30,
        help="Ignore files newer than this."
    )

    parser.add_argument(
        "--output",
        default=str(DATA_DIR / "files.json"),
        help="Output JSON path"
    )

    return parser.parse_args()


# -------------------------------------------------
# Detect File Type
# -------------------------------------------------
def classify_type(path: str):

    lower = path.lower().replace("\\", "/")

    if lower.endswith(".log") or "/var/log" in lower:
        return "log"

    elif lower.endswith(".tmp") or "/tmp/" in lower:
        return "tmp"

    elif "cache" in lower:
        return "cache"

    elif "backup" in lower or lower.endswith(".bak"):
        return "backup"

    elif lower.endswith(".iso"):
        return "iso"

    return "unknown"


# -------------------------------------------------
# Scan Files
#
# BUG FIX (see Learning.md "None date / 0B size"):
# The previous version only emitted `age_days` (an integer) and `size_mb`.
# There was never an explicit, human-readable date field, and no plain
# "size"/"date" keys at all. Any downstream code that looked for
# file.get("date") or file.get("size") — instead of the exact keys
# age_days/size_mb — silently got None/0 back with no error, because
# dict.get() doesn't fail on a missing key.
#
# Fix: emit BOTH the precise machine fields (age_days, size_mb, size_bytes)
# AND an explicit modified_date string, so there is no ambiguous/missing
# key for a consumer to guess at. Also switch to a single lstat() call
# (instead of lstat() + a separate islink() call) to avoid a redundant
# syscall and a small TOCTOU window between the two checks.
# -------------------------------------------------
def scan(paths, min_size_mb, min_age_days):

    now = time.time()

    results = []

    for root_path in paths:

        if not os.path.isdir(root_path):
            print(f"Skipping: {root_path}")
            continue

        print(f"\nScanning: {root_path}")

        for dirpath, _, filenames in os.walk(root_path):

            for filename in filenames:

                filepath = os.path.join(dirpath, filename)

                try:
                    st = os.lstat(filepath)
                except (PermissionError, OSError):
                    continue

                # Skip symlinks using the stat result we already have,
                # instead of a second os.path.islink() syscall.
                if stat_module.S_ISLNK(st.st_mode):
                    continue

                # Skip anything that isn't a regular file (dirs, sockets,
                # devices, etc). Uses the same stat result — no extra
                # syscall, and no race between check and use.
                if not stat_module.S_ISREG(st.st_mode):
                    continue

                size_mb = round(st.st_size / (1024 * 1024), 2)
                age_days = int((now - st.st_mtime) / 86400)

                if size_mb < min_size_mb:
                    continue

                if age_days < min_age_days:
                    continue

                results.append({
                    "path": filepath,
                    "size_mb": size_mb,
                    "size_bytes": st.st_size,
                    "age_days": age_days,
                    # Explicit, always-present human-readable date.
                    # This is the field that was previously missing.
                    "modified_date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                    "type": classify_type(filepath),
                    # Owner UID, used by app.policy.check_ownership to make
                    # sure the AI only recommends cleanup on files owned by
                    # a real human account, not a system/service account.
                    # None on platforms without POSIX ownership (Windows).
                    "owner_uid": getattr(st, "st_uid", None),
                })

    return results


# -------------------------------------------------
# Main
# -------------------------------------------------
def main():

    args = parse_args()

    paths = args.path if args.path else default_paths()

    print("=" * 60)
    print("         FILE SCANNER STARTED")
    print("=" * 60)
    print(f"Operating System : {platform.system()}")
    print(f"Scanning Paths   : {paths}")
    print(f"Minimum Size     : {args.min_size_mb} MB")
    print(f"Minimum Age      : {args.min_age_days} days")
    print("=" * 60)

    files = scan(
        paths,
        args.min_size_mb,
        args.min_age_days
    )

    output = {
        "hostname": socket.gethostname(),
        # Always present — this key going missing entirely (rather than
        # just being empty) was part of the original bug; see Learning.md.
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "files": files
    }

    with open(args.output, "w") as file:
        json.dump(output, file, indent=4)

    print("\n---------------------------------------")
    print(f"Files Found : {len(files)}")
    print(f"Output File : {args.output}")
    print("---------------------------------------")


if __name__ == "__main__":
    main()
