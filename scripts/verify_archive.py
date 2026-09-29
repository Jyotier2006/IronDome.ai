"""Verify the sensor's signed, hash-chained alert archive.

    IRONDOME_ARCHIVE_KEY=<key> python scripts/verify_archive.py /var/lib/irondome/archive
    python scripts/verify_archive.py archive/ --key-file archive.key

Checks every record in order: sequence numbers are contiguous, each record's `prev`
equals the previous record's hash, the hash matches the record's content, and the
HMAC-SHA256 signature matches the key. Any deleted, reordered, edited or forged record
is reported with its file and line. Exit status 0 = intact, 1 = tampered.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from irondome.outputs import verify_archive  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("directory", type=Path)
    ap.add_argument("--key-file", type=Path, help="file holding the signing key (default: $IRONDOME_ARCHIVE_KEY)")
    args = ap.parse_args()
    key = args.key_file.read_text(encoding="utf-8").strip() if args.key_file else os.environ.get("IRONDOME_ARCHIVE_KEY", "")
    if not key:
        sys.exit("no key: set IRONDOME_ARCHIVE_KEY or pass --key-file")
    res = verify_archive(args.directory, key.encode("utf-8"))
    if res["ok"]:
        print(f"OK - {res['records']:,} records intact, chain head {res['head']}")
        return
    print(f"TAMPERED after {res['records']:,} good records: {res['error']}")
    sys.exit(1)


if __name__ == "__main__":
    main()
