"""Refresh the sensor's public JA3 threat-intel feed.

    python scripts/update_threat_intel.py
    python scripts/update_threat_intel.py --from-file ja3_fingerprints.csv   # offline / air-gapped copy

Downloads abuse.ch's SSL Blacklist JA3 fingerprint feed (CSV: ja3_md5, first seen,
last seen, listing reason) into backend/sensor-service/intel/sslbl_ja3.csv. In an
enclave without internet access, fetch the file on a connected machine, carry it across
the diode like any other inbound data, and load it with --from-file.

Note: abuse.ch stopped updating this feed in 2021, and a JA3 hash is not unique to one
program, so hits are raised at 0.9 confidence and name the list that matched.
Restart the sensor to load the new feed.
"""

from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path

URL = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
DEST = Path(__file__).resolve().parents[1] / "backend" / "sensor-service" / "intel" / "sslbl_ja3.csv"


def count_entries(text: str) -> int:
    return sum(1 for line in text.splitlines()
               if line.strip() and not line.startswith("#") and len(line.split(",")[0]) == 32)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from-file", type=Path, help="load a previously downloaded CSV instead of fetching")
    args = ap.parse_args()
    if args.from_file:
        text = args.from_file.read_text(encoding="utf-8")
    else:
        with urllib.request.urlopen(URL, timeout=30) as r:
            text = r.read().decode("utf-8")
    n = count_entries(text)
    if n == 0:
        sys.exit("no JA3 entries found - feed format changed? keeping the existing file")
    DEST.write_text(text, encoding="utf-8")
    print(f"{n} JA3 fingerprints -> {DEST}")


if __name__ == "__main__":
    main()
