"""Download the real benign domain lists used to train and validate the DGA detector.

    python scripts/fetch_domain_lists.py              # Tranco top 100k + OpenDNS top domains
    python scripts/fetch_domain_lists.py --top 200000

Writes data/tranco_top.txt (one registered domain per line, by rank) and
data/opendns_top.txt. The lists are not committed to the repository; training uses
them when present (model_microservice/model_training_pipeline.py) and records the
list date in the model card. Only benign data is fetched here: malicious DGA samples
come from the traffic lab's generic generators, and real DGA recall is measured with
model_microservice/evaluate_domains.py on a labelled list you supply.
"""

from __future__ import annotations

import argparse
import io
import urllib.request
import zipfile
from datetime import date
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data"
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"
OPENDNS = "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt"


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "irondome-domain-lists/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--top", type=int, default=100_000, help="how many Tranco domains to keep")
    args = ap.parse_args()
    DATA.mkdir(exist_ok=True)

    raw = zipfile.ZipFile(io.BytesIO(fetch(TRANCO))).read("top-1m.csv").decode("utf-8")
    domains = [line.split(",", 1)[1].strip().lower() for line in raw.splitlines()[: args.top] if "," in line]
    (DATA / "tranco_top.txt").write_text(f"# Tranco top {len(domains)} (https://tranco-list.eu), fetched {date.today()}\n"
                                         + "\n".join(domains) + "\n", encoding="utf-8")
    print(f"{len(domains):,} Tranco domains -> {DATA / 'tranco_top.txt'}")

    odns = [d.strip().lower() for d in fetch(OPENDNS).decode("utf-8").splitlines() if d.strip() and not d.startswith("#")]
    (DATA / "opendns_top.txt").write_text(f"# OpenDNS public top domains ({OPENDNS}), fetched {date.today()}\n"
                                          + "\n".join(odns) + "\n", encoding="utf-8")
    print(f"{len(odns):,} OpenDNS domains -> {DATA / 'opendns_top.txt'}")


if __name__ == "__main__":
    main()
