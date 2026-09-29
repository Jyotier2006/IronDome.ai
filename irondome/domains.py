"""Real benign domain corpora for the DGA detector.

The lab's own benign names come from a small word list, which is not enough: real
popular domains (google-analytics.com, youtube-nocookie.com, amazon-adsystem.com)
look unusual to a model that has only seen the lab. When the Tranco top-sites list
has been downloaded (scripts/fetch_domain_lists.py -> data/tranco_top.txt), training
draws benign domains from it, and every domain is assigned to exactly one partition
(train / validation / test / stress) by a hash of its name, so held-out numbers never
include a domain the model was trained on.

The sensor itself never needs these lists at runtime.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

from .netutil import registered_domain

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
TRANCO = DATA_DIR / "tranco_top.txt"
OPENDNS = DATA_DIR / "opendns_top.txt"

# share of each partition (sums to 100)
_PARTS = (("train", 70), ("validation", 12), ("test", 12), ("stress", 6))


def domain_split(domain: str) -> str:
    """Stable partition of a registered domain."""
    h = int(hashlib.sha1(registered_domain(domain).encode()).hexdigest()[:8], 16) % 100
    acc = 0
    for name, share in _PARTS:
        acc += share
        if h < acc:
            return name
    return "stress"


def read_list(path: Path) -> list[str]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            out.append(line.split(",")[-1])
    return out


def list_header(path: Path) -> str:
    if not path.exists():
        return ""
    with open(path, encoding="utf-8") as f:
        first = f.readline().strip()
    return first.lstrip("# ") if first.startswith("#") else path.name


@lru_cache(maxsize=None)
def real_benign(split: str) -> tuple[str, ...]:
    """Registered domains from the Tranco list that fall in `split` (empty if not downloaded)."""
    seen, out = set(), []
    for d in read_list(TRANCO):
        rd = registered_domain(d)
        if rd not in seen and domain_split(rd) == split:
            seen.add(rd)
            out.append(rd)
    return tuple(out)


def available() -> bool:
    return TRANCO.exists()
