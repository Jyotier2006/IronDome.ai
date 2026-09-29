"""Small statistics, entropy, IP and domain helpers (stdlib only)."""

from __future__ import annotations

import ipaddress
import math
import os

# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def mean(xs) -> float:
    xs = list(xs)
    return sum(xs) / len(xs) if xs else 0.0


def pstdev(xs) -> float:
    xs = list(xs)
    if len(xs) < 2:
        return 0.0
    m = sum(xs) / len(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs))


def cv(xs) -> float:
    """Coefficient of variation (std / mean); 0 for empty or zero-mean input."""
    xs = list(xs)
    m = mean(xs)
    return pstdev(xs) / m if m > 0 else 0.0


def median(xs) -> float:
    s = sorted(xs)
    n = len(s)
    if not n:
        return 0.0
    mid = n // 2
    return float(s[mid]) if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def mad(xs) -> float:
    """Median absolute deviation."""
    xs = list(xs)
    if not xs:
        return 0.0
    med = median(xs)
    return median(abs(x - med) for x in xs)


def entropy_from_counts(counts) -> float:
    """Shannon entropy in bits of a distribution given as counts."""
    counts = [c for c in counts if c > 0]
    total = sum(counts)
    if total <= 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts)


def normalized_entropy(counts) -> float:
    """Entropy divided by its maximum log2(k); 0 for k < 2."""
    counts = [c for c in counts if c > 0]
    k = len(counts)
    if k < 2:
        return 0.0
    return entropy_from_counts(counts) / math.log2(k)


def str_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return entropy_from_counts(freq.values())


def log10p(x: float) -> float:
    return math.log10(max(0.0, x) + 1.0)


# ---------------------------------------------------------------------------
# Internal / external address classification
# ---------------------------------------------------------------------------
_DEFAULT_INTERNAL = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"


class AddressClassifier:
    """Decides whether an address belongs to the protected (internal) estate.

    Configure with IRONDOME_INTERNAL_CIDRS="10.0.0.0/8,203.0.113.0/24". Results are
    cached; the cache is bounded so spoofed-source floods cannot exhaust memory.
    """

    def __init__(self, cidrs: str | None = None):
        spec = cidrs or os.environ.get("IRONDOME_INTERNAL_CIDRS") or _DEFAULT_INTERNAL
        self.networks = [ipaddress.ip_network(c.strip(), strict=False) for c in spec.split(",") if c.strip()]
        self._cache: dict[str, bool] = {}

    def is_internal(self, ip: str) -> bool:
        r = self._cache.get(ip)
        if r is None:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                r = False
            else:
                r = any(addr.version == n.version and addr in n for n in self.networks)
            if len(self._cache) > 200_000:
                self._cache.clear()
            self._cache[ip] = r
        return r


_default_classifier: AddressClassifier | None = None


def is_internal(ip: str) -> bool:
    global _default_classifier
    if _default_classifier is None:
        _default_classifier = AddressClassifier()
    return _default_classifier.is_internal(ip)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Domain helpers (approximate eTLD+1 without shipping the Public Suffix List)
# ---------------------------------------------------------------------------
MULTI_PART_SUFFIXES = {
    "co.in", "gov.in", "ac.in", "net.in", "org.in", "nic.in", "res.in", "edu.in", "firm.in", "gen.in", "ind.in",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.br", "com.cn", "net.cn", "org.cn", "com.sg", "com.my", "co.za", "co.nz", "com.tr", "com.mx",
    "com.hk", "com.tw", "co.kr", "com.pk", "com.bd", "com.np", "com.lk",
}


def split_domain(qname: str) -> tuple[str, str, str]:
    """Split a query name into (subdomain, second-level label, public suffix).

    >>> split_domain("a.b.example.co.in")
    ('a.b', 'example', 'co.in')
    """
    labels = [lab for lab in qname.strip(".").lower().split(".") if lab]
    if not labels:
        return "", "", ""
    if len(labels) == 1:
        return "", labels[0], ""
    # longest matching multi-part suffix (up to 4 labels)
    for n in (4, 3, 2):
        if len(labels) > n and ".".join(labels[-n:]) in MULTI_PART_SUFFIXES:
            suffix = ".".join(labels[-n:])
            return ".".join(labels[: -n - 1]), labels[-n - 1], suffix
    return ".".join(labels[:-2]), labels[-2], labels[-1]


def registered_domain(qname: str) -> str:
    sub, sld, suffix = split_domain(qname)
    return f"{sld}.{suffix}" if suffix else sld
