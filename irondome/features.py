"""Streaming feature extraction (PS stage: "feature extraction").

A FeaturePipeline consumes normalised flow records one at a time and, as event
time advances, emits *candidates*: an entity (victim, source host, host pair, DNS
domain, TLS flow ...) together with the feature vector its detector's model
scores. Processing is incremental with bounded memory - windows close on an
event-time watermark, per-key state is LRU-capped - so alerts are raised with
bounded latency rather than in an end-of-run report (PS constraint c).

Detector            PS class  Entity                         Window
------------------  --------  -----------------------------  -------------------------
ddos                a         destination IP                 2 s tumbling
c2_beacon           b         (src, dst, dst_port, proto)    last 64 connections
dga_domain          c         source host (per-domain items) 60 s sliding, 2 s hop
dns_tunnel          c         (source host, base domain)     60 s sliding, 2 s hop
encrypted_malware   d         individual TLS / QUIC flow     per flow
recon_scan          e         source IP                      30 s sliding, 2 s hop
exfiltration        f         (internal src, external dst)   60 s sliding, 5 s hop

The same code runs in the live sensor and in the model-training pipeline, so the
models are trained on exactly the features they are served (no train/serve skew).
"""

from __future__ import annotations

import heapq
import math
import time
from collections import OrderedDict, deque

from .lexical import domain_features, tld_rarity
from .netutil import (
    AddressClassifier, cv, entropy_from_counts, is_ip_literal, mad, mean, median,
    normalized_entropy, pstdev, split_domain, str_entropy,
)
from .schema import PROTO_NAMES, community_id

AMP_SERVICES = {
    17: "QOTD", 19: "CharGEN", 53: "DNS", 111: "Portmap", 123: "NTP", 137: "NetBIOS", 161: "SNMP",
    389: "CLDAP", 1900: "SSDP", 3283: "ARD", 3702: "WS-Discovery", 5353: "mDNS", 10001: "Ubiquiti",
    11211: "Memcached",
}
WEB_PORTS = frozenset({80, 443, 8080, 8443})
TLS_PORTS = frozenset({443, 8443, 993, 995, 465, 636, 853, 5061})
ADMIN_PORTS = frozenset({20, 21, 22, 23, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017})
TUNNEL_QTYPES = frozenset({"TXT", "NULL", "ANY", "KEY", "PRIVATE", "CNAME", "MX", "SRV"})
ADDR_QTYPES = frozenset({"A", "AAAA", "HTTPS", "SVCB"})
IGNORED_DNS_SUFFIXES = ("in-addr.arpa", "ip6.arpa", "local", "localhost", "lan", "home.arpa")

# ---------------------------------------------------------------------------
# Feature registry: ordered feature names per detector (the model input order)
# and a human-readable description of each (used by docs and the dashboard).
# ---------------------------------------------------------------------------
FEATURES: dict[str, list[str]] = {
    "ddos": [
        "flows_per_s", "pkts_per_s", "bytes_per_s", "bytes_per_pkt", "pkts_per_flow", "uniq_src",
        "src_entropy_bits", "src_entropy_norm", "flows_per_src", "top_src_share", "syn_only_ratio",
        "established_ratio", "tcp_ratio", "udp_ratio", "icmp_ratio", "amp_port_ratio",
        "unanswered_ratio", "fwd_bwd_byte_ratio_log", "mean_duration", "slow_conns", "slow_ratio",
        "dport_entropy_norm",
    ],
    "recon_scan": [
        "n_flows", "flows_per_s", "uniq_hosts", "uniq_ports", "uniq_pairs", "max_ports_per_host",
        "max_hosts_per_port", "failed_ratio", "no_payload_ratio", "mean_pkts_per_flow",
        "port_entropy_norm", "host_entropy_norm", "low_port_ratio", "port_contiguity", "tcp_ratio",
        "attempts_per_pair",
    ],
    "c2_beacon": [
        "n_conns", "span_s", "iat_mean", "iat_median", "iat_std", "iat_cv", "iat_mad_ratio",
        "iat_regularity", "bytes_fwd_mean", "bytes_fwd_cv", "bytes_bwd_mean", "bytes_bwd_cv",
        "dur_mean", "dst_prevalence", "dport_web", "proto_udp",
    ],
    "dga_domain": [
        "length", "entropy", "digit_ratio", "vowel_ratio", "consonant_max_run", "digit_max_run",
        "unique_char_ratio", "hex_ratio", "bigram_score", "dict_coverage", "hyphen_count",
        "tld_rarity", "n_labels", "sub_length",
    ],
    "dns_tunnel": [
        "queries", "query_rate", "unique_ratio", "mean_qname_len", "max_qname_len", "mean_sub_len",
        "max_label_len", "mean_label_len", "sub_entropy_mean", "sub_digit_ratio", "txt_null_ratio",
        "non_addr_ratio", "mean_req_bytes", "mean_resp_bytes", "nx_ratio",
    ],
    "encrypted_malware": [
        "duration", "pkts_total", "bytes_fwd", "bytes_bwd", "byte_ratio_log", "splt_fwd_mean",
        "splt_fwd_std", "splt_bwd_mean", "splt_bwd_std", "splt_iat_mean", "splt_iat_std",
        "splt_iat_max", "first_fwd_len", "first_bwd_len", "small_pkt_ratio", "tls13",
        "sni_present", "sni_is_ip", "sni_entropy", "sni_len", "sni_digit_ratio", "sni_tld_rarity",
        "alpn_present", "cipher_count", "ext_count", "ja3_prevalence", "dst_prevalence", "is_quic",
    ],
    "exfiltration": [
        "bytes_out_mb", "bytes_in_mb", "out_in_ratio_log", "pkts_out", "n_flows", "upload_rate_kbps",
        "mean_flow_mb", "active_s", "dst_prevalence", "host_out_zscore", "host_baseline_mb",
        "share_of_host_out", "dport_class",
    ],
}

FEATURE_DOCS: dict[str, str] = {
    # ddos
    "flows_per_s": "Flow records per second toward the entity in the window",
    "pkts_per_s": "Packets per second (both directions)",
    "bytes_per_s": "L3 bytes per second (both directions)",
    "bytes_per_pkt": "Mean bytes per packet sent toward the destination",
    "pkts_per_flow": "Mean packets per flow",
    "uniq_src": "Distinct source IPs",
    "src_entropy_bits": "Shannon entropy of the source-IP distribution (bits)",
    "src_entropy_norm": "Source-IP entropy normalised to [0,1] by log2(#sources)",
    "flows_per_src": "Mean flows per distinct source (~1 for spoofed floods)",
    "top_src_share": "Share of flows from the busiest source",
    "syn_only_ratio": "Share of TCP flows that sent SYN but never ACK (half-open)",
    "established_ratio": "Share of TCP flows with a completed, answered handshake",
    "tcp_ratio": "Share of TCP flows", "udp_ratio": "Share of UDP flows", "icmp_ratio": "Share of ICMP flows",
    "amp_port_ratio": "Share of UDP flows whose source port is an amplification service (DNS, NTP, SSDP, memcached...)",
    "unanswered_ratio": "Share of flows with no packet from the responder",
    "fwd_bwd_byte_ratio_log": "log10 of bytes toward / bytes from the destination",
    "mean_duration": "Mean flow duration (s)",
    "slow_conns": "Long-lived, very low-rate TCP connections (Slowloris signature)",
    "slow_ratio": "Share of flows that are long-lived and very low rate",
    "dport_entropy_norm": "Normalised entropy of targeted destination ports",
    # recon_scan
    "n_flows": "Flows (connections) in the window",
    "uniq_hosts": "Distinct destination hosts contacted",
    "uniq_ports": "Distinct destination ports contacted",
    "uniq_pairs": "Distinct (host, port) pairs probed",
    "max_ports_per_host": "Most ports probed on a single host (vertical fan-out)",
    "max_hosts_per_port": "Most hosts probed on a single port (horizontal fan-out)",
    "failed_ratio": "Share of attempts unanswered or reset",
    "no_payload_ratio": "Share of flows that carried headers only (no payload)",
    "mean_pkts_per_flow": "Mean packets per flow",
    "port_entropy_norm": "Normalised entropy of destination ports",
    "host_entropy_norm": "Normalised entropy of destination hosts",
    "low_port_ratio": "Share of distinct ports below 1024",
    "port_contiguity": "Share of probed ports adjacent to another probed port",
    "attempts_per_pair": "Connections per distinct (host, port) - scanners probe each once, retrying apps hammer the same few",
    # c2_beacon
    "n_conns": "Connections observed for the host pair",
    "span_s": "Time span covered by those connections (s)",
    "iat_mean": "Mean inter-arrival time between connections (s)",
    "iat_median": "Median inter-arrival time (s)",
    "iat_std": "Standard deviation of inter-arrival time (s)",
    "iat_cv": "Coefficient of variation of inter-arrival time (low = periodic)",
    "iat_mad_ratio": "Median absolute deviation / median of inter-arrival time (jitter)",
    "iat_regularity": "Share of inter-arrivals within +/-20% of the median",
    "bytes_fwd_mean": "Mean bytes sent per connection",
    "bytes_fwd_cv": "Variation of bytes sent per connection (low = scripted)",
    "bytes_bwd_mean": "Mean bytes received per connection",
    "bytes_bwd_cv": "Variation of bytes received per connection",
    "dur_mean": "Mean connection duration (s)",
    "dst_prevalence": "Distinct internal hosts that contacted this destination in the last hour",
    "dport_web": "1 if the destination port is a web/TLS port",
    "proto_udp": "1 if the connections are UDP",
    # dga_domain
    "length": "Length of the second-level label",
    "entropy": "Shannon entropy of the label's characters",
    "digit_ratio": "Share of digits", "vowel_ratio": "Share of vowels among letters",
    "consonant_max_run": "Longest run of consecutive consonants",
    "digit_max_run": "Longest run of consecutive digits",
    "unique_char_ratio": "Distinct characters / length",
    "hex_ratio": "Share of characters in [0-9a-f]",
    "bigram_score": "Mean log10 character-bigram probability under an English/benign-domain model",
    "dict_coverage": "Share of the label covered by dictionary words",
    "hyphen_count": "Number of hyphens",
    "tld_rarity": "0 popular TLD, 1 other, 2 frequently abused TLD",
    "n_labels": "Number of labels in the full query name",
    "sub_length": "Length of the subdomain part",
    # dns_tunnel
    "queries": "DNS queries to the base domain in 60 s",
    "query_rate": "Queries per second",
    "unique_ratio": "Distinct query names / queries (tunnels never repeat)",
    "mean_qname_len": "Mean full query-name length",
    "max_qname_len": "Longest query name",
    "mean_sub_len": "Mean length of the subdomain part (encoded payload)",
    "max_label_len": "Longest single label (63 max)",
    "mean_label_len": "Mean subdomain label length",
    "sub_entropy_mean": "Mean character entropy of the subdomain part",
    "sub_digit_ratio": "Share of digits in subdomains",
    "txt_null_ratio": "Share of TXT / NULL / CNAME / MX / SRV / ANY queries",
    "non_addr_ratio": "Share of queries that are not A / AAAA / HTTPS",
    "mean_req_bytes": "Mean request size (bytes)",
    "mean_resp_bytes": "Mean response size (bytes)",
    "nx_ratio": "Share of NXDOMAIN responses",
    # encrypted_malware
    "duration": "Flow duration (s)", "pkts_total": "Packets in both directions",
    "bytes_fwd": "Bytes sent by the client", "bytes_bwd": "Bytes sent by the server",
    "byte_ratio_log": "log10 of client bytes / server bytes",
    "splt_fwd_mean": "Mean client packet length over the first packets",
    "splt_fwd_std": "Std of client packet lengths", "splt_bwd_mean": "Mean server packet length",
    "splt_bwd_std": "Std of server packet lengths",
    "splt_iat_mean": "Mean inter-packet time over the first packets (ms)",
    "splt_iat_std": "Std of inter-packet time (ms)", "splt_iat_max": "Largest inter-packet gap (ms)",
    "first_fwd_len": "Size of the first client packet (ClientHello)",
    "first_bwd_len": "Size of the first server packet (ServerHello/certificate)",
    "small_pkt_ratio": "Share of packets under 100 bytes",
    "tls13": "1 if TLS 1.3 was negotiated/offered", "sni_present": "1 if the ClientHello carried SNI",
    "sni_is_ip": "1 if SNI is an IP literal", "sni_entropy": "Character entropy of the SNI",
    "sni_len": "SNI length", "sni_digit_ratio": "Share of digits in the SNI",
    "sni_tld_rarity": "TLD rarity of the SNI (0 popular .. 2 abused)",
    "alpn_present": "1 if ALPN was offered", "cipher_count": "Cipher suites offered",
    "ext_count": "TLS extensions offered",
    "ja3_prevalence": "Distinct internal hosts using this JA3 in the last hour",
    "dst_prevalence": "Distinct internal hosts that contacted this destination in the last hour (popular service vs rare C2)",
    "is_quic": "1 for QUIC (UDP/443)",
    # exfiltration
    "bytes_out_mb": "MB sent from the internal host to the destination in 60 s",
    "bytes_in_mb": "MB received from the destination in 60 s",
    "out_in_ratio_log": "log10 of outbound / inbound bytes",
    "pkts_out": "Packets sent", "upload_rate_kbps": "Upload rate (kbit/s)",
    "mean_flow_mb": "Mean MB sent per flow", "active_s": "Seconds with transfer activity",
    "host_out_zscore": "Host's outbound volume vs its own baseline (z-score)",
    "host_baseline_mb": "Host's usual outbound MB per minute (EWMA)",
    "share_of_host_out": "Share of the host's outbound bytes going to this destination",
    "dport_class": "0 web/TLS, 1 admin/file-transfer (SSH, FTP, SMB, DB), 2 other",
}


def _tuple(rec: dict) -> tuple:
    return (rec["src_ip"], rec["src_port"], rec["dst_ip"], rec["dst_port"], rec["proto"])


def _flow_ref(t: tuple) -> dict:
    src, sp, dst, dp, proto = t
    return {"src_ip": src, "src_port": sp, "dst_ip": dst, "dst_port": dp,
            "protocol": PROTO_NAMES.get(proto, str(proto))}


def _cid(t: tuple) -> str:
    return community_id(t[0], t[2], t[1], t[3], t[4])


def _candidate(detector, key, entity, features, rep, samples, first, last, wall, context, items=None):
    rep_t = rep or (samples[0] if samples else ("0.0.0.0", 0, "0.0.0.0", 0, 0))
    related = []
    for t in samples:
        cid = _cid(t)
        if cid not in related:
            related.append(cid)
        if len(related) >= 8:
            break
    cand = {
        "detector": detector,
        "key": key,
        "entity": entity,
        "features": {k: round(float(v), 6) for k, v in features.items()},
        "flow": _flow_ref(rep_t),
        "flow_id": _cid(rep_t),
        "related_flow_ids": related,
        "first_seen": first,
        "last_seen": last,
        "ingest_wall": wall,
        "context": context,
    }
    if items is not None:
        cand["items"] = items
    return cand


class _LRU(OrderedDict):
    """OrderedDict with a size cap; get_or_create() refreshes recency."""

    def __init__(self, cap: int):
        super().__init__()
        self.cap = cap

    def get_or_create(self, key, factory):
        v = self.get(key)
        if v is None:
            v = factory()
            self[key] = v
            if len(self) > self.cap:
                self.popitem(last=False)
        else:
            self.move_to_end(key)
        return v


# ---------------------------------------------------------------------------
# Shared context: prevalence and host baselines
# ---------------------------------------------------------------------------
class ContextStore:
    """Estate-wide context that makes single-entity features meaningful:
    how many internal hosts talk to a destination / use a JA3, and each host's
    normal outbound volume."""

    PREVALENCE_WINDOW = 3600.0
    MAX_MEMBERS = 256

    def __init__(self):
        self.dst_srcs = _LRU(50_000)
        self.ja3_srcs = _LRU(20_000)
        self.host_out = {}            # src -> [ewma_mean, ewma_var, n]
        self.seeded_dst: dict[str, int] = {}
        self.seeded_ja3: dict[str, int] = {}

    def _touch(self, table, key, member, ts):
        d = table.get_or_create(key, dict)
        if member in d or len(d) < self.MAX_MEMBERS:
            d[member] = ts

    def _count(self, table, key, now):
        d = table.get(key)
        if not d:
            return 0
        cutoff = now - self.PREVALENCE_WINDOW
        return sum(1 for t in d.values() if t >= cutoff)

    def touch_dst(self, dst, src, ts):
        self._touch(self.dst_srcs, dst, src, ts)

    def dst_prevalence(self, dst, now) -> int:
        return max(self._count(self.dst_srcs, dst, now), self.seeded_dst.get(dst, 0))

    def touch_ja3(self, ja3, src, ts):
        self._touch(self.ja3_srcs, ja3, src, ts)

    def ja3_prevalence(self, ja3, now) -> int:
        return max(self._count(self.ja3_srcs, ja3, now), self.seeded_ja3.get(ja3, 0))

    def host_baseline(self, src):
        m = self.host_out.get(src)
        if not m:
            return 0.0, 0.0, 0
        return m[0], math.sqrt(max(m[1], 0.0)), m[2]

    def update_host(self, src, value, alpha=0.1):
        m = self.host_out.get(src)
        if m is None:
            self.host_out[src] = [value, 0.0, 1]
            if len(self.host_out) > 100_000:
                self.host_out.pop(next(iter(self.host_out)))
            return
        diff = value - m[0]
        m[0] += alpha * diff
        m[1] = (1 - alpha) * (m[1] + alpha * diff * diff)
        m[2] += 1

    # Training hooks: synthesise estate context that a sample would have had live.
    def seed_dst_prevalence(self, dst, n):
        self.seeded_dst[dst] = int(n)

    def seed_ja3_prevalence(self, ja3, n):
        self.seeded_ja3[ja3] = int(n)

    def seed_host(self, src, mean_bytes, std_bytes, n):
        self.host_out[src] = [float(mean_bytes), float(std_bytes) ** 2, int(n)]


# ---------------------------------------------------------------------------
# (a) Volumetric / protocol DDoS - per destination, 2 s tumbling windows
# ---------------------------------------------------------------------------
class _DstAgg:
    __slots__ = ("n", "pkts_f", "bytes_f", "pkts_b", "bytes_b", "src", "dports", "tcp", "udp", "icmp",
                 "syn_only", "established", "amp", "amp_ports", "unanswered", "dur_sum", "slow",
                 "first", "last", "wall", "samples")

    def __init__(self):
        self.n = self.pkts_f = self.bytes_f = self.pkts_b = self.bytes_b = 0
        self.tcp = self.udp = self.icmp = self.syn_only = self.established = 0
        self.amp = self.unanswered = self.slow = 0
        self.dur_sum = 0.0
        self.src: dict = {}
        self.dports: dict = {}
        self.amp_ports: dict = {}
        self.first = math.inf
        self.last = 0.0
        self.wall = 0.0
        self.samples: list = []

    def add(self, r, wall):
        self.n += 1
        pf, pb = r["pkts_fwd"], r["pkts_bwd"]
        self.pkts_f += pf
        self.bytes_f += r["bytes_fwd"]
        self.pkts_b += pb
        self.bytes_b += r["bytes_bwd"]
        s = r["src_ip"]
        self.src[s] = self.src.get(s, 0) + 1
        dp = r["dst_port"]
        self.dports[dp] = self.dports.get(dp, 0) + 1
        proto = r["proto"]
        dur = r["te"] - r["ts"]
        self.dur_sum += dur
        if pb == 0:
            self.unanswered += 1
        if proto == 6:
            self.tcp += 1
            ff = r["flags_fwd"]
            if "S" in ff and "A" not in ff:
                self.syn_only += 1
            elif "A" in ff and pb > 0:
                self.established += 1
            if dur >= 5.0 and r["bytes_fwd"] / dur <= 200.0 and r["bytes_bwd"] <= 2000:
                self.slow += 1
        elif proto == 17:
            self.udp += 1
            sp = r["src_port"]
            if sp in AMP_SERVICES:
                self.amp += 1
                self.amp_ports[sp] = self.amp_ports.get(sp, 0) + 1
        elif proto in (1, 58):
            self.icmp += 1
        if r["ts"] < self.first:
            self.first = r["ts"]
        if r["te"] > self.last:
            self.last = r["te"]
        if wall > self.wall:
            self.wall = wall
        if len(self.samples) < 6:
            self.samples.append(_tuple(r))


class DDoSExtractor:
    name = "ddos"
    WINDOW = 2.0
    LATENESS = 0.5
    MIN_FLOWS = 30
    MIN_SLOW = 12
    MIN_PKTS = 3000      # few-flow, high-packet floods (ICMP, fixed-port UDP)

    def __init__(self, ctx: ContextStore, addr: AddressClassifier):
        self.windows: dict[int, dict[str, _DstAgg]] = {}
        self.next_close = -1

    def update(self, r, wall):
        widx = int(r["te"] // self.WINDOW)
        if widx < self.next_close:          # late record: fold into the oldest open window
            widx = self.next_close
        win = self.windows.get(widx)
        if win is None:
            win = self.windows[widx] = {}
        agg = win.get(r["dst_ip"])
        if agg is None:
            agg = win[r["dst_ip"]] = _DstAgg()
        agg.add(r, wall)

    def evaluate(self, wm, final=False):
        out = []
        for widx in sorted(self.windows):
            end = (widx + 1) * self.WINDOW
            if not final and end + self.LATENESS > wm:
                break
            win = self.windows.pop(widx)
            self.next_close = max(self.next_close, widx + 1)
            for dst, a in win.items():
                # A few-flow, high-packet window is a candidate only when it is a strongly
                # asymmetric *inbound* burst (reverse packets < 1/8 of forward) - the shape
                # of an ICMP / fixed-port UDP flood. A busy but answered download, upload or
                # video call is bidirectional and is left alone.
                high_pkt = (a.pkts_f + a.pkts_b >= self.MIN_PKTS and a.pkts_b * 8 <= a.pkts_f)
                if a.n >= self.MIN_FLOWS or a.slow >= self.MIN_SLOW or high_pkt:
                    out.append(self._candidate(dst, a, widx * self.WINDOW, end))
        return out

    def features(self, a: _DstAgg) -> dict:
        W = self.WINDOW
        n = a.n
        uniq = len(a.src)
        return {
            "flows_per_s": n / W,
            "pkts_per_s": (a.pkts_f + a.pkts_b) / W,
            "bytes_per_s": (a.bytes_f + a.bytes_b) / W,
            "bytes_per_pkt": a.bytes_f / max(a.pkts_f, 1),
            "pkts_per_flow": (a.pkts_f + a.pkts_b) / n,
            "uniq_src": uniq,
            "src_entropy_bits": entropy_from_counts(a.src.values()),
            "src_entropy_norm": normalized_entropy(a.src.values()),
            "flows_per_src": n / max(uniq, 1),
            "top_src_share": max(a.src.values()) / n,
            "syn_only_ratio": a.syn_only / max(a.tcp, 1),
            "established_ratio": a.established / max(a.tcp, 1),
            "tcp_ratio": a.tcp / n,
            "udp_ratio": a.udp / n,
            "icmp_ratio": a.icmp / n,
            "amp_port_ratio": a.amp / max(a.udp, 1),
            "unanswered_ratio": a.unanswered / n,
            "fwd_bwd_byte_ratio_log": math.log10((a.bytes_f + 1) / (a.bytes_b + 1)),
            "mean_duration": a.dur_sum / n,
            "slow_conns": a.slow,
            "slow_ratio": a.slow / n,
            "dport_entropy_norm": normalized_entropy(a.dports.values()),
        }

    def _candidate(self, dst, a, start, end):
        feats = self.features(a)
        top_src = heapq.nlargest(5, a.src.items(), key=lambda kv: kv[1])
        top_ports = heapq.nlargest(3, a.dports.items(), key=lambda kv: kv[1])
        busiest = top_src[0][0]
        rep = next((t for t in a.samples if t[0] == busiest), None)
        context = {
            "window": {"start": start, "end": end, "seconds": self.WINDOW},
            "flows": a.n, "packets": a.pkts_f + a.pkts_b, "bytes": a.bytes_f + a.bytes_b,
            "top_sources": [{"ip": ip, "flows": c} for ip, c in top_src],
            "top_dst_ports": [{"port": p, "flows": c} for p, c in top_ports],
            "amp_services": {AMP_SERVICES[p]: c for p, c in sorted(a.amp_ports.items(), key=lambda kv: -kv[1])[:3]},
        }
        return _candidate("ddos", f"ddos|{dst}", {"type": "destination", "ip": dst}, feats, rep, a.samples,
                          a.first, a.last, a.wall, context)


# ---------------------------------------------------------------------------
# (e) Reconnaissance / port scanning - per source, 30 s sliding window
# ---------------------------------------------------------------------------
class _SrcScan:
    __slots__ = ("events", "dirty", "last_eval", "wall")

    def __init__(self):
        self.events = deque(maxlen=5000)   # (te, dst, dport, failed, no_payload, pkts, proto)
        self.dirty = False
        self.last_eval = -math.inf
        self.wall = 0.0


class ScanExtractor:
    name = "recon_scan"
    SPAN = 30.0
    HOP = 2.0
    MIN_PAIRS = 12

    def __init__(self, ctx: ContextStore, addr: AddressClassifier):
        self.state = _LRU(20_000)
        self.next_eval = -math.inf

    def update(self, r, wall):
        if r["seg"] or r["proto"] not in (6, 17):
            return
        pf, pb = r["pkts_fwd"], r["pkts_bwd"]
        failed = pb == 0 or "R" in r["flags_bwd"] or ("R" in r["flags_fwd"] and r["bytes_fwd"] <= 66 * pf)
        no_payload = r["bytes_fwd"] <= 66 * pf and r["bytes_bwd"] <= 66 * max(pb, 1)
        st = self.state.get_or_create(r["src_ip"], _SrcScan)
        st.events.append((r["te"], r["dst_ip"], r["dst_port"], failed, no_payload, pf + pb, r["proto"]))
        st.dirty = True
        if wall > st.wall:
            st.wall = wall

    def evaluate(self, wm, final=False):
        if not final and wm < self.next_eval:
            return []
        self.next_eval = wm + self.HOP
        out = []
        cutoff = wm - self.SPAN
        for src in list(self.state.keys()):
            st = self.state[src]
            ev = st.events
            while ev and ev[0][0] < cutoff and not final:
                ev.popleft()
            if not ev:
                del self.state[src]
                continue
            if not st.dirty:
                continue
            st.dirty = False
            cand = self._evaluate_src(src, st)
            if cand:
                out.append(cand)
        return out

    def features(self, events) -> dict:
        n = len(events)
        hosts: dict = {}
        ports: dict = {}
        per_host: dict = {}
        per_port: dict = {}
        failed = no_payload = pkts = tcp = 0
        for te, dst, dport, f, npay, p, proto in events:
            hosts[dst] = hosts.get(dst, 0) + 1
            ports[dport] = ports.get(dport, 0) + 1
            s = per_host.get(dst)
            if s is None:
                s = per_host[dst] = set()
            s.add(dport)
            s = per_port.get(dport)
            if s is None:
                s = per_port[dport] = set()
            s.add(dst)
            failed += f
            no_payload += npay
            pkts += p
            tcp += proto == 6
        pairs = sum(len(v) for v in per_host.values())
        uports = sorted(ports)
        pset = set(uports)
        contiguous = sum(1 for p in uports if p + 1 in pset or p - 1 in pset)
        span = max(2.0, min(self.SPAN, events[-1][0] - events[0][0] + self.HOP))
        return {
            "n_flows": n,
            "flows_per_s": n / span,
            "uniq_hosts": len(hosts),
            "uniq_ports": len(ports),
            "uniq_pairs": pairs,
            "max_ports_per_host": max(len(v) for v in per_host.values()),
            "max_hosts_per_port": max(len(v) for v in per_port.values()),
            "failed_ratio": failed / n,
            "no_payload_ratio": no_payload / n,
            "mean_pkts_per_flow": pkts / n,
            "port_entropy_norm": normalized_entropy(ports.values()),
            "host_entropy_norm": normalized_entropy(hosts.values()),
            "low_port_ratio": sum(1 for p in uports if p < 1024) / len(uports),
            "port_contiguity": contiguous / len(uports),
            "tcp_ratio": tcp / n,
            "attempts_per_pair": n / max(pairs, 1),
        }

    def _evaluate_src(self, src, st):
        events = list(st.events)
        pairs = {(e[1], e[2]) for e in events}
        if len(pairs) < self.MIN_PAIRS:
            return None
        feats = self.features(events)
        top_hosts: dict = {}
        for e in events:
            top_hosts[e[1]] = top_hosts.get(e[1], 0) + 1
        ports = sorted({e[2] for e in events})
        last = events[-1]
        rep = (src, 0, last[1], last[2], last[6])
        samples = [(src, 0, e[1], e[2], e[6]) for e in events[-6:]]
        context = {
            "window": {"start": events[0][0], "end": last[0], "seconds": self.SPAN},
            "top_targets": [{"ip": ip, "flows": c} for ip, c in sorted(top_hosts.items(), key=lambda kv: -kv[1])[:5]],
            "ports_sample": ports[:24],
            "ports_total": len(ports),
        }
        return _candidate("recon_scan", f"scan|{src}", {"type": "source", "ip": src}, feats, rep, samples,
                          events[0][0], last[0], st.wall, context)


# ---------------------------------------------------------------------------
# (b) Botnet C2 beaconing - per (internal src, external dst, port, proto)
# ---------------------------------------------------------------------------
class _Pair:
    __slots__ = ("conns", "since_eval", "last_eval_ts", "pending", "wall", "last_sport")

    def __init__(self):
        self.conns = deque(maxlen=64)   # (ts, bytes_fwd, bytes_bwd, duration)
        self.since_eval = 0
        self.last_eval_ts = -math.inf
        self.pending = False
        self.wall = 0.0
        self.last_sport = 0


class BeaconExtractor:
    name = "c2_beacon"
    MIN_CONNS = 6
    REEVAL_CONNS = 2
    REEVAL_SECONDS = 120.0

    def __init__(self, ctx: ContextStore, addr: AddressClassifier):
        self.ctx = ctx
        self.addr = addr
        self.pairs = _LRU(50_000)
        self.pending: dict = {}

    def update(self, r, wall):
        if r["seg"] or r["proto"] not in (6, 17):
            return
        src, dst = r["src_ip"], r["dst_ip"]
        if not self.addr.is_internal(src) or self.addr.is_internal(dst):
            return
        if r["dst_port"] == 53:     # DNS has its own detectors
            return
        key = (src, dst, r["dst_port"], r["proto"])
        p = self.pairs.get_or_create(key, _Pair)
        p.conns.append((r["ts"], r["bytes_fwd"], r["bytes_bwd"], r["te"] - r["ts"]))
        p.since_eval += 1
        p.last_sport = r["src_port"]
        if wall > p.wall:
            p.wall = wall
        if len(p.conns) >= self.MIN_CONNS and (
            p.since_eval >= self.REEVAL_CONNS or r["ts"] - p.last_eval_ts >= self.REEVAL_SECONDS
        ):
            self.pending[key] = p

    def features(self, conns, dst, dport, proto, now) -> dict:
        ts = sorted(c[0] for c in conns)
        iats = [b - a for a, b in zip(ts, ts[1:])]
        med = median(iats)
        bf = [c[1] for c in conns]
        bb = [c[2] for c in conns]
        return {
            "n_conns": len(conns),
            "span_s": ts[-1] - ts[0],
            "iat_mean": mean(iats),
            "iat_median": med,
            "iat_std": pstdev(iats),
            "iat_cv": cv(iats),
            "iat_mad_ratio": mad(iats) / med if med > 0 else 1.0,
            "iat_regularity": (sum(1 for x in iats if abs(x - med) <= 0.2 * med) / len(iats)) if med > 0 else 0.0,
            "bytes_fwd_mean": mean(bf),
            "bytes_fwd_cv": cv(bf),
            "bytes_bwd_mean": mean(bb),
            "bytes_bwd_cv": cv(bb),
            "dur_mean": mean(c[3] for c in conns),
            "dst_prevalence": self.ctx.dst_prevalence(dst, now),
            "dport_web": 1.0 if dport in WEB_PORTS or dport in TLS_PORTS else 0.0,
            "proto_udp": 1.0 if proto == 17 else 0.0,
        }

    def evaluate(self, wm, final=False):
        out = []
        for key, p in list(self.pending.items()):
            src, dst, dport, proto = key
            conns = list(p.conns)
            p.since_eval = 0
            p.last_eval_ts = conns[-1][0]
            feats = self.features(conns, dst, dport, proto, conns[-1][0])
            rep = (src, p.last_sport, dst, dport, proto)
            context = {
                "window": {"start": conns[0][0], "end": conns[-1][0]},
                "interval_s": round(feats["iat_median"], 2),
                "jitter_pct": round(100 * feats["iat_mad_ratio"], 1),
                "connection_times": [round(c[0], 3) for c in conns[-12:]],
            }
            out.append(_candidate("c2_beacon", f"beacon|{src}|{dst}|{dport}|{proto}",
                                  {"type": "host_pair", "src_ip": src, "dst_ip": dst, "dst_port": dport},
                                  feats, rep, [rep], conns[0][0], conns[-1][0] + conns[-1][3], p.wall, context))
        self.pending.clear()
        return out


# ---------------------------------------------------------------------------
# (c) DGA - per source host; each queried base domain is scored by the model
# ---------------------------------------------------------------------------
def dga_prefilter(feat: dict, rcode: str) -> bool:
    """Recall-oriented gate deciding which domains are worth sending to the model."""
    return (
        rcode == "NXDOMAIN"
        or feat["bigram_score"] <= -1.7
        or (feat["entropy"] >= 3.3 and feat["dict_coverage"] < 0.5)
        or feat["digit_ratio"] >= 0.25
        or feat["consonant_max_run"] >= 6
        or (feat["length"] >= 15 and feat["dict_coverage"] < 0.5)
        or feat["tld_rarity"] >= 2
    )


class _DgaSrc:
    __slots__ = ("domains", "new", "wall", "last_tuple")

    def __init__(self):
        self.domains = OrderedDict()   # base domain -> (te, rcode, qname, suspicious)
        self.new = 0
        self.wall = 0.0
        self.last_tuple = None


class DgaExtractor:
    name = "dga_domain"
    SPAN = 60.0
    HOP = 2.0
    MIN_SUSPICIOUS = 4
    MAX_ITEMS = 32

    def __init__(self, ctx: ContextStore, addr: AddressClassifier):
        self.state = _LRU(20_000)
        self.lexcache = _LRU(50_000)
        self.next_eval = -math.inf

    def _lex(self, qname):
        f = self.lexcache.get(qname)
        if f is None:
            f = self.lexcache.get_or_create(qname, lambda: domain_features(qname))
        return f

    def update(self, r, wall):
        dns = r.get("dns")
        if not dns or r["seg"]:
            return
        qname = dns["qname"]
        if qname.endswith(IGNORED_DNS_SUFFIXES) or "." not in qname:
            return
        sub, sld, suffix = split_domain(qname)
        base = f"{sld}.{suffix}" if suffix else sld
        st = self.state.get_or_create(r["src_ip"], _DgaSrc)
        feat = self._lex(base)
        suspicious = dga_prefilter(feat, dns["rcode"])
        if base not in st.domains:
            st.new += suspicious
        else:
            st.domains.move_to_end(base)
        st.domains[base] = (r["te"], dns["rcode"], qname, suspicious)
        if len(st.domains) > 512:
            st.domains.popitem(last=False)
        st.last_tuple = _tuple(r)
        if wall > st.wall:
            st.wall = wall

    def evaluate(self, wm, final=False):
        if not final and wm < self.next_eval:
            return []
        self.next_eval = wm + self.HOP
        out = []
        cutoff = wm - self.SPAN
        for src in list(self.state.keys()):
            st = self.state[src]
            while st.domains and not final:
                base, v = next(iter(st.domains.items()))
                if v[0] >= cutoff:
                    break
                st.domains.popitem(last=False)
            if not st.domains:
                del self.state[src]
                continue
            if st.new <= 0:
                continue
            st.new = 0
            suspicious = [(b, v) for b, v in st.domains.items() if v[3]]
            if len(suspicious) < self.MIN_SUSPICIOUS:
                continue
            total = len(st.domains)
            nx = sum(1 for v in st.domains.values() if v[1] == "NXDOMAIN")
            items = [{"domain": b, "qname": v[2], "rcode": v[1], "features": self._lex(b)}
                     for b, v in suspicious[-self.MAX_ITEMS:]]
            first = min(v[0] for v in st.domains.values())
            last = max(v[0] for v in st.domains.values())
            agg = {"unique_domains": total, "suspicious_domains": len(suspicious),
                   "nx_ratio": nx / total, "nx_count": nx}
            rep = st.last_tuple
            context = {"window": {"start": first, "end": last, "seconds": self.SPAN}, **agg}
            out.append(_candidate("dga_domain", f"dga|{src}", {"type": "host", "ip": src}, agg, rep, [rep],
                                  first, last, st.wall, context, items=items))
        return out


# ---------------------------------------------------------------------------
# (c) DNS tunnelling - per (source host, base domain), 60 s sliding window
# ---------------------------------------------------------------------------
class _Tun:
    __slots__ = ("q", "dirty", "wall", "last_tuple")

    def __init__(self):
        self.q = deque(maxlen=4000)   # (te, qname, qtype, sub, req_bytes, resp_bytes, nx)
        self.dirty = False
        self.wall = 0.0
        self.last_tuple = None


class DnsTunnelExtractor:
    name = "dns_tunnel"
    SPAN = 60.0
    HOP = 2.0
    MIN_QUERIES = 8

    def __init__(self, ctx: ContextStore, addr: AddressClassifier):
        self.state = _LRU(50_000)
        self.next_eval = -math.inf

    def update(self, r, wall):
        dns = r.get("dns")
        if not dns or r["seg"]:
            return
        qname = dns["qname"]
        if qname.endswith(IGNORED_DNS_SUFFIXES) or "." not in qname:
            return
        sub, sld, suffix = split_domain(qname)
        base = f"{sld}.{suffix}" if suffix else sld
        st = self.state.get_or_create((r["src_ip"], base), _Tun)
        st.q.append((r["te"], qname, dns["qtype"], sub, r["bytes_fwd"], r["bytes_bwd"], dns["rcode"] == "NXDOMAIN"))
        st.dirty = True
        st.last_tuple = _tuple(r)
        if wall > st.wall:
            st.wall = wall

    def features(self, q) -> dict:
        n = len(q)
        qnames = [x[1] for x in q]
        subs = [x[3] for x in q]
        labels = [lab for s in subs for lab in s.split(".") if lab]
        sub_chars = "".join(subs)
        span = max(1.0, min(self.SPAN, q[-1][0] - q[0][0] + 1.0))
        return {
            "queries": n,
            "query_rate": n / span,
            "unique_ratio": len(set(qnames)) / n,
            "mean_qname_len": mean(len(x) for x in qnames),
            "max_qname_len": max(len(x) for x in qnames),
            "mean_sub_len": mean(len(s) for s in subs),
            "max_label_len": max((len(lab) for lab in labels), default=0),
            "mean_label_len": mean(len(lab) for lab in labels) if labels else 0.0,
            "sub_entropy_mean": mean(str_entropy(s) for s in subs),
            "sub_digit_ratio": (sum(c.isdigit() for c in sub_chars) / len(sub_chars)) if sub_chars else 0.0,
            "txt_null_ratio": sum(1 for x in q if x[2] in TUNNEL_QTYPES) / n,
            "non_addr_ratio": sum(1 for x in q if x[2] not in ADDR_QTYPES) / n,
            "mean_req_bytes": mean(x[4] for x in q),
            "mean_resp_bytes": mean(x[5] for x in q),
            "nx_ratio": sum(1 for x in q if x[6]) / n,
        }

    def evaluate(self, wm, final=False):
        if not final and wm < self.next_eval:
            return []
        self.next_eval = wm + self.HOP
        out = []
        cutoff = wm - self.SPAN
        for key in list(self.state.keys()):
            st = self.state[key]
            while st.q and st.q[0][0] < cutoff and not final:
                st.q.popleft()
            if not st.q:
                del self.state[key]
                continue
            if not st.dirty or len(st.q) < self.MIN_QUERIES:
                continue
            st.dirty = False
            src, base = key
            q = list(st.q)
            feats = self.features(q)
            qtypes: dict = {}
            for x in q:
                qtypes[x[2]] = qtypes.get(x[2], 0) + 1
            context = {
                "window": {"start": q[0][0], "end": q[-1][0], "seconds": self.SPAN},
                "base_domain": base,
                "sample_queries": [x[1] for x in q[-5:]],
                "qtypes": qtypes,
            }
            rep = st.last_tuple
            out.append(_candidate("dns_tunnel", f"tunnel|{src}|{base}",
                                  {"type": "host_domain", "ip": src, "domain": base}, feats, rep, [rep],
                                  q[0][0], q[-1][0], st.wall, context))
        return out


# ---------------------------------------------------------------------------
# (d) Malware in encrypted sessions - per TLS / QUIC flow, metadata only
# ---------------------------------------------------------------------------
class TlsExtractor:
    name = "encrypted_malware"
    MAX_PER_EVAL = 3000

    def __init__(self, ctx: ContextStore, addr: AddressClassifier):
        self.ctx = ctx
        self.addr = addr
        self.queue: list = []
        self.shed = 0

    @staticmethod
    def is_encrypted(r) -> bool:
        return "tls" in r or "quic" in r or (r["proto"] == 17 and r["dst_port"] == 443 and "splt" in r)

    def update(self, r, wall):
        # Outbound sessions from protected hosts only: the question is "is one of *our*
        # hosts talking to malware infrastructure", not what internet clients run.
        if r["seg"] or not self.is_encrypted(r) or not self.addr.is_internal(r["src_ip"]):
            return
        if len(self.queue) >= self.MAX_PER_EVAL:
            self.shed += 1
            return
        self.queue.append((r, wall))

    def features(self, r) -> dict:
        tls = r.get("tls") or {}
        splt = r.get("splt") or {"len": [], "iat": []}
        lens = splt.get("len") or []
        iats = splt.get("iat") or []
        fwd = [x for x in lens if x > 0]
        bwd = [-x for x in lens if x < 0]
        sni = tls.get("sni") or ""
        host = sni.rsplit(":", 1)[0]
        sub, sld, suffix = split_domain(host) if host and not is_ip_literal(host) else ("", "", "")
        pkts = r["pkts_fwd"] + r["pkts_bwd"]
        ja3 = tls.get("ja3")
        return {
            "duration": r["te"] - r["ts"],
            "pkts_total": pkts,
            "bytes_fwd": r["bytes_fwd"],
            "bytes_bwd": r["bytes_bwd"],
            "byte_ratio_log": math.log10((r["bytes_fwd"] + 1) / (r["bytes_bwd"] + 1)),
            "splt_fwd_mean": mean(fwd), "splt_fwd_std": pstdev(fwd),
            "splt_bwd_mean": mean(bwd), "splt_bwd_std": pstdev(bwd),
            "splt_iat_mean": mean(iats), "splt_iat_std": pstdev(iats),
            "splt_iat_max": max(iats) if iats else 0.0,
            "first_fwd_len": fwd[0] if fwd else 0,
            "first_bwd_len": bwd[0] if bwd else 0,
            "small_pkt_ratio": (sum(1 for x in lens if abs(x) < 100) / len(lens)) if lens else 0.0,
            "tls13": 1.0 if tls.get("version") == "TLS1.3" or "quic" in r else 0.0,
            "sni_present": 1.0 if host else 0.0,
            "sni_is_ip": 1.0 if host and is_ip_literal(host) else 0.0,
            "sni_entropy": str_entropy(sld) if sld else 0.0,
            "sni_len": float(len(host)),
            "sni_digit_ratio": (sum(c.isdigit() for c in host) / len(host)) if host else 0.0,
            "sni_tld_rarity": float(tld_rarity(suffix)) if suffix else 1.0,
            "alpn_present": 1.0 if tls.get("alpn") else 0.0,
            "cipher_count": float(tls.get("ciphers", 0) or 0),
            "ext_count": float(tls.get("exts", 0) or 0),
            "ja3_prevalence": float(self.ctx.ja3_prevalence(ja3, r["ts"])) if ja3 else 0.0,
            "dst_prevalence": float(self.ctx.dst_prevalence(r["dst_ip"], r["ts"])),
            "is_quic": 1.0 if "quic" in r or r["proto"] == 17 else 0.0,
        }

    def evaluate(self, wm, final=False):
        out = []
        for r, wall in self.queue:
            t = _tuple(r)
            tls = r.get("tls") or {}
            context = {k: tls.get(k) for k in ("version", "sni", "alpn", "ja3", "ja3s", "ja4") if tls.get(k)}
            if "quic" in r:
                context["quic_version"] = r["quic"].get("version")
            out.append(_candidate("encrypted_malware", f"tls|{_cid(t)}",
                                  {"type": "flow", "src_ip": r["src_ip"], "dst_ip": r["dst_ip"], "dst_port": r["dst_port"]},
                                  self.features(r), t, [t], r["ts"], r["te"], wall, context))
        self.queue = []
        return out


# ---------------------------------------------------------------------------
# (f) Data exfiltration - per (internal src, external dst), 60 s sliding window
# ---------------------------------------------------------------------------
class _Exf:
    __slots__ = ("ev", "dirty", "wall", "last_sport")

    def __init__(self):
        self.ev = deque(maxlen=5000)   # (te, bytes_fwd, bytes_bwd, pkts_fwd, duration, dport, proto)
        self.dirty = False
        self.wall = 0.0
        self.last_sport = 0


class ExfilExtractor:
    name = "exfiltration"
    SPAN = 60.0
    HOP = 5.0
    MIN_BYTES_OUT = 1_000_000
    MIN_RATIO = 2.0
    BASELINE_EVERY = 60.0

    def __init__(self, ctx: ContextStore, addr: AddressClassifier):
        self.ctx = ctx
        self.addr = addr
        self.state = _LRU(50_000)
        self.host_ev: dict = {}        # src -> deque of (te, bytes_fwd)
        self.next_eval = -math.inf
        self.next_baseline = -math.inf

    def update(self, r, wall):
        src, dst = r["src_ip"], r["dst_ip"]
        if not self.addr.is_internal(src) or self.addr.is_internal(dst):
            return
        st = self.state.get_or_create((src, dst), _Exf)
        st.ev.append((r["te"], r["bytes_fwd"], r["bytes_bwd"], r["pkts_fwd"], r["te"] - r["ts"], r["dst_port"], r["proto"]))
        st.dirty = True
        st.last_sport = r["src_port"]
        if wall > st.wall:
            st.wall = wall
        h = self.host_ev.get(src)
        if h is None:
            h = self.host_ev[src] = deque(maxlen=20000)
            if len(self.host_ev) > 50_000:
                self.host_ev.pop(next(iter(self.host_ev)))
        h.append((r["te"], r["bytes_fwd"]))

    def _host_total(self, src, cutoff):
        h = self.host_ev.get(src)
        if not h:
            return 0
        while h and h[0][0] < cutoff:
            h.popleft()
        return sum(b for _, b in h)

    def features(self, ev, dst, host_total, prevalence, baseline) -> dict:
        out_b = sum(e[1] for e in ev)
        in_b = sum(e[2] for e in ev)
        active = max(1.0, min(self.SPAN, sum(e[4] for e in ev)))
        span = max(1.0, min(self.SPAN, ev[-1][0] - ev[0][0] + ev[0][4]))
        dport = ev[-1][5]
        mean_b, std_b, n_b = baseline
        z = (host_total - mean_b) / max(std_b, 500_000.0) if n_b >= 5 else 0.0
        return {
            "bytes_out_mb": out_b / 1e6,
            "bytes_in_mb": in_b / 1e6,
            "out_in_ratio_log": math.log10((out_b + 1) / (in_b + 1)),
            "pkts_out": sum(e[3] for e in ev),
            "n_flows": len(ev),
            "upload_rate_kbps": out_b * 8 / 1000 / span,
            "mean_flow_mb": out_b / 1e6 / len(ev),
            "active_s": active,
            "dst_prevalence": prevalence,
            "host_out_zscore": max(-10.0, min(50.0, z)),
            "host_baseline_mb": mean_b / 1e6,
            "share_of_host_out": out_b / host_total if host_total > 0 else 1.0,
            "dport_class": 0.0 if dport in WEB_PORTS or dport in TLS_PORTS else (1.0 if dport in ADMIN_PORTS else 2.0),
        }

    def evaluate(self, wm, final=False):
        if not final and wm < self.next_eval:
            return []
        self.next_eval = wm + self.HOP
        cutoff = wm - self.SPAN
        out = []
        for key in list(self.state.keys()):
            st = self.state[key]
            while st.ev and st.ev[0][0] < cutoff and not final:
                st.ev.popleft()
            if not st.ev:
                del self.state[key]
                continue
            if not st.dirty:
                continue
            st.dirty = False
            ev = list(st.ev)
            out_b = sum(e[1] for e in ev)
            in_b = sum(e[2] for e in ev)
            if out_b < self.MIN_BYTES_OUT or out_b < self.MIN_RATIO * in_b:
                continue
            src, dst = key
            host_total = self._host_total(src, cutoff) if not final else sum(b for _, b in self.host_ev.get(src, ()))
            feats = self.features(ev, dst, max(host_total, out_b), self.ctx.dst_prevalence(dst, wm),
                                  self.ctx.host_baseline(src))
            rep = (src, st.last_sport, dst, ev[-1][5], ev[-1][6])
            context = {
                "window": {"start": ev[0][0] - ev[0][4], "end": ev[-1][0], "seconds": self.SPAN},
                "bytes_out": out_b, "bytes_in": in_b,
                "ratio": round((out_b + 1) / (in_b + 1), 1),
            }
            out.append(_candidate("exfiltration", f"exfil|{src}|{dst}",
                                  {"type": "host_pair", "src_ip": src, "dst_ip": dst}, feats, rep, [rep],
                                  ev[0][0] - ev[0][4], ev[-1][0], st.wall, context))
        if not final and wm >= self.next_baseline:
            self.next_baseline = wm + self.BASELINE_EVERY
            for src in list(self.host_ev.keys()):
                total = self._host_total(src, cutoff)
                mean_b, std_b, n_b = self.ctx.host_baseline(src)
                if n_b >= 5 and (total - mean_b) / max(std_b, 500_000.0) > 3.0:
                    continue          # do not learn the baseline from an anomalous minute
                self.ctx.update_host(src, total)
        return out


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
EXTRACTORS = [DDoSExtractor, ScanExtractor, BeaconExtractor, DgaExtractor, DnsTunnelExtractor,
              TlsExtractor, ExfilExtractor]


class FeaturePipeline:
    """Routes flow records to every extractor and advances event time.

    mode="live":   the watermark also advances with the wall clock, so windows close
                   on time even when traffic pauses.
    mode="replay": pure event time taken from the records (captures replay with their
                   original timing, at any speed).
    """

    LIVE_LAG = 1.0
    LATE_HORIZON = 30.0   # live mode: records older than this only update estate context

    def __init__(self, pipeline_id: str = "live", mode: str = "live", internal_cidrs: str | None = None,
                 detectors: list[str] | None = None):
        self.id = pipeline_id
        self.mode = mode
        self.addr = AddressClassifier(internal_cidrs)
        self.ctx = ContextStore()
        self.extractors = [cls(self.ctx, self.addr) for cls in EXTRACTORS
                           if detectors is None or cls.name in detectors]
        self.watermark = 0.0
        self.first_event = None       # earliest event time observed: how much estate history we have
        self.records = 0
        self.bytes = 0
        self.packets = 0
        self.late = 0
        self.candidates: dict[str, int] = {cls.name: 0 for cls in EXTRACTORS}

    def ingest(self, rec: dict, wall: float | None = None):
        wall = wall if wall is not None else time.time()
        te = rec["te"]
        if self.mode == "live" and te > wall + 5.0:     # clock-skewed exporter: clamp
            rec["te"] = te = wall
            rec["ts"] = min(rec["ts"], te)
        if te > self.watermark:
            self.watermark = te
        if self.first_event is None or rec["ts"] < self.first_event:
            self.first_event = rec["ts"]
        self.records += 1
        self.bytes += rec["bytes_fwd"] + rec["bytes_bwd"]
        self.packets += rec["pkts_fwd"] + rec["pkts_bwd"]
        # estate context shared by several detectors
        src = rec["src_ip"]
        if self.addr.is_internal(src) and not self.addr.is_internal(rec["dst_ip"]):
            self.ctx.touch_dst(rec["dst_ip"], src, rec["ts"])
        tls = rec.get("tls")
        if tls and tls.get("ja3"):
            self.ctx.touch_ja3(tls["ja3"], src, rec["ts"])
        # Late-data policy: a record older than the late horizon (exporter backlog, a
        # warm-start history burst) can no longer belong to an open window - folding it
        # into the current one would fake a spike. It still informs estate context above.
        if self.mode == "live" and te < wall - self.LATE_HORIZON:
            self.late += 1
            return
        for ex in self.extractors:
            ex.update(rec, wall)

    def current_watermark(self, now_wall: float | None = None) -> float:
        wm = self.watermark
        if self.mode == "live":
            wm = max(wm, (now_wall if now_wall is not None else time.time()) - self.LIVE_LAG)
        return wm

    def context_age(self, wm: float | None = None) -> float:
        """Seconds of event-time history behind the estate context (prevalence, baselines)."""
        if self.first_event is None:
            return 0.0
        return max(0.0, (wm if wm is not None else self.watermark) - self.first_event)

    def evaluate(self, now_wall: float | None = None, final: bool = False) -> list[dict]:
        wm = self.current_watermark(now_wall)
        age = self.context_age(min(wm, self.watermark) if self.watermark else wm)
        out = []
        for ex in self.extractors:
            cands = ex.evaluate(wm, final)
            self.candidates[ex.name] += len(cands)
            for c in cands:
                c["context_age_s"] = round(age, 1)
                if self.mode != "live":
                    c.pop("ingest_wall", None)   # offline replay runs on event time: latency is undefined
            out.extend(cands)
        return out

    def flush(self) -> list[dict]:
        return self.evaluate(final=True)

    def shed(self) -> int:
        return sum(getattr(ex, "shed", 0) for ex in self.extractors)
