"""Synthetic lab traffic - the "simulated IP data" of the problem statement.

Patterns here stand in for the lab tools the PS lists as data sources:

    benign load (iperf3 / Ostinato / TRex)     WebServer, Browsing, PeriodicService,
                                               CloudBackup, VideoCall, P2P, AvLookups ...
    hping3 SYN / UDP / ICMP floods             SynFlood, UdpIcmpFlood
    hping3 --rand-source                       SpoofedFlood
    reflection / amplification                 UdpAmplification
    Slowloris                                  Slowloris
    nmap                                       PortScan
    dnscat2 / iodine                           DnsTunnel
    DGArchive-style DGA families               DgaBurst / dga_domain()
    sandboxed C2 emulator                      Beacon, MalwareTls
    data theft                                 Exfiltration

Every pattern emits *connections*; the Exporter turns them into flow records the way
a NetFlow/IPFIX exporter does (long flows are split by an active timeout). Packet
and byte counts follow a fixed on-the-wire layout so the PCAP synthesiser
(pcap.py) can realise them packet-for-packet.
"""

from __future__ import annotations

import hashlib
import heapq
import math
import random
import string

from . import dnsmsg
from . import tls as tlsmod
from .lexical import BENIGN_DOMAINS, WORDS
from .netutil import registered_domain

HDR_TCP = 40          # IPv4 + TCP header, no options
HDR_UDP = 28
HDR_ICMP = 28
MSS = 1448
ACTIVE_TIMEOUT = 10.0  # seconds; long flows are exported in 10 s segments


# ---------------------------------------------------------------------------
# Addressing
# ---------------------------------------------------------------------------
def eph_port(rng: random.Random) -> int:
    return rng.randint(32768, 60999)


def public_ip(rng: random.Random) -> str:
    """A random routable-looking IPv4 address (never RFC1918 / loopback / multicast)."""
    while True:
        a = rng.randint(1, 223)
        b = rng.randint(0, 255)
        if a in (10, 127) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) \
                or (a == 169 and b == 254) or (a == 100 and 64 <= b <= 127):
            continue
        return f"{a}.{b}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def stable_ip(name: str) -> str:
    """Deterministic public IP for a service name (so prevalence builds up naturally)."""
    return public_ip(random.Random(hashlib.sha1(name.encode()).digest()))


def poisson(rng: random.Random, lam: float) -> int:
    if lam <= 0:
        return 0
    if lam > 30:
        return max(0, int(round(rng.gauss(lam, math.sqrt(lam)))))
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def arrivals(rng: random.Random, rate: float, a: float, b: float) -> list[float]:
    if b <= a or rate <= 0:
        return []
    return sorted(rng.uniform(a, b) for _ in range(poisson(rng, rate * (b - a))))


def lognormal_bytes(rng: random.Random, median: float, sigma: float = 1.0, lo: int = 0, hi: int = 10**9) -> int:
    return int(min(hi, max(lo, rng.lognormvariate(math.log(max(median, 1.0)), sigma))))


# ---------------------------------------------------------------------------
# Flow records
# ---------------------------------------------------------------------------
def make_record(ts, te, src, sp, dst, dp, proto, pf, bf, pb, bb, ff="", fb="", seg=0, **extra) -> dict:
    rec = {"ts": ts, "te": te, "src_ip": src, "src_port": sp, "dst_ip": dst, "dst_port": dp, "proto": proto,
           "pkts_fwd": pf, "bytes_fwd": bf, "pkts_bwd": pb, "bytes_bwd": bb, "flags_fwd": ff, "flags_bwd": fb,
           "seg": seg}
    rec.update(extra)
    return rec


def tcp_conn(rng, ts, dur, src, dst, dport, *, sport=None, splt=None, up=0, down=0, close=True, **extra) -> dict:
    """A completed TCP connection. `splt` is the list of (signed IP length, iat ms) for the
    leading data packets; `up`/`down` are further payload bytes sent at MSS size.

    Layout: fwd = SYN, ACK, data..., delayed ACKs (1 per 2 server data pkts), FIN
            bwd = SYN-ACK, data..., delayed ACKs (1 per 2 client data pkts), FIN
    """
    f_data = [x for x, _ in splt if x > 0] if splt else []
    b_data = [-x for x, _ in splt if x < 0] if splt else []
    nf_x = math.ceil(up / MSS) if up > 0 else 0
    nb_x = math.ceil(down / MSS) if down > 0 else 0
    n_f, n_b = len(f_data) + nf_x, len(b_data) + nb_x
    acks_f, acks_b = n_b // 2, n_f // 2
    ctrl_f, ctrl_b = 2 + close, 1 + close
    pf = ctrl_f + n_f + acks_f
    pb = ctrl_b + n_b + acks_b
    bf = HDR_TCP * (ctrl_f + acks_f + nf_x) + sum(f_data) + up
    bb = HDR_TCP * (ctrl_b + acks_b + nb_x) + sum(b_data) + down
    ff = "SA" + ("P" if n_f else "") + ("F" if close else "")
    fb = "SA" + ("P" if n_b else "") + ("F" if close else "")
    rec = make_record(ts, ts + dur, src, sport or eph_port(rng), dst, dport, 6, pf, bf, pb, bb, ff, fb, **extra)
    if splt:
        rec["splt"] = {"len": [x for x, _ in splt[:20]], "iat": [round(i, 3) for _, i in splt[:20]]}
    return rec


def dns_conn(rng, ts, src, resolver, qname, qtype="A", rcode="NOERROR", answers=None, resp_extra=0, sport=None) -> dict:
    if answers is None:
        answers = rng.randint(1, 4) if qtype in ("A", "AAAA") else 1
    if rcode != "NOERROR":
        answers = 0
    q_len = dnsmsg.query_len(qname)
    r_len = dnsmsg.min_response_len(qname, qtype, rcode, answers)
    if resp_extra > 0:
        r_len += max(15, resp_extra)        # carried as EDNS padding when synthesised
    rtt = rng.uniform(0.002, 0.06)
    return make_record(ts, ts + rtt, src, sport or eph_port(rng), resolver, 53, 17, 1, HDR_UDP + q_len,
                       1, HDR_UDP + r_len,
                       dns={"qname": qname, "qtype": qtype, "rcode": rcode, "answers": answers})


def segment(conn: dict, timeout: float = ACTIVE_TIMEOUT) -> list[dict]:
    """Split a long connection into active-timeout segments (seg 0, 1, 2 ...).

    Packets and payload bytes are allocated to segments in proportion to time using
    cumulative rounding, so segment totals always add up exactly to the connection."""
    ts, te = conn["ts"], conn["te"]
    dur = te - ts
    if dur <= timeout:
        return [conn]
    n = math.ceil(dur / timeout)
    hdr = HDR_TCP if conn["proto"] == 6 else HDR_UDP
    totals = {}
    for d in ("fwd", "bwd"):
        pk = conn[f"pkts_{d}"]
        totals[d] = (pk, max(0, conn[f"bytes_{d}"] - hdr * pk))
    prev = {"fwd": (0, 0), "bwd": (0, 0)}
    carry = {"fwd": 0, "bwd": 0}
    out = []
    keep = lambda f, allow: "".join(c for c in f if c in allow)  # noqa: E731
    for i in range(n):
        s_ = ts + i * timeout
        e_ = min(te, s_ + timeout)
        last = i == n - 1
        frac = 1.0 if last else (e_ - ts) / dur
        rec = dict(conn) if i == 0 else {k: v for k, v in conn.items() if k not in ("dns", "tls", "splt", "quic")}
        rec["ts"], rec["te"], rec["seg"] = s_, e_, i
        for d in ("fwd", "bwd"):
            tot_p, tot_pay = totals[d]
            cum_p, cum_pay = round(tot_p * frac), round(tot_pay * frac)
            p = cum_p - prev[d][0]
            pay = cum_pay - prev[d][1] + carry[d]
            prev[d] = (cum_p, cum_pay)
            if p == 0 and not last:
                carry[d], pay = pay, 0
            else:
                carry[d] = 0
            rec[f"pkts_{d}"], rec[f"bytes_{d}"] = p, hdr * p + pay
        if conn["proto"] == 6:
            ff, fb = conn["flags_fwd"], conn["flags_bwd"]
            if i == 0:
                rec["flags_fwd"], rec["flags_bwd"] = keep(ff, "SAPU"), keep(fb, "SAPU")
            else:
                rec["flags_fwd"] = ("A" if rec["pkts_fwd"] else "") + ("P" if rec["bytes_fwd"] > hdr * rec["pkts_fwd"] else "") + (keep(ff, "FR") if last else "")
                rec["flags_bwd"] = ("A" if rec["pkts_bwd"] else "") + ("P" if rec["bytes_bwd"] > hdr * rec["pkts_bwd"] else "") + (keep(fb, "FR") if last else "")
        if rec["pkts_fwd"] or rec["pkts_bwd"]:
            out.append(rec)
    return out


class Exporter:
    """Buffers connections and releases flow records in export-time order."""

    def __init__(self, active_timeout: float = ACTIVE_TIMEOUT):
        self.timeout = active_timeout
        self.heap: list = []
        self.seq = 0

    def add(self, conn: dict):
        for rec in segment(conn, self.timeout):
            self.seq += 1
            heapq.heappush(self.heap, (rec["te"], self.seq, rec))

    def drain(self, until: float) -> list[dict]:
        out = []
        while self.heap and self.heap[0][0] < until:
            out.append(heapq.heappop(self.heap)[2])
        return out

    def drain_all(self) -> list[dict]:
        return self.drain(math.inf)


# ---------------------------------------------------------------------------
# TLS client profiles (ClientHello field lists) - benign clients and lab C2 families
# ---------------------------------------------------------------------------
_SIG_MODERN = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
_SIG_OPENSSL = [0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080A, 0x080B, 0x0804, 0x0805, 0x0806,
                0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602]
_OPENSSL3_CIPHERS = [4866, 4867, 4865, 49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192,
                     107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 61, 60, 53, 47, 255]

TLS_PROFILES: dict[str, dict] = {
    "chrome": {"version": 0x0303,
               "ciphers": [0x0A0A, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
               "extensions": [0x1A1A, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
               "groups": [0x2A2A, 29, 23, 24], "point_formats": [0], "sig_algs": _SIG_MODERN,
               "alpn": ["h2", "http/1.1"], "versions": [0x3A3A, 0x0304, 0x0303]},
    "firefox": {"version": 0x0303,
                "ciphers": [4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49171, 49172, 156, 157, 47, 53],
                "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 21],
                "groups": [29, 23, 24, 25, 256, 257], "point_formats": [0],
                "sig_algs": [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201],
                "alpn": ["h2", "http/1.1"], "versions": [0x0304, 0x0303]},
    "safari": {"version": 0x0303,
               "ciphers": [0x2A2A, 4865, 4866, 4867, 49196, 49195, 52393, 49200, 49199, 52392, 49162, 49161, 49172, 49171, 157, 156, 53, 47, 49160, 49170, 10],
               "extensions": [0x3A3A, 0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 21],
               "groups": [0x4A4A, 29, 23, 24, 25], "point_formats": [0], "sig_algs": _SIG_MODERN + [0x0203, 0x0201],
               "alpn": ["h2", "http/1.1"], "versions": [0x5A5A, 0x0304, 0x0303, 0x0302, 0x0301]},
    "schannel": {"version": 0x0303,
                 "ciphers": [49196, 49195, 49200, 49199, 159, 158, 49188, 49187, 49192, 49191, 49162, 49161, 49172, 49171, 157, 156, 61, 60, 53, 47, 10],
                 "extensions": [0, 5, 10, 11, 13, 35, 16, 23, 65281],
                 "groups": [29, 23, 24], "point_formats": [0], "sig_algs": _SIG_MODERN + [0x0201],
                 "alpn": ["h2", "http/1.1"], "versions": []},
    "openssl3": {"version": 0x0303, "ciphers": _OPENSSL3_CIPHERS,
                 "extensions": [0, 11, 10, 35, 16, 22, 23, 13, 43, 45, 51],
                 "groups": [29, 23, 30, 25, 24], "point_formats": [0, 1, 2], "sig_algs": _SIG_OPENSSL,
                 "alpn": ["h2", "http/1.1"], "versions": [0x0304, 0x0303]},
    "python": {"version": 0x0303, "ciphers": _OPENSSL3_CIPHERS,
               "extensions": [0, 11, 10, 35, 16, 22, 23, 13, 43, 45, 51],
               "groups": [29, 23, 30, 25, 24], "point_formats": [0, 1, 2], "sig_algs": _SIG_OPENSSL,
               "alpn": ["http/1.1"], "versions": [0x0304, 0x0303]},
    "go": {"version": 0x0303,
           "ciphers": [49195, 49199, 49196, 49200, 52393, 52392, 49161, 49171, 49162, 49172, 156, 157, 47, 53, 49170, 10, 4865, 4866, 4867],
           "extensions": [0, 5, 10, 11, 13, 65281, 18, 43, 51, 16, 23],
           "groups": [29, 23, 24, 25], "point_formats": [0], "sig_algs": _SIG_MODERN + [0x0203, 0x0201],
           "alpn": ["h2", "http/1.1"], "versions": [0x0304, 0x0303]},
    "okhttp": {"version": 0x0303,
               "ciphers": [4865, 4866, 4867, 49195, 49196, 52393, 49199, 49200, 52392, 49171, 49172, 156, 157, 47, 53],
               "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43, 21],
               "groups": [29, 23, 24], "point_formats": [0], "sig_algs": _SIG_MODERN + [0x0201],
               "alpn": ["h2", "http/1.1"], "versions": [0x0304, 0x0303]},
    # ---- lab C2 families (synthetic, modelled on common implant traits) ----
    "mal_legacy_ssl": {"version": 0x0303,   # old statically linked OpenSSL: heartbeat ext, many legacy suites
                       "ciphers": [49200, 49196, 49192, 49188, 49172, 49162, 163, 159, 107, 106, 57, 56, 136, 135,
                                   49202, 49198, 49194, 49190, 49167, 49157, 157, 61, 53, 132, 49199, 49195, 49191,
                                   49187, 49171, 49161, 162, 158, 103, 64, 51, 50, 154, 153, 69, 68, 49201, 49197,
                                   49193, 49189, 49166, 49156, 156, 60, 47, 150, 65, 7, 49169, 49159, 49164, 49154,
                                   5, 4, 255],
                       "extensions": [0, 11, 10, 35, 13, 15], "groups": [23, 25, 28, 27, 24, 26, 22, 14, 13, 11, 12, 9, 10],
                       "point_formats": [0, 1, 2], "sig_algs": [0x0601, 0x0602, 0x0603, 0x0501, 0x0502, 0x0503, 0x0401, 0x0402, 0x0403, 0x0301, 0x0302, 0x0303, 0x0201, 0x0202, 0x0203],
                       "alpn": [], "versions": []},
    "mal_minimal": {"version": 0x0303,      # hand-rolled client: few suites, few extensions
                    "ciphers": [49199, 49195, 49200, 49196, 47, 53],
                    "extensions": [0, 10, 11, 13, 23], "groups": [23, 24], "point_formats": [0],
                    "sig_algs": [0x0401, 0x0501, 0x0403], "alpn": [], "versions": []},
    "mal_go_implant": {"version": 0x0303,   # Go implant: Go stack without ALPN
                       "ciphers": [49195, 49199, 49196, 49200, 52393, 52392, 49161, 49171, 49162, 49172, 156, 157, 47, 53, 49170, 10, 4865, 4866, 4867],
                       "extensions": [0, 5, 10, 11, 13, 65281, 18, 43, 51],
                       "groups": [29, 23, 24, 25], "point_formats": [0], "sig_algs": _SIG_MODERN + [0x0203, 0x0201],
                       "alpn": [], "versions": [0x0304, 0x0303]},
    "mal_py_implant": {"version": 0x0303, "ciphers": _OPENSSL3_CIPHERS,
                       "extensions": [0, 11, 10, 35, 22, 23, 13, 43, 45, 51],
                       "groups": [29, 23, 30, 25, 24], "point_formats": [0, 1, 2], "sig_algs": _SIG_OPENSSL,
                       "alpn": [], "versions": [0x0304, 0x0303]},
}

BENIGN_TLS_CLIENTS = [("chrome", 0.42), ("firefox", 0.12), ("safari", 0.05), ("schannel", 0.16),
                      ("openssl3", 0.06), ("python", 0.05), ("go", 0.07), ("okhttp", 0.07)]
MALWARE_TLS_CLIENTS = ["mal_legacy_ssl", "mal_minimal", "mal_go_implant", "mal_py_implant", "chrome", "schannel"]
WATCHLIST_PROFILES = ["mal_legacy_ssl", "mal_minimal"]   # "known" lab families in threat intel

_fp_cache: dict = {}
_ch_len_cache: dict = {}


def weighted_choice(rng, pairs):
    total = sum(w for _, w in pairs)
    x = rng.uniform(0, total)
    for item, w in pairs:
        x -= w
        if x <= 0:
            return item
    return pairs[-1][0]


def tls_meta(profile_name: str, sni: str | None, quic: bool = False) -> dict:
    key = (profile_name, bool(sni), quic)
    base = _fp_cache.get(key)
    if base is None:
        ch = tlsmod.profile_hello(TLS_PROFILES[profile_name], "x" if sni else None)
        base = tlsmod.tls_metadata(ch, None, quic=quic)
        base.pop("sni", None)
        _fp_cache[key] = base
    meta = dict(base)
    meta["sni"] = sni or ""
    meta["_profile"] = profile_name   # lab-private hint for PCAP synthesis; stripped before export
    return meta


def client_hello_len(profile_name: str, sni: str | None) -> int:
    key = (profile_name, len(sni) if sni else -1)
    n = _ch_len_cache.get(key)
    if n is None:
        n = _ch_len_cache[key] = len(tlsmod.build_client_hello(TLS_PROFILES[profile_name], sni))
    return n


def lab_ja3_watchlist() -> dict[str, str]:
    """JA3 hashes of the 'known' lab C2 families (with and without SNI)."""
    out = {}
    for name in WATCHLIST_PROFILES:
        for sni in ("c2.example", None):
            out[tls_meta(name, sni)["ja3"]] = name
    return out


# ---------------------------------------------------------------------------
# Packet-size / timing sequences (SPLT) for encrypted sessions
# ---------------------------------------------------------------------------
def splt_web(rng, ch_len: int, rtt_ms: float) -> tuple[list, int, int]:
    """Benign HTTPS page/API fetch: large server flight, request, burst of full-size replies."""
    seq = [(HDR_TCP + ch_len, 0.0)]
    for i in range(rng.randint(2, 4)):
        seq.append((-(HDR_TCP + rng.randint(1100, MSS)), rtt_ms if i == 0 else rng.uniform(0.05, 1.5)))
    seq.append((HDR_TCP + rng.randint(64, 160), rng.uniform(0.3, 4)))
    seq.append((HDR_TCP + rng.randint(250, 900), rng.uniform(0.1, 3)))
    for i in range(rng.randint(3, 14)):
        size = MSS if rng.random() < 0.75 else rng.randint(200, MSS)
        seq.append((-(HDR_TCP + size), rtt_ms if i == 0 else rng.uniform(0.02, 2.5)))
    extra_down = lognormal_bytes(rng, 30_000, 1.4, 0, 20_000_000)
    extra_up = lognormal_bytes(rng, 1_500, 1.0, 0, 200_000)
    return seq[:20], extra_up, extra_down


def splt_c2(rng, ch_len: int, rtt_ms: float, tasking: bool = False) -> tuple[list, int, int]:
    """C2 check-in: short server flight (small/self-signed chain), small request, small reply."""
    seq = [(HDR_TCP + ch_len, 0.0)]
    seq.append((-(HDR_TCP + rng.randint(700, 1300)), rtt_ms))
    if rng.random() < 0.5:
        seq.append((-(HDR_TCP + rng.randint(60, 400)), rng.uniform(0.05, 1)))
    seq.append((HDR_TCP + rng.randint(60, 140), rng.uniform(0.3, 3)))
    seq.append((HDR_TCP + rng.randint(120, 420), rng.uniform(0.1, 5)))
    seq.append((-(HDR_TCP + rng.randint(60, 320)), rtt_ms * rng.uniform(1, 3)))
    if tasking:
        for _ in range(rng.randint(2, 8)):
            seq.append((-(HDR_TCP + rng.randint(600, MSS)), rng.uniform(0.02, 2)))
        seq.append((HDR_TCP + rng.randint(80, 600), rng.uniform(50, 800)))
    elif rng.random() < 0.4:  # keep-alive heartbeat on the same session
        for _ in range(rng.randint(1, 4)):
            seq.append((HDR_TCP + rng.randint(60, 200), rng.uniform(800, 5000)))
            seq.append((-(HDR_TCP + rng.randint(60, 200)), rtt_ms))
    extra_down = rng.randint(20_000, 400_000) if tasking else 0
    return seq[:20], rng.randint(0, 2000), extra_down


def splt_quic(rng, benign: bool, rtt_ms: float) -> list:
    seq = [(HDR_UDP + rng.choice([1200, 1252, 1350]), 0.0), (-(HDR_UDP + 1200), rtt_ms), (-(HDR_UDP + rng.randint(900, 1200)), 0.2)]
    if benign:
        seq.append((HDR_UDP + rng.randint(40, 90), rng.uniform(0.3, 3)))
        seq.append((HDR_UDP + rng.randint(200, 700), rng.uniform(0.1, 2)))
        for i in range(rng.randint(4, 14)):
            seq.append((-(HDR_UDP + rng.choice([1200, 1252, 1350, rng.randint(100, 1350)])), rtt_ms if i == 0 else rng.uniform(0.02, 2)))
    else:
        seq.append((HDR_UDP + rng.randint(40, 90), rng.uniform(0.3, 3)))
        seq.append((HDR_UDP + rng.randint(100, 300), rng.uniform(0.1, 3)))
        seq.append((-(HDR_UDP + rng.randint(60, 250)), rtt_ms))
        for _ in range(rng.randint(0, 3)):
            seq.append((HDR_UDP + rng.randint(40, 120), rng.uniform(1000, 5000)))
    return seq[:20]


def tls_session(rng, ts, src, dst, dport, profile, sni, *, c2=False, tasking=False, rtt_ms=None, sport=None) -> dict:
    """An outbound TLS session with realistic handshake metadata and SPLT."""
    rtt = rtt_ms if rtt_ms is not None else rng.uniform(8, 120)
    ch = client_hello_len(profile, sni)
    if c2:
        splt, up, down = splt_c2(rng, ch, rtt, tasking)
        dur = sum(i for _, i in splt) / 1000.0 + rng.uniform(0.05, 1.5)
    else:
        splt, up, down = splt_web(rng, ch, rtt)
        dur = sum(i for _, i in splt) / 1000.0 + down / rng.uniform(400_000, 6_000_000) + rng.uniform(0.05, 20)
    return tcp_conn(rng, ts, dur, src, dst, dport, sport=sport, splt=splt, up=up, down=down,
                    tls=tls_meta(profile, sni))


def quic_session(rng, ts, src, dst, benign=True) -> dict:
    rtt = rng.uniform(8, 80)
    splt = splt_quic(rng, benign, rtt)
    f = [x for x, _ in splt if x > 0]
    b = [-x for x, _ in splt if x < 0]
    extra_down = lognormal_bytes(rng, 40_000, 1.4, 0, 10_000_000) if benign else 0
    nb_extra = math.ceil(extra_down / 1350) if extra_down else 0
    pf = len(f) + nb_extra // 4
    bf = sum(f) + (nb_extra // 4) * (HDR_UDP + 40)
    pb = len(b) + nb_extra
    bb = sum(b) + extra_down + HDR_UDP * nb_extra
    dur = sum(i for _, i in splt) / 1000.0 + (extra_down / 3_000_000 if benign else rng.uniform(0.2, 3))
    rec = make_record(ts, ts + dur, src, eph_port(rng), dst, 443, 17, pf, bf, pb, bb, quic={"version": "1"})
    rec["splt"] = {"len": [x for x, _ in splt], "iat": [round(i, 3) for _, i in splt]}
    return rec


# ---------------------------------------------------------------------------
# Domain names: benign, DGA families, tunnel encodings
# ---------------------------------------------------------------------------
_TLDS_COMMON = ["com"] * 8 + ["net", "org", "in", "co.in", "io", "info"]
_TLDS_DGA = ["com", "net", "org", "info", "biz", "ru", "xyz", "top", "cc", "pw", "in", "club", "online", "su"]
_SUBS = ["www", "api", "cdn", "static", "img", "m", "login", "mail", "app", "assets", "edge", "media"]


def benign_domain(rng, with_sub: bool = True) -> str:
    r = rng.random()
    if r < 0.7:
        d = rng.choice(BENIGN_DOMAINS)
    elif r < 0.9:
        d = rng.choice(WORDS) + rng.choice(WORDS) + "." + rng.choice(_TLDS_COMMON)
    else:
        d = rng.choice(WORDS) + rng.choice(["", "hub", "ly", "ify", "app", "web", "360", "24", "online"]) + "." + rng.choice(_TLDS_COMMON)
    if with_sub and d.count(".") == 1 and rng.random() < 0.6:
        d = rng.choice(_SUBS) + "." + d
    return d


def cdn_hostname(rng) -> str:
    provider = rng.choice(["cloudfront.net", "akamaihd.net", "fastly.net", "azureedge.net", "gvt1.com"])
    return "".join(rng.choice("0123456789abcdef") for _ in range(rng.randint(10, 16))) + "." + provider


DGA_FAMILIES = ["random_alpha", "alnum", "hex", "pronounceable", "wordlist"]


def dga_domain(rng, family: str) -> str:
    if family == "random_alpha":
        label = "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(8, 20)))
    elif family == "alnum":
        label = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(rng.randint(10, 24)))
    elif family == "hex":
        label = hashlib.md5(str(rng.random()).encode()).hexdigest()[: rng.randint(12, 32)]
    elif family == "pronounceable":
        cons, vows = "bcdfghjklmnprstvwxz", "aeiou"
        label = "".join(rng.choice(cons) + rng.choice(vows) for _ in range(rng.randint(4, 8)))
        if rng.random() < 0.5:
            label += rng.choice(cons)
    else:  # wordlist (e.g. Suppobox / Matsnu style)
        label = "".join(rng.choice(WORDS) for _ in range(rng.randint(2, 3)))
    return f"{label}.{rng.choice(_TLDS_DGA)}"


_B32 = "abcdefghijklmnopqrstuvwxyz234567"


def tunnel_qname(rng, base: str, style: str, seq: int) -> tuple[str, str]:
    """(qname, qtype) for one tunnelled query."""
    if style == "dnscat":
        n = rng.randint(20, 110)
        payload = "".join(rng.choice("0123456789abcdef") for _ in range(n))
        labels = [f"{seq & 0xFFFF:04x}" + payload[:59]] + [payload[i:i + 63] for i in range(59, len(payload), 63)]
        return ".".join(labels + [base]), rng.choice(["TXT", "TXT", "CNAME", "MX"])
    if style == "iodine":
        payload = "".join(rng.choice(_B32 + "0189") for _ in range(rng.randint(60, 180)))
        labels = [payload[i:i + 63] for i in range(0, len(payload), 63)]
        return ".".join(["y" + labels[0][1:]] + labels[1:] + [base]), rng.choice(["NULL", "NULL", "TXT", "SRV"])
    # slow exfil: base32 chunks in A lookups
    payload = "".join(rng.choice(_B32) for _ in range(rng.randint(24, 56)))
    return f"{payload}.{seq % 997}.{base}", "A"


def tunnel_resp_extra(rng, style: str, qtype: str) -> int:
    if qtype == "NULL":
        return rng.randint(200, 1100)
    if qtype == "TXT":
        return rng.randint(60, 240)
    if qtype in ("CNAME", "MX", "SRV"):
        return rng.randint(20, 120)
    return 0


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
class Pattern:
    """A traffic source active in [start, end). emit() adds connections that start in [t0, t1)."""

    kind = "benign"
    label = "benign"

    def __init__(self, rng: random.Random, start: float = -math.inf, end: float = math.inf):
        self.rng = rng
        self.start = start
        self.end = end

    def window(self, t0, t1):
        a, b = max(t0, self.start), min(t1, self.end)
        return (a, b) if b > a else None

    def emit(self, ex: Exporter, t0: float, t1: float):
        raise NotImplementedError

    def done(self, t: float) -> bool:
        return t >= self.end


# ----- benign -------------------------------------------------------------
class WebServer(Pattern):
    """Inbound HTTPS to a public-facing server from a (possibly huge) client population."""

    def __init__(self, rng, server, rate, n_clients=2000, dport=443, keepalive_share=0.05, **kw):
        super().__init__(rng, **kw)
        self.server, self.rate, self.dport = server, rate, dport
        self.clients = [public_ip(rng) for _ in range(min(n_clients, 20000))]
        self.keepalive = keepalive_share

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w:
            return
        rng = self.rng
        n = len(self.clients)
        for t in arrivals(rng, self.rate, *w):
            client = self.clients[min(n - 1, int(n * rng.random() ** 2))]   # skewed popularity
            if rng.random() < self.keepalive:
                dur = rng.uniform(12, 90)
                up, down = rng.randint(200, 3000), rng.randint(500, 60000)
            else:
                dur = rng.uniform(0.05, 8)
                up, down = lognormal_bytes(rng, 700, 0.8, 100, 50_000), lognormal_bytes(rng, 25_000, 1.5, 300, 5_000_000)
            ex.add(tcp_conn(rng, t, dur, client, self.server, self.dport, up=up, down=down))


class UdpService(Pattern):
    """Inbound UDP service (DNS, NTP, VoIP/game) with answered requests."""

    def __init__(self, rng, server, dport, rate, n_clients=500, req=(40, 90), resp=(60, 500), pkts=(1, 1), **kw):
        super().__init__(rng, **kw)
        self.server, self.dport, self.rate = server, dport, rate
        self.clients = [public_ip(rng) for _ in range(n_clients)]
        self.req, self.resp, self.pkts = req, resp, pkts

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w:
            return
        rng = self.rng
        for t in arrivals(rng, self.rate, *w):
            p = rng.randint(*self.pkts)
            pf, pb = p, p
            bf = sum(HDR_UDP + rng.randint(*self.req) for _ in range(pf))
            bb = sum(HDR_UDP + rng.randint(*self.resp) for _ in range(pb))
            dur = rng.uniform(0.001, 0.05) if p == 1 else rng.uniform(1, 30)
            ex.add(make_record(t, t + dur, rng.choice(self.clients), eph_port(rng), self.server, self.dport, 17, pf, bf, pb, bb))


class Browsing(Pattern):
    """A workstation browsing: DNS lookups then TLS / QUIC sessions to popular sites."""

    def __init__(self, rng, host, resolver, rate=0.15, browser="chrome", **kw):
        super().__init__(rng, **kw)
        self.host, self.resolver, self.rate, self.browser = host, resolver, rate, browser

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w:
            return
        rng = self.rng
        for t in arrivals(rng, self.rate, *w):
            domain = benign_domain(rng)
            ex.add(dns_conn(rng, t, self.host, self.resolver, domain, rng.choice(["A", "A", "AAAA", "HTTPS"])))
            if rng.random() < 0.02:  # typo / dead link
                ex.add(dns_conn(rng, t + 0.01, self.host, self.resolver, benign_domain(rng, False).replace(".", "x.", 1), "A", "NXDOMAIN"))
            dst = stable_ip(registered_domain(domain))
            if rng.random() < 0.15 and self.browser == "chrome":
                ex.add(quic_session(rng, t + 0.03, self.host, dst))
            else:
                for k in range(rng.randint(1, 4)):
                    ex.add(tls_session(rng, t + 0.03 + k * rng.uniform(0.01, 0.3), self.host, dst, 443, self.browser, domain))
            for _ in range(rng.randint(0, 3)):  # page sub-resources on CDNs
                cdn = cdn_hostname(rng)
                ex.add(dns_conn(rng, t + rng.uniform(0.05, 0.5), self.host, self.resolver, cdn))
                ex.add(tls_session(rng, t + rng.uniform(0.1, 0.8), self.host, stable_ip(registered_domain(cdn)), 443, self.browser, cdn))


class PeriodicService(Pattern):
    """Benign periodic traffic: NTP, update checks, telemetry heartbeats, mail polling."""

    def __init__(self, rng, host, dst, dport, interval, jitter=0.05, proto=6, sizes=(300, 800),
                 profile=None, sni=None, phase=None, **kw):
        super().__init__(rng, **kw)
        self.host, self.dst, self.dport, self.interval, self.jitter = host, dst, dport, interval, jitter
        self.proto, self.sizes, self.profile, self.sni = proto, sizes, profile, sni
        self.next = (phase if phase is not None else rng.uniform(0, interval))

    def emit(self, ex, t0, t1):
        rng = self.rng
        if self.next < t0 - self.interval * 2:   # align a freshly created pattern
            self.next = t0 + rng.uniform(0, self.interval)
        while self.next < t1:
            t = self.next
            self.next += self.interval * (1 + rng.uniform(-self.jitter, self.jitter))
            if t < t0 or not (self.start <= t < self.end):
                continue
            if self.proto == 17:
                ex.add(make_record(t, t + rng.uniform(0.01, 0.1), self.host, eph_port(rng) if self.dport != 123 else 123,
                                   self.dst, self.dport, 17, 1, HDR_UDP + 48, 1, HDR_UDP + 48))
            elif self.profile:
                ex.add(tls_session(rng, t, self.host, self.dst, self.dport, self.profile, self.sni,
                                   c2=rng.random() < 0.5))
            else:
                ex.add(tcp_conn(rng, t, rng.uniform(0.05, 1.0), self.host, self.dst, self.dport,
                                up=rng.randint(*self.sizes), down=rng.randint(*self.sizes)))


class CloudBackup(Pattern):
    """Large outbound upload to a popular backup / sync service (hard negative for exfiltration)."""

    def __init__(self, rng, host, dst, rate_bps, sni="backup.cloudsync.com", profile="schannel", **kw):
        super().__init__(rng, **kw)
        self.host, self.dst, self.rate, self.sni, self.profile = host, dst, rate_bps, sni, profile
        self.opened = False

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w or self.opened:
            return
        self.opened = True
        rng = self.rng
        dur = (self.end - w[0]) if math.isfinite(self.end) else rng.uniform(60, 600)
        up = int(self.rate * dur)
        ch = client_hello_len(self.profile, self.sni)
        splt, _, _ = splt_web(rng, ch, rng.uniform(10, 60))
        ex.add(tcp_conn(rng, w[0], dur, self.host, self.dst, 443, splt=splt[:6], up=up,
                        down=int(up * rng.uniform(0.01, 0.04)), tls=tls_meta(self.profile, self.sni)))


class VideoCall(Pattern):
    def __init__(self, rng, host, dst, kbps=1500, **kw):
        super().__init__(rng, **kw)
        self.host, self.dst, self.kbps = host, dst, kbps
        self.opened = False

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w or self.opened:
            return
        self.opened = True
        rng = self.rng
        dur = (self.end - w[0]) if math.isfinite(self.end) else rng.uniform(300, 1800)
        pps = self.kbps * 1000 / 8 / 900
        pf = int(pps * dur)
        pb = int(pf * rng.uniform(0.7, 1.4))
        ex.add(make_record(w[0], w[0] + dur, self.host, eph_port(rng), self.dst, rng.choice([3478, 443, 8801]), 17,
                           pf, pf * rng.randint(700, 1100), pb, pb * rng.randint(700, 1100)))


class P2P(Pattern):
    """Peer-to-peer client: many peers on random ports, many failures (hard negative for scans)."""

    def __init__(self, rng, host, rate=4.0, **kw):
        super().__init__(rng, **kw)
        self.host, self.rate = host, rate
        self.peers = [(public_ip(rng), rng.randint(1025, 65000)) for _ in range(400)]

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w:
            return
        rng = self.rng
        for t in arrivals(rng, self.rate, *w):
            ip, port = rng.choice(self.peers)
            if rng.random() < 0.35:   # unreachable peer
                ex.add(make_record(t, t + rng.uniform(0, 3), self.host, eph_port(rng), ip, port, 6, rng.randint(1, 3), 40 * rng.randint(1, 3), 0, 0, "S", ""))
            elif rng.random() < 0.3:
                ex.add(make_record(t, t + 0.05, self.host, eph_port(rng), ip, port, 17, 1, rng.randint(60, 140), 1, rng.randint(60, 400)))
            else:
                ex.add(tcp_conn(rng, t, rng.uniform(1, 60), self.host, ip, port, up=lognormal_bytes(rng, 50_000, 1.5),
                                down=lognormal_bytes(rng, 200_000, 1.5)))


class AvLookups(Pattern):
    """Endpoint-security reputation lookups: hash-like labels in A queries (DNS hard negative)."""

    def __init__(self, rng, host, resolver, rate=0.3, base="rep.cloudav-sec.net", **kw):
        super().__init__(rng, **kw)
        self.host, self.resolver, self.rate, self.base = host, resolver, rate, base

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w:
            return
        rng = self.rng
        for t in arrivals(rng, self.rate, *w):
            h = hashlib.sha1(str(rng.random()).encode()).hexdigest()[: rng.choice([16, 32, 40])]
            ex.add(dns_conn(rng, t, self.host, self.resolver, f"{h}.{self.base}", "A", answers=1))


class TelemetryDns(Pattern):
    """Apps resolving the same few telemetry names repeatedly (low uniqueness)."""

    def __init__(self, rng, host, resolver, rate=0.5, base="events.telemetry-hub.com", **kw):
        super().__init__(rng, **kw)
        self.host, self.resolver, self.rate, self.base = host, resolver, rate, base
        self.names = [f"{p}.{base}" for p in ("eu", "global", "mobile", "v10", "settings")]

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w:
            return
        for t in arrivals(self.rng, self.rate, *w):
            ex.add(dns_conn(self.rng, t, self.host, self.resolver, self.rng.choice(self.names), self.rng.choice(["A", "AAAA", "HTTPS"])))


class Download(Pattern):
    def __init__(self, rng, host, dst, size, sni="dl.software-cdn.com", profile="schannel", **kw):
        super().__init__(rng, **kw)
        self.host, self.dst, self.size, self.sni, self.profile = host, dst, size, sni, profile
        self.opened = False

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w or self.opened:
            return
        self.opened = True
        rng = self.rng
        dur = self.size / rng.uniform(1e6, 12e6) + 1
        ch = client_hello_len(self.profile, self.sni)
        splt, _, _ = splt_web(rng, ch, rng.uniform(10, 60))
        ex.add(tcp_conn(rng, w[0], dur, self.host, self.dst, 443, splt=splt, up=rng.randint(1000, 20000),
                        down=self.size, tls=tls_meta(self.profile, self.sni)))


# ----- attacks ------------------------------------------------------------
class SynFlood(Pattern):
    """hping3 -S --flood: half-open TCP SYNs from a set of (real) bot addresses."""
    kind, label = "attack", "syn_flood"

    def __init__(self, rng, victim, dport, rate, sources, answer_prob=0.6, **kw):
        super().__init__(rng, **kw)
        self.victim, self.dport, self.rate = victim, dport, rate
        self.sources = sources if isinstance(sources, list) else [public_ip(rng) for _ in range(sources)]
        self.answer = answer_prob

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w:
            return
        rng = self.rng
        for t in arrivals(rng, self.rate, *w):
            src = self.sources[int(len(self.sources) * rng.random())]
            size = rng.choice([40, 40, 44, 60])
            if rng.random() < self.answer:
                ff, pf, bf = ("SR", 2, size + 40) if rng.random() < 0.5 else ("S", 1, size)
                ex.add(make_record(t, t + rng.uniform(0, 1.0), src, eph_port(rng), self.victim, self.dport, 6, pf, bf,
                                   rng.randint(1, 2), 44 * rng.randint(1, 2), ff, "SA"))
            else:
                ex.add(make_record(t, t, src, eph_port(rng), self.victim, self.dport, 6, 1, size, 0, 0, "S", ""))


class SpoofedFlood(Pattern):
    """hping3 --rand-source: every packet from a fresh random source address."""
    kind, label = "attack", "spoofed_flood"

    def __init__(self, rng, victim, dport, rate, proto=6, **kw):
        super().__init__(rng, **kw)
        self.victim, self.dport, self.rate, self.proto = victim, dport, rate, proto

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w:
            return
        rng = self.rng
        for t in arrivals(rng, self.rate, *w):
            src = public_ip(rng)
            if self.proto == 6:
                if rng.random() < 0.5:   # victim's SYN-ACK / RST toward the spoofed address
                    ex.add(make_record(t, t + rng.uniform(0, 1), src, eph_port(rng), self.victim, self.dport, 6, 1, 40,
                                       1, 44, "S", rng.choice(["SA", "RA"])))
                else:
                    ex.add(make_record(t, t, src, eph_port(rng), self.victim, self.dport, 6, 1, 40, 0, 0, "S", ""))
            else:
                size = rng.randint(28, 1200)
                ex.add(make_record(t, t, src, eph_port(rng), self.victim, self.dport or rng.randint(1, 65535), 17, 1, size, 0, 0))


class UdpIcmpFlood(Pattern):
    """hping3 --udp / --icmp --flood from real sources (source port increments or fixed)."""
    kind, label = "attack", "udp_icmp_flood"

    def __init__(self, rng, victim, pps, sources, proto=17, size=(64, 1400), dport=None, fixed_ports=False, **kw):
        super().__init__(rng, **kw)
        self.victim, self.pps, self.proto, self.size, self.dport = victim, pps, proto, size, dport
        self.sources = sources if isinstance(sources, list) else [public_ip(rng) for _ in range(sources)]
        self.fixed = fixed_ports or proto == 1
        self.opened = False

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w:
            return
        rng = self.rng
        if self.fixed:
            if self.opened:
                return
            self.opened = True
            end = self.end if math.isfinite(self.end) else w[0] + 60
            per_src = self.pps / len(self.sources)
            for src in self.sources:
                ts = w[0] + rng.uniform(0, min(ACTIVE_TIMEOUT, max(0.0, end - w[0] - 1)))
                dur = end - ts
                p = max(1, int(per_src * dur))
                size = rng.randint(*self.size)
                if self.proto == 1:
                    # under a real ping flood the target is saturated; only a small
                    # fraction of echo requests get an echo reply
                    replies = int(p * rng.uniform(0, 0.08))
                    ex.add(make_record(ts, end, src, 0, self.victim, 2048, 1, p, p * size, replies, replies * size))
                else:
                    ex.add(make_record(ts, end, src, eph_port(rng), self.victim, self.dport or rng.randint(1, 1024), 17, p, p * size, 0, 0))
            return
        # hping3 default: the source port increments, so every packet is a new flow
        for t in arrivals(rng, self.pps, *w):
            size = rng.randint(*self.size)
            ex.add(make_record(t, t, self.sources[int(len(self.sources) * rng.random())], eph_port(rng), self.victim,
                               self.dport or rng.randint(1, 65535), 17, 1, size, 0, 0))


AMP_PROFILES = {  # service port -> (bytes per packet range, packets per response range)
    53: ((1100, 1480), (1, 4)),      # DNS ANY / DNSSEC
    123: ((440, 468), (1, 100)),     # NTP monlist
    1900: ((280, 360), (1, 10)),     # SSDP
    11211: ((1300, 1480), (5, 60)),  # memcached
    389: ((1300, 1480), (1, 3)),     # CLDAP
    19: ((700, 1100), (1, 2)),       # CharGEN
    161: ((400, 1480), (1, 6)),      # SNMP
}


class UdpAmplification(Pattern):
    """Reflected responses from open amplifiers toward the victim (never requested by it)."""
    kind, label = "attack", "udp_amplification"

    def __init__(self, rng, victim, rate, reflectors=300, service=53, **kw):
        super().__init__(rng, **kw)
        self.victim, self.rate, self.service = victim, rate, service
        self.reflectors = [public_ip(rng) for _ in range(reflectors)]

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w:
            return
        rng = self.rng
        (blo, bhi), (plo, phi) = AMP_PROFILES[self.service]
        for t in arrivals(rng, self.rate, *w):
            p = rng.randint(plo, phi)
            b = sum(rng.randint(blo, bhi) for _ in range(p))
            ex.add(make_record(t, t + rng.uniform(0, 0.2), rng.choice(self.reflectors), self.service, self.victim,
                               rng.randint(1024, 65535), 17, p, b, 0, 0))


class Slowloris(Pattern):
    """Many long-lived connections trickling partial HTTP headers to exhaust a web server."""
    kind, label = "attack", "slow_http"

    def __init__(self, rng, victim, dport=80, conns=400, sources=2, interval=(8, 15), **kw):
        super().__init__(rng, **kw)
        self.victim, self.dport, self.conns, self.interval = victim, dport, conns, interval
        self.sources = sources if isinstance(sources, list) else [public_ip(rng) for _ in range(sources)]
        self.opened = False

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w or self.opened:
            return
        self.opened = True
        rng = self.rng
        end = self.end if math.isfinite(self.end) else w[0] + 300
        for _ in range(self.conns):
            t = w[0] + rng.uniform(0, min(8.0, end - w[0]))
            dur = end - t
            gap = rng.uniform(*self.interval)
            beats = max(1, int(dur / gap))
            first = HDR_TCP + rng.randint(180, 320)       # partial request line + first headers
            beat = HDR_TCP + rng.randint(18, 40)          # one "X-a: b" header line per packet
            pf, bf = 3 + beats, 2 * HDR_TCP + first + beats * beat
            pb, bb = 2 + beats, HDR_TCP * (2 + beats)     # SYN-ACK + an ACK per trickled line
            splt = {"len": [first] + [beat] * min(beats, 19), "iat": [0.0] + [round(gap * 1000, 3)] * min(beats, 19)}
            ex.add(make_record(t, t + dur, rng.choice(self.sources), eph_port(rng), self.victim, self.dport, 6,
                               pf, bf, pb, bb, "SAP", "SA", splt=splt))


class PortScan(Pattern):
    """nmap-style SYN / connect / UDP scans. style: vertical (many ports) or horizontal (many hosts)."""
    kind = "attack"

    def __init__(self, rng, scanner, targets, ports, rate, style="vertical", open_ratio=0.05, method="syn", **kw):
        super().__init__(rng, **kw)
        self.label = f"{style}_scan"
        self.scanner, self.rate, self.method, self.open_ratio = scanner, rate, method, open_ratio
        probes = [(h, p) for h in targets for p in ports]
        rng.shuffle(probes)
        self.probes = probes
        self.i = 0

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w:
            return
        rng = self.rng
        for t in arrivals(rng, self.rate, *w):
            if self.i >= len(self.probes):
                self.i = 0
            host, port = self.probes[self.i]
            self.i += 1
            if self.method == "udp":
                ex.add(make_record(t, t, self.scanner, eph_port(rng), host, port, 17, 1, HDR_UDP + rng.choice([0, 8, 40]), 0, 0))
                continue
            r = rng.random()
            if r < self.open_ratio:         # open: SYN-ACK, scanner resets (or completes for -sT)
                ff = "SAR" if self.method == "connect" else "SR"
                ex.add(make_record(t, t + rng.uniform(0.001, 0.1), self.scanner, eph_port(rng), host, port, 6,
                                   2 + (self.method == "connect"), 40 * (2 + (self.method == "connect")), 1, 44, ff, "SA"))
            elif r < 0.55:                  # closed: RST
                ex.add(make_record(t, t + rng.uniform(0.001, 0.05), self.scanner, eph_port(rng), host, port, 6, 1, 44, 1, 40, "S", "RA"))
            else:                           # filtered: silence
                ex.add(make_record(t, t, self.scanner, eph_port(rng), host, port, 6, 1, 44, 0, 0, "S", ""))


class Beacon(Pattern):
    """C2 emulator: periodic TLS check-ins with jitter, occasional tasking."""
    kind, label = "attack", "beacon"

    def __init__(self, rng, host, c2, dport=443, interval=10.0, jitter=0.1, profile="mal_go_implant",
                 sni=None, miss=0.03, tls=True, **kw):
        super().__init__(rng, **kw)
        self.host, self.c2, self.dport, self.interval, self.jitter = host, c2, dport, interval, jitter
        self.profile, self.sni, self.miss, self.tls = profile, sni, miss, tls
        self.next = None

    def emit(self, ex, t0, t1):
        rng = self.rng
        if self.next is None:
            self.next = max(t0, self.start) + rng.uniform(0, self.interval)
        while self.next < min(t1, self.end):
            t = self.next
            self.next += self.interval * (1 + rng.uniform(-self.jitter, self.jitter))
            if t < t0 or t < self.start or rng.random() < self.miss:
                continue
            if self.tls:
                ex.add(tls_session(rng, t, self.host, self.c2, self.dport, self.profile, self.sni, c2=True,
                                   tasking=rng.random() < 0.05))
            else:   # plain HTTP check-in: small GET, small reply
                ex.add(tcp_conn(rng, t, rng.uniform(0.05, 0.6), self.host, self.c2, self.dport,
                                up=rng.randint(180, 420), down=rng.randint(80, 400)))


class MalwareTls(Pattern):
    """Irregular encrypted C2 / loader sessions from an implant's TLS stack."""
    kind, label = "attack", "malware_tls"

    def __init__(self, rng, host, c2, profile, sni=None, rate=0.2, dport=443, **kw):
        super().__init__(rng, **kw)
        self.host, self.c2, self.profile, self.sni, self.rate, self.dport = host, c2, profile, sni, rate, dport

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w:
            return
        for t in arrivals(self.rng, self.rate, *w):
            ex.add(tls_session(self.rng, t, self.host, self.c2, self.dport, self.profile, self.sni, c2=True,
                               tasking=self.rng.random() < 0.15))


class DgaBurst(Pattern):
    """A bot walking its DGA list: many never-registered names -> NXDOMAIN, one live C2."""
    kind, label = "attack", "dga"

    def __init__(self, rng, host, resolver, family="random_alpha", rate=2.0, nx_ratio=0.95, **kw):
        super().__init__(rng, **kw)
        self.host, self.resolver, self.family, self.rate, self.nx = host, resolver, family, rate, nx_ratio

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w:
            return
        rng = self.rng
        for t in arrivals(rng, self.rate, *w):
            d = dga_domain(rng, self.family)
            nx = rng.random() < self.nx
            ex.add(dns_conn(rng, t, self.host, self.resolver, d, "A", "NXDOMAIN" if nx else "NOERROR", answers=1))


class DnsTunnel(Pattern):
    """dnscat2 / iodine style tunnel, or slow base32 exfiltration over A lookups."""
    kind, label = "attack", "dns_tunnel"

    def __init__(self, rng, host, resolver, base="t.tunnel-lab.xyz", style="dnscat", rate=8.0, **kw):
        super().__init__(rng, **kw)
        self.host, self.resolver, self.base, self.style, self.rate = host, resolver, base, style, rate
        self.seq = rng.randint(0, 5000)

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w:
            return
        rng = self.rng
        for t in arrivals(rng, self.rate, *w):
            self.seq += 1
            qname, qtype = tunnel_qname(rng, self.base, self.style, self.seq)
            ex.add(dns_conn(rng, t, self.host, self.resolver, qname, qtype, answers=1,
                            resp_extra=tunnel_resp_extra(rng, self.style, qtype)))


class Exfiltration(Pattern):
    """Bulk upload from an internal host to a rarely contacted external destination."""
    kind, label = "attack", "exfiltration"

    def __init__(self, rng, host, dst, rate_bps=2_000_000, dport=443, streams=1, profile="python", sni=None, **kw):
        super().__init__(rng, **kw)
        self.host, self.dst, self.rate, self.dport, self.streams = host, dst, rate_bps, dport, streams
        self.profile, self.sni = profile, sni
        self.opened = False

    def emit(self, ex, t0, t1):
        w = self.window(t0, t1)
        if not w or self.opened:
            return
        self.opened = True
        rng = self.rng
        end = self.end if math.isfinite(self.end) else w[0] + 180
        for i in range(self.streams):
            ts = w[0] + i * rng.uniform(0.5, 3)
            dur = max(1.0, end - ts)
            up = int(self.rate / self.streams * dur)
            extra = {}
            splt = None
            if self.dport in (443, 8443):
                extra["tls"] = tls_meta(self.profile, self.sni)
                splt, _, _ = splt_web(rng, client_hello_len(self.profile, self.sni), rng.uniform(20, 150))
                splt = splt[:6]
            ex.add(tcp_conn(rng, ts, dur, self.host, self.dst, self.dport, splt=splt, up=up,
                            down=rng.randint(2000, 40000), **extra))
