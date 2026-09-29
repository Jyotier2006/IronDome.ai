"""Labelled training samples for every detector.

Each sample is produced by the traffic-lab patterns (traffic.py) and pushed through
the very same FeaturePipeline the live sensor runs, so every model is trained on
exactly the feature vectors it will be served.

Benign data deliberately includes *hard negatives* - flash crowds, P2P clients,
network monitoring pollers, AV reputation lookups, CDN hostnames, backup uploads,
periodic update checks, rare-but-legitimate tools - so the models learn the
difference rather than a shortcut.

`shift=True` produces a *stress* distribution (weaker/slower/stealthier attacks and
harder negatives) that is never used for training and is reported separately.
"""

from __future__ import annotations

import math
import random

from . import traffic as T
from .features import FEATURES, DDoSExtractor, FeaturePipeline
from .lexical import domain_features
from .netutil import registered_domain

LABELS = {
    "ddos": ["benign", "syn_flood", "udp_icmp_flood", "udp_amplification", "spoofed_flood", "slow_http"],
    "recon_scan": ["benign", "vertical_scan", "horizontal_scan"],
    "c2_beacon": ["benign", "beacon"],
    "dga_domain": ["benign", "dga"],
    "dns_tunnel": ["benign", "tunnel"],
    "encrypted_malware": ["benign", "malware"],
    "exfiltration": ["benign", "exfiltration"],
}

RESOLVER = "203.0.113.53"


def loguniform(rng, lo, hi):
    return math.exp(rng.uniform(math.log(lo), math.log(hi)))


def internal_host(rng) -> str:
    return f"10.{rng.randint(10, 60)}.{rng.randint(1, 30)}.{rng.randint(2, 250)}"


def _epoch(rng) -> float:
    return rng.uniform(1.70e9, 1.78e9)


def _collect(patterns, t_start, t_end, lead=0.0, step=2.0):
    ex = T.Exporter()
    t = t_start - lead
    while t < t_end:
        t1 = min(t + step, t_end)
        for p in patterns:
            p.emit(ex, t, t1)
        t = t1
    return [r for r in ex.drain(t_end) if r["te"] >= t_start]


def _run(detector, records, seeds=None):
    pipe = FeaturePipeline("train", "replay", detectors=[detector])
    if seeds:
        seeds(pipe.ctx)
    for r in records:
        pipe.ingest(r, 0.0)
    return pipe.flush()


# ---------------------------------------------------------------------------
# (a) DDoS
# ---------------------------------------------------------------------------
def _server_background(rng, victim, t0, t1, rate):
    return T.WebServer(rng, victim, rate, n_clients=int(loguniform(rng, 50, 5000)), dport=rng.choice([443, 80]),
                       start=t0 - 0.3, end=t1)


def ddos_sample(rng, label, shift=False):
    W = DDoSExtractor.WINDOW
    t0 = W * math.floor(_epoch(rng) / W)
    t1 = t0 + W
    victim = internal_host(rng)
    pats = []
    lead = 0.3
    lo, hi = (15, 90) if shift else (40, 4000)
    if label == "benign":
        kind = T.weighted_choice(rng, [("web", 0.26), ("flash", 0.09), ("dns", 0.12), ("ntp", 0.05), ("voip", 0.11),
                                       ("quic", 0.09), ("clients", 0.18), ("scan_noise", 0.1)])
        rate = loguniform(rng, 15, 3000)
        if kind in ("web", "clients"):
            clients = int(loguniform(rng, 30, 20000))
            dport = rng.choice([443, 80])
            short = T.WebServer(rng, victim, rate if kind == "web" else loguniform(rng, 15, 400), n_clients=clients,
                                dport=dport, keepalive_share=0.0, start=t0 - 0.3, end=t1)
            # long-lived keep-alive / websocket connections opened before the window
            keep = T.WebServer(rng, victim, min(20.0, rate * rng.uniform(0, 0.15)), n_clients=clients, dport=dport,
                               keepalive_share=1.0, start=t0 - 40, end=t1)
            if kind == "clients":   # many internal clients -> one popular external destination
                short.clients = keep.clients = [internal_host(rng) for _ in range(rng.randint(5, 80))]
            pats += [short, keep]
            lead = 40
        elif kind == "flash":
            pats.append(T.WebServer(rng, victim, loguniform(rng, 800, 5000), n_clients=20000, keepalive_share=0.02,
                                    start=t0 - 0.3, end=t1))
        elif kind == "dns":
            pats.append(T.UdpService(rng, victim, 53, rate, n_clients=int(loguniform(rng, 20, 5000)), req=(30, 80),
                                     resp=(60, 500), start=t0 - 0.3, end=t1))
        elif kind == "ntp":
            pats.append(T.UdpService(rng, victim, 123, rate, n_clients=int(loguniform(rng, 20, 5000)), req=(48, 48),
                                     resp=(48, 48), start=t0 - 0.3, end=t1))
        elif kind == "voip":
            pats.append(T.UdpService(rng, victim, rng.choice([3478, 27015, 5060, 10000]), loguniform(rng, 15, 200),
                                     n_clients=int(loguniform(rng, 10, 800)), req=(60, 1200), resp=(60, 1200), pkts=(3, 300),
                                     start=t0 - 10, end=t1))
            lead = 10
        elif kind == "quic":
            pats.append(T.UdpService(rng, victim, 443, loguniform(rng, 15, 1000), n_clients=int(loguniform(rng, 30, 8000)),
                                     req=(40, 1350), resp=(100, 1350), pkts=(5, 60), start=t0 - 10, end=t1))
            lead = 10
        else:  # scan_noise: one source probing the victim's ports. That is a *scan* (the
               # recon detector's job), not a volumetric DDoS, so it is a hard negative here -
               # it stops fast vertical scans from being mislabelled as SYN floods.
            scanner = T.public_ip(rng) if rng.random() < 0.7 else internal_host(rng)
            if rng.random() < 0.6:
                ports = list(range(1, 1 + rng.randint(200, 1024)))
            else:
                ports = rng.sample(range(1, 65535), rng.randint(100, 1500))
            pats.append(T.PortScan(rng, scanner, [victim], ports, loguniform(rng, 20, 400), style="vertical",
                                   open_ratio=rng.uniform(0.005, 0.05), method=rng.choice(["syn", "syn", "connect"]),
                                   start=t0 - 0.3, end=t1))
            if rng.random() < 0.6:   # scan mixed with the victim's normal serving traffic
                pats.append(T.WebServer(rng, victim, loguniform(rng, 10, 300), n_clients=int(loguniform(rng, 20, 2000)),
                                        dport=rng.choice([443, 80]), start=t0 - 0.3, end=t1))
        if rng.random() < (0.5 if shift else 0.3):   # internet background radiation / backscatter
            pats.append(T.SynFlood(rng, victim, rng.choice([22, 23, 445, 3389, 80]), rng.uniform(1, 8),
                                   sources=200, answer_prob=0.9, start=t0 - 0.3, end=t1))
    else:
        if label == "syn_flood":
            pats.append(T.SynFlood(rng, victim, rng.choice([80, 443, 22, 25, 53, 3389]), loguniform(rng, lo, hi),
                                   sources=int(loguniform(rng, 1, 600)), answer_prob=rng.uniform(0, 0.95), start=t0 - 0.3, end=t1))
        elif label == "udp_icmp_flood":
            if rng.random() < 0.5:
                pats.append(T.UdpIcmpFlood(rng, victim, loguniform(rng, lo, hi), sources=int(loguniform(rng, 1, 80)),
                                           size=(rng.randint(28, 200), rng.randint(200, 1470)), start=t0 - 0.3, end=t1))
            else:
                start = t0 - rng.uniform(1, 40)
                pats.append(T.UdpIcmpFlood(rng, victim, loguniform(rng, 2000, 80000) / (4 if shift else 1),
                                           sources=int(loguniform(rng, 3, 40)), proto=rng.choice([1, 17]),
                                           size=(rng.randint(28, 200), rng.randint(200, 1470)), fixed_ports=True,
                                           start=start, end=t1 + rng.uniform(5, 60)))
                lead = t0 - start + 1
        elif label == "udp_amplification":
            pats.append(T.UdpAmplification(rng, victim, loguniform(rng, lo, hi), reflectors=int(loguniform(rng, 10, 3000)),
                                           service=rng.choice(list(T.AMP_PROFILES)), start=t0 - 0.3, end=t1))
        elif label == "spoofed_flood":
            pats.append(T.SpoofedFlood(rng, victim, rng.choice([80, 443, 53, 0]), loguniform(rng, lo, hi),
                                       proto=6 if rng.random() < 0.7 else 17, start=t0 - 0.3, end=t1))
        elif label == "slow_http":
            start = t0 - rng.uniform(15, 60)
            conns = int(loguniform(rng, 80, 400) if shift else loguniform(rng, 120, 1500))
            pats.append(T.Slowloris(rng, victim, rng.choice([80, 443, 8080]), conns=conns,
                                    sources=rng.randint(1, 5), interval=(rng.uniform(4, 10), rng.uniform(10, 20)),
                                    start=start, end=t1 + rng.uniform(1, 10)))
            lead = t0 - start + 1
        if rng.random() < (0.9 if shift else 0.6):
            pats.append(_server_background(rng, victim, t0, t1, loguniform(rng, 5, 600 if shift else 300)))
    recs = _collect(pats, t0, t1, lead=lead)
    cands = [c for c in _run("ddos", recs) if c["entity"]["ip"] == victim]
    meta_kind = f"benign:{kind}" if label == "benign" else label
    return (cands[0]["features"], {"kind": meta_kind}) if cands else None


# ---------------------------------------------------------------------------
# (e) Recon / scanning
# ---------------------------------------------------------------------------
_SWEEP_PORTS = [22, 23, 80, 443, 445, 3389, 8080, 5900, 1433, 6379, 21, 25, 139, 161]


def _scan_ports(rng, n):
    style = rng.random()
    if style < 0.35:
        first = rng.choice([1, 1, 1, 20, 1000, 8000])
        return list(range(first, first + n))
    if style < 0.8:   # nmap-top-ports-like: heavy toward well-known ports
        ports = set()
        while len(ports) < n:
            ports.add(int(min(65535, max(1, rng.paretovariate(0.6) * 10))))
        return sorted(ports)
    return rng.sample(range(1, 65536), n)


def scan_sample(rng, label, shift=False):
    t0 = _epoch(rng)
    span = 30.0
    pats = []
    rate_lo, rate_hi = (0.4, 3) if shift else (1, 300)
    if label == "benign":
        src = internal_host(rng)
        kind = T.weighted_choice(rng, [("browse", 0.25), ("p2p", 0.16), ("poller", 0.13), ("mail", 0.08),
                                       ("proxy", 0.13), ("resolver", 0.08), ("retry_storm", 0.08),
                                       ("udp_flood_src", 0.09)])
        if kind == "browse":
            pats.append(T.Browsing(rng, src, RESOLVER, rate=loguniform(rng, 0.2, 4), browser=rng.choice(["chrome", "firefox", "safari"])))
        elif kind == "p2p":
            pats.append(T.P2P(rng, src, rate=loguniform(rng, 0.5, 20)))
        elif kind == "udp_flood_src":
            # a flooding source spraying random destination ports with large payloads: a DoS
            # (the DDoS detector's job), not reconnaissance - hard negative for the scan model
            src = T.public_ip(rng) if rng.random() < 0.7 else src
            pats.append(T.UdpIcmpFlood(rng, internal_host(rng), loguniform(rng, 20, 600), sources=[src],
                                       size=(rng.randint(100, 500), rng.randint(500, 1470)), start=t0, end=t0 + span))
        else:
            recs = []
            if kind == "retry_storm":   # app retrying unreachable backends: many failed SYNs, few pairs
                backends = [internal_host(rng) for _ in range(rng.randint(4, 12))]
                ports = rng.sample([443, 5432, 6379, 9092, 8080, 27017, 1433], rng.randint(1, 3))
                for t in T.arrivals(rng, loguniform(rng, 2, 60), t0, t0 + span):
                    recs.append(T.make_record(t, t + rng.uniform(0, 3), src, T.eph_port(rng), rng.choice(backends),
                                              rng.choice(ports), 6, rng.randint(1, 3), 60 * rng.randint(1, 3), 0, 0, "S", ""))
            elif kind == "poller":
                hosts = [internal_host(rng) for _ in range(int(loguniform(rng, 20, 400)))]
                ports = rng.sample([22, 161, 443, 9100, 3389, 5985, 80], rng.randint(1, 3))
                for h in hosts:
                    for p in ports:
                        t = t0 + rng.uniform(0, span)
                        if p == 161:
                            recs.append(T.make_record(t, t + 0.02, src, T.eph_port(rng), h, 161, 17, 1, 90, 1, rng.randint(90, 600)))
                        else:
                            recs.append(T.tcp_conn(rng, t, rng.uniform(0.05, 2), src, h, p, up=rng.randint(100, 3000), down=rng.randint(200, 30000)))
            elif kind in ("mail", "proxy", "resolver"):
                rate = loguniform(rng, 0.5, 10) if kind == "mail" else loguniform(rng, 2, 50)
                for t in T.arrivals(rng, rate, t0, t0 + span):
                    dst = T.public_ip(rng) if rng.random() < 0.7 else T.stable_ip(f"s{rng.randint(1, 30)}")
                    if kind == "resolver":
                        recs.append(T.make_record(t, t + 0.05, src, T.eph_port(rng), dst, 53, 17, 1, rng.randint(60, 100), 1, rng.randint(80, 500)))
                    else:
                        port = 25 if kind == "mail" else rng.choice([443, 443, 443, 80, 8080, 5222, 993])
                        recs.append(T.tcp_conn(rng, t, rng.uniform(0.1, 20), src, dst, port,
                                               up=T.lognormal_bytes(rng, 3000, 1.5), down=T.lognormal_bytes(rng, 30000, 1.5)))
            cands = [c for c in _run("recon_scan", sorted(recs, key=lambda r: r["te"])) if c["entity"]["ip"] == src]
            return (cands[0]["features"], {"kind": kind}) if cands else None
    else:
        src = T.public_ip(rng) if rng.random() < 0.7 else internal_host(rng)
        method = T.weighted_choice(rng, [("syn", 0.75), ("connect", 0.15), ("udp", 0.1)])
        if label == "vertical_scan":
            targets = [internal_host(rng) for _ in range(rng.randint(1, 3))]
            ports = _scan_ports(rng, int(loguniform(rng, 20, 3000)))
        else:
            base = f"10.{rng.randint(10, 60)}.{rng.randint(1, 30)}"
            targets = [f"{base}.{i}" for i in rng.sample(range(1, 255), min(254, int(loguniform(rng, 15, 254))))]
            ports = rng.sample(_SWEEP_PORTS, rng.randint(1, 3))
        pats.append(T.PortScan(rng, src, targets, ports, loguniform(rng, rate_lo, rate_hi), style=label.split("_")[0],
                               open_ratio=rng.uniform(0.005, 0.1), method=method, start=t0, end=t0 + span))
        kind = label
    recs = _collect(pats, t0, t0 + span)
    cands = [c for c in _run("recon_scan", recs) if c["entity"]["ip"] == src]
    return (cands[0]["features"], {"kind": kind}) if cands else None


# ---------------------------------------------------------------------------
# (b) C2 beaconing
# ---------------------------------------------------------------------------
def _sni_for_malware(rng, style=None):
    style = style or T.weighted_choice(rng, [("none", 0.35), ("ip", 0.15), ("dga", 0.3), ("lookalike", 0.2)])
    if style == "none":
        return None
    if style == "ip":
        return T.public_ip(rng)
    if style == "dga":
        return T.dga_domain(rng, rng.choice(T.DGA_FAMILIES[:4]))
    return rng.choice(["update", "cdn", "secure", "login", "api", "sync"]) + "-" + rng.choice(
        ["microsoft", "office", "windows", "google", "adobe", "cloud", "account"]) + rng.choice(["-cdn.com", "-services.net", ".info", "-update.com"])


def beacon_sample(rng, label, shift=False):
    t0 = _epoch(rng)
    host, dst = internal_host(rng), T.public_ip(rng)
    n = rng.randint(6, 40)
    if label == "beacon":
        interval = loguniform(rng, 3, 300)
        jitter = rng.uniform(0.3, 0.6) if shift else rng.uniform(0, 0.4)
        miss = rng.uniform(0.1, 0.25) if shift else rng.uniform(0, 0.1)
        prevalence = rng.randint(1, 3) if rng.random() < 0.85 else rng.randint(4, 12)
        use_tls = rng.random() < 0.85
        dport = rng.choice([443] * 6 + [8443, 80, 8080, rng.randint(1025, 65000)]) if use_tls else rng.choice([80, 8080])
        pat = T.Beacon(rng, host, dst, dport, interval, jitter, rng.choice(T.MALWARE_TLS_CLIENTS), _sni_for_malware(rng),
                       miss=miss, tls=use_tls, start=t0, end=t0 + interval * (n + 0.5))
        kind = "beacon"
    else:
        kind = T.weighted_choice(rng, [("ntp", 0.14), ("update", 0.14), ("heartbeat", 0.16), ("chat", 0.1),
                                       ("mail", 0.1), ("cron_api", 0.08 if not shift else 0.2), ("irregular", 0.28)])
        prevalence = int(loguniform(rng, 5, 250))
        if kind == "ntp":
            interval = loguniform(rng, 64, 1024)
            pat = T.PeriodicService(rng, host, dst, 123, interval, rng.uniform(0, 0.02), proto=17, start=t0, end=t0 + interval * (n + 0.5))
        elif kind == "irregular":
            median = loguniform(rng, 10, 600)
            times, t = [], t0
            for _ in range(n):
                t += rng.lognormvariate(math.log(median), rng.uniform(0.8, 2.0))
                times.append(t)
            profile = T.weighted_choice(rng, T.BENIGN_TLS_CLIENTS)
            sni = T.benign_domain(rng)
            prevalence = int(loguniform(rng, 1, 250))
            recs = []
            ex = T.Exporter()
            for t in times:
                ex.add(T.tls_session(rng, t, host, dst, 443, profile, sni, c2=rng.random() < 0.3))
            recs = ex.drain_all()
            return _beacon_features(host, dst, 443, 6, recs, prevalence, kind)
        else:
            cfg = {"update": (loguniform(rng, 300, 3600), 0.1, "schannel", "update.os-vendor.com", 443),
                   "heartbeat": (loguniform(rng, 15, 300), 0.1, rng.choice(["okhttp", "go", "schannel"]), "hb.telemetry-hub.com", 443),
                   "chat": (loguniform(rng, 20, 60), 0.2, "chrome", "chat.messenger-app.com", 443),
                   "mail": (loguniform(rng, 60, 600), 0.1, "schannel", "imap.mail-provider.com", 993),
                   "cron_api": (loguniform(rng, 60, 900), 0.05, rng.choice(["python", "go", "openssl3"]), "api.partner-portal.in", 443)}[kind]
            interval, jmax, profile, sni, port = cfg
            if kind == "cron_api":
                prevalence = rng.randint(1, 3)
            pat = T.PeriodicService(rng, host, dst, port, interval, rng.uniform(0, jmax), profile=profile, sni=sni,
                                    phase=t0 + rng.uniform(0, interval), start=t0, end=t0 + interval * (n + 0.5))
    recs = _collect([pat], pat.start, pat.end, step=max(2.0, (pat.end - pat.start) / 50))
    return _beacon_features(host, dst, pat.dport, getattr(pat, "proto", 6), recs, prevalence, kind)


def _beacon_features(host, dst, dport, proto, recs, prevalence, kind):
    def seeds(ctx):
        ctx.seed_dst_prevalence(dst, prevalence)
    cands = [c for c in _run("c2_beacon", recs, seeds) if c["entity"]["dst_ip"] == dst]
    return (cands[-1]["features"], {"kind": kind}) if cands else None


# ---------------------------------------------------------------------------
# (c) DGA domains (per domain) and DNS tunnelling (per host + base domain)
# ---------------------------------------------------------------------------
def dga_sample(rng, label, shift=False):
    if label == "dga":
        family = rng.choice(["wordlist", "pronounceable"]) if shift else rng.choice(T.DGA_FAMILIES)
        d = T.dga_domain(rng, family)
    else:
        family = "benign"
        r = rng.random()
        if r < 0.1:
            d = T.cdn_hostname(rng)
        else:
            d = T.benign_domain(rng, with_sub=False)
    return domain_features(registered_domain(d)), {"kind": family, "domain": d}


def tunnel_sample(rng, label, shift=False):
    t0 = _epoch(rng)
    span = 60.0
    host = internal_host(rng)
    if label == "tunnel":
        style = rng.choice(["slow", "slow", "dnscat"]) if shift else rng.choice(["dnscat", "iodine", "slow"])
        rate = {"dnscat": loguniform(rng, 0.3, 40), "iodine": loguniform(rng, 1, 40), "slow": loguniform(rng, 0.15, 2)}[style]
        if shift:
            rate = min(rate, 1.5)
        base = rng.choice(["t", "ns", "d", "x", "q"]) + "." + registered_domain(T.dga_domain(rng, rng.choice(T.DGA_FAMILIES)))
        pat = T.DnsTunnel(rng, host, RESOLVER, base=base, style=style, rate=rate, start=t0, end=t0 + span)
        kind = style
    else:
        kind = T.weighted_choice(rng, [("av", 0.2), ("cdn", 0.15), ("telemetry", 0.2), ("site", 0.15),
                                       ("mail_txt", 0.1), ("dnsbl", 0.1), ("srv", 0.1)])
        rate = loguniform(rng, 0.15, 5)
        if kind == "av":
            pat = T.AvLookups(rng, host, RESOLVER, rate=rate, base=rng.choice(["rep.cloudav-sec.net", "lookup.endpoint-guard.com"]), start=t0, end=t0 + span)
        elif kind == "telemetry":
            pat = T.TelemetryDns(rng, host, RESOLVER, rate=rate, start=t0, end=t0 + span)
        else:
            base = {"cdn": rng.choice(["cloudfront.net", "akamaihd.net", "fastly.net", "azureedge.net"]),
                    "site": registered_domain(T.benign_domain(rng)),
                    "mail_txt": registered_domain(T.benign_domain(rng)),
                    "dnsbl": rng.choice(["dnsbl.blocklist-lab.org", "rbl.mailshield.net"]),
                    "srv": "corp-example.in"}[kind]
            recs = []
            for t in T.arrivals(rng, min(rate, 2.0), t0, t0 + span):
                if kind == "cdn":
                    q, qt = "".join(rng.choice("0123456789abcdef") for _ in range(rng.randint(10, 16))) + "." + base, rng.choice(["A", "AAAA"])
                elif kind == "site":
                    q, qt = rng.choice(T._SUBS) + "." + base, rng.choice(["A", "AAAA", "HTTPS"])
                elif kind == "mail_txt":
                    q, qt = rng.choice([base, "_dmarc." + base, "selector1._domainkey." + base, "mail." + base]), rng.choice(["TXT", "TXT", "MX", "A"])
                elif kind == "dnsbl":
                    ip = T.public_ip(rng).split(".")
                    q, qt = ".".join(reversed(ip)) + "." + base, "A"
                else:
                    q, qt = rng.choice(["_ldap._tcp.dc._msdcs.", "_kerberos._udp.", "_gc._tcp.", "_ldap._tcp."]) + base, "SRV"
                rc = "NXDOMAIN" if kind == "dnsbl" and rng.random() < 0.9 else "NOERROR"
                recs.append(T.dns_conn(rng, t, host, RESOLVER, q, qt, rc, resp_extra=rng.choice([0, 0, rng.randint(20, 300)])))
            return _tunnel_features(host, recs, kind)
    recs = _collect([pat], t0, t0 + span)
    return _tunnel_features(host, recs, kind)


def _tunnel_features(host, recs, kind):
    cands = [c for c in _run("dns_tunnel", sorted(recs, key=lambda r: r["te"])) if c["entity"]["ip"] == host]
    if not cands:
        return None
    best = max(cands, key=lambda c: c["features"]["queries"])
    return best["features"], {"kind": kind}


# ---------------------------------------------------------------------------
# (d) Malware in encrypted sessions
# ---------------------------------------------------------------------------
def tls_sample(rng, label, shift=False):
    t0 = _epoch(rng)
    host, dst = internal_host(rng), T.public_ip(rng)
    ex = T.Exporter()
    if label == "benign":
        kind = T.weighted_choice(rng, [("browser", 0.5), ("app_periodic", 0.14), ("api_tool", 0.14 if not shift else 0.3),
                                       ("quic", 0.12), ("download", 0.1)])
        dst_prev = int(loguniform(rng, 8, 300))
        if kind == "quic":
            ex.add(T.quic_session(rng, t0, host, dst, benign=True))
            profile = None
            prevalence = 0
        else:
            if kind == "browser":
                profile = rng.choice(["chrome", "chrome", "firefox", "safari", "schannel", "okhttp"])
                sni = T.benign_domain(rng) if rng.random() < 0.8 else T.cdn_hostname(rng)
                ex.add(T.tls_session(rng, t0, host, dst, 443, profile, sni))
            elif kind == "app_periodic":
                profile = rng.choice(["schannel", "okhttp", "chrome", "go"])
                ex.add(T.tls_session(rng, t0, host, dst, 443, profile, rng.choice(["hb.telemetry-hub.com", "update.os-vendor.com", "sync.cloudsync.com", "push.notify-svc.com"]), c2=True))
            elif kind == "api_tool":
                profile = rng.choice(["python", "go", "openssl3"])
                ex.add(T.tls_session(rng, t0, host, dst, 443, profile, "api." + registered_domain(T.benign_domain(rng)), c2=rng.random() < 0.5))
            else:
                profile = rng.choice(["schannel", "chrome", "firefox"])
                ex.add(T.tls_session(rng, t0, host, dst, 443, profile, "dl." + registered_domain(T.benign_domain(rng))))
            prevalence = int(loguniform(rng, 1, 25)) if profile in ("python", "go", "openssl3") else int(loguniform(rng, 8, 250))
            # popular destinations are contacted by many internal hosts; an internal API
            # or a one-off download by fewer. This is the key benign-vs-C2 rarity signal.
            if kind == "api_tool":
                dst_prev = int(loguniform(rng, 1, 20))
            elif kind in ("app_periodic", "download"):
                dst_prev = int(loguniform(rng, 4, 150))
    else:
        kind = "malware"
        dst_prev = rng.randint(1, 4)   # C2 infrastructure is rarely contacted, even when the client mimics a browser
        if rng.random() < 0.05:
            ex.add(T.quic_session(rng, t0, host, dst, benign=False))
            profile, prevalence = None, 0
        else:
            profile = rng.choice(["chrome", "schannel", "chrome"]) if shift else rng.choice(T.MALWARE_TLS_CLIENTS)
            sni = _sni_for_malware(rng, "lookalike" if shift and rng.random() < 0.7 else None)
            dport = rng.choice([443] * 8 + [8443, 4443, 993])
            ex.add(T.tls_session(rng, t0, host, dst, dport, profile, sni, c2=True, tasking=rng.random() < 0.1))
            prevalence = rng.randint(1, 3) if profile.startswith("mal_") else int(loguniform(rng, 8, 250))
        kind = profile or "quic"
    recs = [r for r in ex.drain_all() if r["seg"] == 0]

    def seeds(ctx):
        ctx.seed_dst_prevalence(dst, dst_prev)
        for r in recs:
            ja3 = (r.get("tls") or {}).get("ja3")
            if ja3:
                ctx.seed_ja3_prevalence(ja3, prevalence)
    cands = _run("encrypted_malware", recs, seeds)
    return (cands[0]["features"], {"kind": kind}) if cands else None


# ---------------------------------------------------------------------------
# (f) Data exfiltration
# ---------------------------------------------------------------------------
def exfil_sample(rng, label, shift=False):
    t_end = _epoch(rng)
    t0 = t_end - 60.0
    host, dst = internal_host(rng), T.public_ip(rng)
    pats = []
    cold = rng.random() < 0.2
    base_mean = loguniform(rng, 0.05e6, 30e6)
    baseline = (0.0, 0.0, 0) if cold else (base_mean, base_mean * rng.uniform(0.2, 1.0), rng.randint(5, 500))
    if label == "exfiltration":
        rate = loguniform(rng, 15e3, 120e3) if shift else loguniform(rng, 20e3, 20e6)
        dport = T.weighted_choice(rng, [(443, 0.6), (22, 0.15), (21, 0.05), (8443, 0.05), (8080, 0.05), (rng.randint(1025, 65000), 0.1)])
        profile = rng.choice(["python", "go", "openssl3", "mal_py_implant", "mal_go_implant"])
        if rng.random() < 0.25:   # smash-and-grab: one short burst inside the window
            dur = rng.uniform(5, 50)
            start = t0 + rng.uniform(0, 60 - dur)
            pats.append(T.Exfiltration(rng, host, dst, loguniform(rng, 1e6, 60e6) / dur, dport=dport, profile=profile,
                                       sni=_sni_for_malware(rng), start=start, end=start + dur))
        else:
            pats.append(T.Exfiltration(rng, host, dst, rate, dport=dport, streams=rng.randint(1, 4), profile=profile,
                                       sni=_sni_for_malware(rng), start=t0 - rng.uniform(0, 120), end=t_end + rng.uniform(1, 300)))
        prevalence = rng.randint(1, 3)
        kind = "exfiltration"
    else:
        kind = T.weighted_choice(rng, [("backup", 0.3), ("git", 0.15), ("mail", 0.15), ("photo", 0.1),
                                       ("screenshare", 0.12), ("partner_sftp", 0.08 if not shift else 0.2), ("video_upload", 0.1)])
        prevalence = int(loguniform(rng, 10, 250))
        if kind == "backup":
            pats.append(T.CloudBackup(rng, host, dst, loguniform(rng, 50e3, 20e6), start=t0 - rng.uniform(0, 300), end=t_end + rng.uniform(1, 600)))
            if rng.random() < 0.5:
                baseline = (loguniform(rng, 20e6, 900e6), loguniform(rng, 5e6, 200e6), rng.randint(5, 500))
        elif kind in ("git", "mail", "photo", "video_upload"):
            size = {"git": loguniform(rng, 1e6, 200e6), "mail": loguniform(rng, 1e6, 30e6), "photo": loguniform(rng, 2e6, 300e6),
                    "video_upload": loguniform(rng, 20e6, 900e6)}[kind]
            dport = {"git": rng.choice([443, 22]), "mail": rng.choice([587, 465, 443]), "photo": 443, "video_upload": 443}[kind]
            dur = rng.uniform(5, 55)
            start = t0 + rng.uniform(0, 60 - dur)
            pats.append(T.Exfiltration(rng, host, dst, size / dur, dport=dport, profile="schannel", sni="upload." + registered_domain(T.benign_domain(rng)),
                                       start=start, end=start + dur))
        elif kind == "screenshare":
            pats.append(T.Exfiltration(rng, host, dst, loguniform(rng, 100e3, 2e6), dport=443, profile="chrome", sni="meet.video-conf.com",
                                       start=t0 - 60, end=t_end + 60))
            pats.append(T.Download(rng, host, dst, int(loguniform(rng, 1e6, 20e6)), sni="meet.video-conf.com", profile="chrome", start=t0 + rng.uniform(0, 50), end=t_end))
        elif kind == "partner_sftp":
            prevalence = rng.randint(1, 3)
            size = loguniform(rng, 1e6, 80e6)
            dur = rng.uniform(5, 55)
            start = t0 + rng.uniform(0, 60 - dur)
            pats.append(T.Exfiltration(rng, host, dst, size / dur, dport=22, start=start, end=start + dur))
    recs = _collect(pats, t0, t_end, lead=max(0.0, t0 - min(p.start for p in pats)))

    def seeds(ctx):
        ctx.seed_dst_prevalence(dst, prevalence)
        if baseline[2]:
            ctx.seed_host(host, *baseline)
    cands = [c for c in _run("exfiltration", recs, seeds) if c["entity"]["dst_ip"] == dst]
    return (cands[-1]["features"], {"kind": kind}) if cands else None


GENERATORS = {
    "ddos": ddos_sample,
    "recon_scan": scan_sample,
    "c2_beacon": beacon_sample,
    "dga_domain": dga_sample,
    "dns_tunnel": tunnel_sample,
    "encrypted_malware": tls_sample,
    "exfiltration": exfil_sample,
}


def generate(detector: str, label: str, n: int, seed: int, shift: bool = False, max_tries: int = 6):
    """n labelled rows for one (detector, label). Returns (rows, metas)."""
    rng = random.Random(seed)
    names = FEATURES[detector]
    gen = GENERATORS[detector]
    rows, metas = [], []
    tries = 0
    while len(rows) < n and tries < n * max_tries:
        tries += 1
        out = gen(rng, label, shift)
        if out is None:
            continue
        feats, meta = out
        rows.append([float(feats[k]) for k in names])
        metas.append(meta)
    return rows, metas
