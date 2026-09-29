"""The traffic lab: a simulated estate behind the monitored link.

`Lab` produces a continuous benign background (workstations browsing, NTP, update
checks, telemetry heart-beats, a public web and mail server, backups, calls,
downloads) and injects labelled scenarios on demand. It stands on the *production*
side of the data diode: its only output is a one-way stream of flow records, exactly
what a SPAN/TAP-fed flow exporter would emit.

The same class builds replayable captures (JSONL flow records or PCAP) for the
dashboard's replay panel and for offline evaluation. Each injected scenario is
recorded with its start/end and target so evaluation can score alerts against ground
truth. Nothing here ever contacts a real host; it only generates data.
"""

from __future__ import annotations

import random
import uuid

from . import traffic as T

LAB_EPOCH = 1_758_000_000.0   # fixed start time for generated captures (2025-09-16 UTC)

# Each scenario maps to one problem-statement threat class (a-f) and the lab tool it
# stands in for. `title`/`description` are shown on the dashboard's scenario panel.
SCENARIOS: dict[str, dict] = {
    "syn_flood": {"title": "TCP SYN flood", "tool": "hping3 -S --flood", "ps_ref": "a",
                  "threat_class": "volumetric_ddos", "duration": 40,
                  "description": "Bots send half-open SYNs to the public web server."},
    "spoofed_flood": {"title": "Spoofed-source SYN flood", "tool": "hping3 -S --rand-source", "ps_ref": "a",
                      "threat_class": "volumetric_ddos", "duration": 40,
                      "description": "Every packet from a random forged source address."},
    "udp_flood": {"title": "UDP flood", "tool": "hping3 --udp --flood", "ps_ref": "a",
                  "threat_class": "volumetric_ddos", "duration": 40,
                  "description": "A handful of hosts blast large UDP packets at random ports."},
    "udp_amplification": {"title": "DNS / NTP reflection-amplification", "tool": "reflector set", "ps_ref": "a",
                          "threat_class": "volumetric_ddos", "duration": 40,
                          "description": "Open resolvers / NTP servers reflect oversized replies at the victim."},
    "slowloris": {"title": "Slowloris slow-HTTP exhaustion", "tool": "slowloris", "ps_ref": "a",
                  "threat_class": "volumetric_ddos", "duration": 90,
                  "description": "Many half-sent HTTP requests held open, trickling a header every few seconds."},
    "c2_beacon": {"title": "C2 beaconing", "tool": "sandboxed C2 emulator", "ps_ref": "b",
                  "threat_class": "c2_beaconing", "duration": 120,
                  "description": "An infected workstation checks in over TLS at a regular interval with jitter."},
    "dga": {"title": "DGA domain burst", "tool": "DGArchive-style generator", "ps_ref": "c",
            "threat_class": "dga_dns_tunnelling", "duration": 45,
            "description": "A host walks its domain-generation list; most lookups return NXDOMAIN."},
    "dns_tunnel": {"title": "DNS tunnel", "tool": "dnscat2 / iodine", "ps_ref": "c",
                   "threat_class": "dga_dns_tunnelling", "duration": 60,
                   "description": "Encoded TXT/CNAME/NULL queries to one controlled domain at a high rate."},
    "encrypted_malware": {"title": "Malware C2 over TLS", "tool": "implant TLS stack", "ps_ref": "d",
                          "threat_class": "encrypted_malware", "duration": 90,
                          "description": "An implant opens irregular TLS sessions with its own client stack; no SNI/ALPN."},
    "port_scan": {"title": "Vertical port scan", "tool": "nmap -sS -p1-1024", "ps_ref": "e",
                  "threat_class": "recon_scan", "duration": 30,
                  "description": "An external host SYN-scans a range of ports on the public servers."},
    "host_sweep": {"title": "Horizontal host sweep", "tool": "nmap -sS -p445,3389", "ps_ref": "e",
                   "threat_class": "recon_scan", "duration": 30,
                   "description": "An internal host sweeps the workstation subnet for SMB and RDP."},
    "exfiltration": {"title": "Bulk data exfiltration", "tool": "scripted upload", "ps_ref": "f",
                     "threat_class": "data_exfiltration", "duration": 90,
                     "description": "A workstation uploads a large volume to a never-before-seen external server."},
    "kill_chain": {"title": "Full kill-chain", "tool": "combined", "ps_ref": "b-f",
                   "threat_class": "multiple", "duration": 190,
                   "description": "Recon then C2 beacon, DGA fallback, DNS tunnel and exfiltration in sequence."},
}


class LabNetwork:
    """Fixed addressing for the simulated estate."""

    def __init__(self, n_workstations: int = 48):
        self.workstations = [f"10.10.1.{i}" for i in range(10, 10 + n_workstations)]
        self.web, self.mail, self.vpn = "10.10.2.80", "10.10.2.25", "10.10.2.10"
        self.public_servers = [self.web, self.mail, self.vpn]
        self.resolver = "203.0.113.53"
        self.ntp = T.stable_ip("pool.ntp.org")
        self.update = T.stable_ip("update.os-vendor.com")
        self.telemetry = T.stable_ip("hb.telemetry-hub.com")
        self.backup = T.stable_ip("backup.cloudsync.com")
        self.chat = T.stable_ip("chat.messenger-app.com")
        self.meet = T.stable_ip("meet.video-conf.com")
        self.cdn = T.stable_ip("dl.software-cdn.com")


class Lab:
    """Benign background + injectable labelled scenarios -> flow records."""

    def __init__(self, seed: int | None = None, scale: float = 1.0, n_workstations: int = 48):
        self.rng = random.Random(seed)
        self.scale = scale
        self.net = LabNetwork(n_workstations)
        self.ex = T.Exporter()
        self.background = self._background()
        self.transient: list = []
        self.active: list[dict] = []
        self.history: list[dict] = []
        self._next_event = None

    # ----- benign background ---------------------------------------------
    def _background(self):
        rng, net, s = self.rng, self.net, self.scale
        pats = []
        for h in net.workstations:
            browser = T.weighted_choice(rng, [("chrome", 0.7), ("firefox", 0.2), ("safari", 0.1)])
            pats.append(T.Browsing(rng, h, net.resolver, rate=rng.uniform(0.02, 0.12) * s, browser=browser))
            pats.append(T.PeriodicService(rng, h, net.ntp, 123, interval=rng.choice([64.0, 128.0]), jitter=0.01, proto=17))
            pats.append(T.PeriodicService(rng, h, net.update, 443, interval=rng.uniform(300, 900), jitter=0.1,
                                          profile="schannel", sni="update.os-vendor.com"))
            pats.append(T.PeriodicService(rng, h, net.telemetry, 443, interval=rng.uniform(30, 90), jitter=0.05,
                                          profile="okhttp", sni="hb.telemetry-hub.com"))
            pats.append(T.PeriodicService(rng, h, net.backup, 443, interval=rng.uniform(120, 300), jitter=0.2,
                                          profile="schannel", sni="backup.cloudsync.com"))
            pats.append(T.TelemetryDns(rng, h, net.resolver, rate=0.03 * s))
            pats.append(T.AvLookups(rng, h, net.resolver, rate=0.02 * s))
            if rng.random() < 0.4:
                pats.append(T.PeriodicService(rng, h, net.chat, 443, interval=rng.uniform(25, 60), jitter=0.15,
                                              profile=browser, sni="chat.messenger-app.com"))
        pats.append(T.WebServer(rng, net.web, 40 * s, n_clients=3000, dport=443))
        pats.append(T.WebServer(rng, net.web, 5 * s, n_clients=800, dport=80))
        pats.append(T.WebServer(rng, net.mail, 1.5 * s, n_clients=300, dport=25))
        pats.append(T.UdpService(rng, net.vpn, 1194, 0.5 * s, n_clients=40, req=(60, 1200), resp=(60, 1200), pkts=(20, 400)))
        return pats

    def _spawn_transient(self, t: float):
        """Occasional legitimate bulk traffic: downloads, calls, backups (hard negatives)."""
        rng, net = self.rng, self.net
        if self._next_event is None:
            self._next_event = t + rng.uniform(5, 20)
        while self._next_event <= t:
            at = self._next_event
            self._next_event += rng.expovariate(1 / 25.0)
            h = rng.choice(net.workstations)
            kind = T.weighted_choice(rng, [("download", 0.5), ("call", 0.25), ("backup", 0.25)])
            if kind == "download":
                self.transient.append(T.Download(rng, h, net.cdn, int(T.lognormal_bytes(rng, 20e6, 1.2, 1_000_000, 2_000_000_000)),
                                                 start=at, end=at + 600))
            elif kind == "call":
                self.transient.append(T.VideoCall(rng, h, net.meet, kbps=rng.uniform(800, 2500), start=at,
                                                  end=at + rng.uniform(120, 900)))
            else:
                self.transient.append(T.CloudBackup(rng, h, net.backup, rng.uniform(0.3e6, 4e6), start=at,
                                                    end=at + rng.uniform(60, 300)))

    # ----- scenario injection --------------------------------------------
    def start(self, scenario: str, now: float, duration: float | None = None, intensity: float = 1.0) -> dict:
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {scenario}")
        spec = SCENARIOS[scenario]
        dur = float(duration or spec["duration"])
        rng, net = self.rng, self.net
        host = rng.choice(net.workstations)
        attacker = T.public_ip(rng)
        end = now + dur
        k = max(0.1, intensity)
        pats: list = []
        target = net.web
        if scenario == "syn_flood":
            pats.append(T.SynFlood(rng, net.web, 443, 1500 * k, sources=40, answer_prob=0.6, start=now, end=end))
        elif scenario == "spoofed_flood":
            pats.append(T.SpoofedFlood(rng, net.web, 80, 1200 * k, proto=6, start=now, end=end))
        elif scenario == "udp_flood":
            pats.append(T.UdpIcmpFlood(rng, net.web, 1200 * k, sources=6, proto=17, size=(512, 1400), start=now, end=end))
        elif scenario == "udp_amplification":
            pats.append(T.UdpAmplification(rng, net.web, 900 * k, reflectors=350, service=rng.choice([53, 123, 11211]),
                                           start=now, end=end))
        elif scenario == "slowloris":
            pats.append(T.Slowloris(rng, net.web, 80, conns=int(500 * k), sources=2, start=now, end=end))
        elif scenario == "port_scan":
            pats.append(T.PortScan(rng, attacker, net.public_servers, list(range(1, 1025)), 120 * k, style="vertical",
                                   open_ratio=0.01, start=now, end=end))
            target = ", ".join(net.public_servers)
        elif scenario == "host_sweep":
            pats.append(T.PortScan(rng, host, [f"10.10.1.{i}" for i in range(1, 255)], [445, 3389], 60 * k,
                                   style="horizontal", open_ratio=0.03, start=now, end=end))
            attacker, target = host, "10.10.1.0/24"
        elif scenario == "c2_beacon":
            pats.append(T.Beacon(rng, host, attacker, 443, interval=5.0 / k, jitter=0.1, profile="mal_go_implant",
                                 sni=T.dga_domain(rng, "pronounceable"), start=now, end=end))
            target = host
        elif scenario == "dga":
            pats.append(T.DgaBurst(rng, host, net.resolver, family=rng.choice(["random_alpha", "alnum", "hex"]),
                                   rate=2.5 * k, nx_ratio=0.95, start=now, end=end))
            attacker, target = host, net.resolver
        elif scenario == "dns_tunnel":
            base = "t." + T.dga_domain(rng, "pronounceable")
            pats.append(T.DnsTunnel(rng, host, net.resolver, base=base, style="dnscat", rate=12 * k, start=now, end=end))
            attacker, target = host, base
        elif scenario == "encrypted_malware":
            pats.append(T.MalwareTls(rng, host, attacker, rng.choice(["mal_legacy_ssl", "mal_minimal", "mal_py_implant"]),
                                     sni=None, rate=0.6 * k, start=now, end=end))
            target = host
        elif scenario == "exfiltration":
            pats.append(T.Exfiltration(rng, host, attacker, 3_000_000 * k, dport=443, profile="python", start=now, end=end))
            attacker, target = host, attacker
        elif scenario == "kill_chain":
            c2 = attacker
            pats += [
                T.PortScan(rng, host, [f"10.10.1.{i}" for i in range(1, 255)], [445], 40 * k, style="horizontal",
                           start=now, end=now + 30),
                T.Beacon(rng, host, c2, 443, interval=5.0, jitter=0.12, profile="mal_go_implant",
                         sni=T.dga_domain(rng, "pronounceable"), start=now + 20, end=end),
                T.DgaBurst(rng, host, net.resolver, family="random_alpha", rate=2.0 * k, start=now + 50, end=now + 90),
                T.DnsTunnel(rng, host, net.resolver, base="t." + T.dga_domain(rng, "pronounceable"), style="dnscat",
                            rate=10 * k, start=now + 90, end=now + 140),
                T.Exfiltration(rng, host, T.public_ip(rng), 2_500_000 * k, dport=443, profile="python",
                               start=now + 120, end=end),
            ]
            target = host
        run = {"id": uuid.uuid4().hex[:12], "scenario": scenario, "title": spec["title"], "tool": spec["tool"],
               "ps_ref": spec["ps_ref"], "threat_class": spec["threat_class"], "start": now, "end": end,
               "attacker": attacker, "target": target, "host": host, "intensity": k}
        self.active.append({**run, "patterns": pats})
        self.history.append(run)
        return run

    def stop(self, run_id: str | None = None, now: float | None = None):
        for a in self.active:
            if run_id is None or a["id"] == run_id:
                a["end"] = min(a["end"], now if now is not None else a["end"])
                for p in a["patterns"]:
                    p.end = min(p.end, a["end"])

    # ----- stepping -------------------------------------------------------
    def step(self, t0: float, t1: float) -> list[dict]:
        """Emit every pattern for [t0, t1) and return the flow records exported by t1."""
        self._spawn_transient(t1)
        for p in self.background:
            p.emit(self.ex, t0, t1)
        for p in list(self.transient):
            p.emit(self.ex, t0, t1)
            if p.done(t1):
                self.transient.remove(p)
        for a in list(self.active):
            for p in a["patterns"]:
                p.emit(self.ex, t0, t1)
            if t1 >= a["end"]:
                self.active.remove(a)
        return self.ex.drain(t1)

    def flush(self) -> list[dict]:
        return self.ex.drain_all()

    def ground_truth(self) -> list[dict]:
        """Injected scenarios with their time window and target, for scoring alerts."""
        return [{k: r[k] for k in ("id", "scenario", "ps_ref", "threat_class", "start", "end", "attacker", "target", "host")}
                for r in self.history]


def generate_capture(scenario: str | list[str] | None = "kill_chain", seed: int = 1, warmup: float = 120.0,
                     duration: float | None = None, gap: float = 20.0, scale: float = 1.0,
                     step: float = 1.0, start_time: float = LAB_EPOCH):
    """Build one offline capture: benign warm-up, then the given scenario(s) in sequence.

    Returns (records, ground_truth). Records are event-time ordered flow dicts ready to
    replay, write to PCAP (pcap.write_pcap) or push through a FeaturePipeline.
    """
    lab = Lab(seed=seed, scale=scale)
    scenarios = [scenario] if isinstance(scenario, str) else (scenario or [])
    records: list[dict] = []
    t = start_time
    # warm-up: benign only
    end_warm = t + warmup
    while t < end_warm:
        records += lab.step(t, min(t + step, end_warm))
        t = min(t + step, end_warm)
    # scenarios back to back
    for name in scenarios:
        run = lab.start(name, t)
        seg_end = run["end"] + gap
        while t < seg_end:
            records += lab.step(t, min(t + step, seg_end))
            t = min(t + step, seg_end)
    if duration:
        end_all = start_time + duration
        while t < end_all:
            records += lab.step(t, min(t + step, end_all))
            t = min(t + step, end_all)
    records += lab.flush()
    records.sort(key=lambda r: r["te"])
    return records, lab.ground_truth()
