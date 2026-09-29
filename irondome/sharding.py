"""Scale-out: run the detection pipeline across several worker processes.

One Python process sustains about 5,000 flows/s. With IRONDOME_WORKERS=N the sensor
keeps ingest, correlation and the API in the main process and runs feature extraction
and model inference in N worker processes:

  * Partitioning. Most detectors reason about one *protected host* (a DDoS victim, a
    beaconing or exfiltrating workstation, a host's DNS and TLS sessions), so each flow
    goes to the worker that owns its internal host. Scan detection reasons about the
    *initiator* (a sweep touches many hosts), so the flow is also routed by source
    address to the worker that owns that scanner. A flow therefore reaches at most two
    workers, and every detector sees everything it needs for its entity.
  * Shared estate context. Prevalence ("how many internal hosts talk to this
    destination / use this JA3 in the last hour") spans all hosts, so no single worker
    can compute it. The main process keeps the one estate-context store (it sees every
    flow), and each routed flow carries the current global prevalence values, which the
    worker adopts. Host baselines are per host and live with the host's worker. The
    main process also sends the estate's context age, so the learning-period gate
    behaves exactly as in a single process.
  * Alerts flow back over a queue into the main process, which correlates them into
    incidents and applies cross-worker rules (a SYN flood whose half-open traffic comes
    from a source another worker flagged as a scanner is dropped).

Workers are started with the "spawn" method and exchange batches through bounded
queues; if a worker falls behind, whole batches are shed and counted, never blocking
ingest.
"""

from __future__ import annotations

import multiprocessing as mp
import queue
import time
import zlib

from .features import FeaturePipeline
from .netutil import AddressClassifier

HOST_DETECTORS = ["ddos", "c2_beacon", "dga_domain", "dns_tunnel", "encrypted_malware", "exfiltration"]
SCAN_DETECTORS = ["recon_scan"]
BATCH = 256
FLUSH_INTERVAL = 0.1   # s: bounded queueing delay added by routing


def _slot(key: str, n: int) -> int:
    return zlib.crc32(key.encode()) % n


def worker_main(wid: int, inq, outq, internal_cidrs, tick: float):
    from .scoring import ThreatScorer
    host = FeaturePipeline(f"worker{wid}", "live", internal_cidrs, detectors=HOST_DETECTORS)
    scan = FeaturePipeline(f"worker{wid}-scan", "live", internal_cidrs, detectors=SCAN_DETECTORS)
    scorer = ThreatScorer()
    source = {"pipeline": "sensor", "mode": "live", "worker": wid}
    next_eval = time.time() + tick
    next_stats = time.time() + 1.0
    ingested = 0
    while True:
        timeout = max(0.005, next_eval - time.time())
        try:
            msg = inq.get(timeout=timeout)
        except queue.Empty:
            msg = {}
        if msg is None:
            break
        if msg:
            fe = msg.get("first_event")
            for p in (host, scan):
                if fe is not None and (p.first_event is None or fe < p.first_event):
                    p.first_event = fe
            ctx = host.ctx
            for rec in msg["records"]:
                role, wall, dst_prev, ja3_prev = rec.pop("_route")
                if dst_prev is not None:
                    ctx.seeded_dst[rec["dst_ip"]] = dst_prev
                if ja3_prev is not None:
                    ctx.seeded_ja3[rec["tls"]["ja3"]] = ja3_prev
                if role != "scan":
                    host.ingest(rec, wall)
                if role != "host":
                    scan.ingest(rec, wall)
                ingested += 1
            if len(ctx.seeded_dst) > 200_000:
                ctx.seeded_dst.clear()
            if len(ctx.seeded_ja3) > 50_000:
                ctx.seeded_ja3.clear()
        now = time.time()
        if now >= next_eval:
            cands = host.evaluate(now_wall=now) + scan.evaluate(now_wall=now)
            if cands:
                alerts = scorer.score_many(cands, source=source)
                if alerts:
                    outq.put(("alerts", wid, alerts))
            next_eval = now + tick
        if now >= next_stats:
            outq.put(("stats", wid, {"records": ingested, "late": host.late + scan.late,
                                     "shed": host.shed() + scan.shed(),
                                     "candidates": sum(host.candidates.values()) + sum(scan.candidates.values()),
                                     "suppressed_scan_residue": scorer.stats["suppressed_scan_residue"]}))
            next_stats = now + 2.0


class ShardRouter:
    """Main-process side: routes flows to workers and collects their alerts."""

    def __init__(self, workers: int, internal_cidrs: str | None = None, tick: float = 0.5):
        spawn = mp.get_context("spawn")
        self.n = workers
        self.addr = AddressClassifier(internal_cidrs)
        self.inq = [spawn.Queue(maxsize=512) for _ in range(workers)]
        self.outq = spawn.Queue()
        self.procs = [spawn.Process(target=worker_main, args=(i, self.inq[i], self.outq, internal_cidrs, tick),
                                    name=f"irondome-worker-{i}", daemon=True) for i in range(workers)]
        for p in self.procs:
            p.start()
        self.buf: list[list] = [[] for _ in range(workers)]
        self.first_event = None
        self.last_flush = 0.0
        self.worker_stats: dict[int, dict] = {}
        self.stats = {"routed": 0, "shed_batches": 0, "shed_flows": 0}

    def route(self, rec: dict, wall: float, ctx):
        """`ctx` is the main process's estate-context store (already updated with rec)."""
        src, dst = rec["src_ip"], rec["dst_ip"]
        s_in, d_in = self.addr.is_internal(src), self.addr.is_internal(dst)
        tls = rec.get("tls")
        ja3 = tls.get("ja3") if tls else None
        dst_prev = ctx.dst_prevalence(dst, rec["te"]) if s_in and not d_in else None
        ja3_prev = ctx.ja3_prevalence(ja3, rec["te"]) if ja3 else None
        owner = _slot(src if s_in else (dst if d_in else src), self.n)
        scanner = _slot(src, self.n)
        if self.first_event is None or rec["ts"] < self.first_event:
            self.first_event = rec["ts"]
        if owner == scanner:
            rec["_route"] = ("both", wall, dst_prev, ja3_prev)
            self._push(owner, rec)
        else:
            copy = dict(rec)
            rec["_route"] = ("host", wall, dst_prev, ja3_prev)
            copy["_route"] = ("scan", wall, None, None)
            self._push(owner, rec)
            self._push(scanner, copy)
        self.stats["routed"] += 1
        if wall - self.last_flush >= FLUSH_INTERVAL:
            self.flush()

    def _push(self, i, rec):
        b = self.buf[i]
        b.append(rec)
        if len(b) >= BATCH:
            self._send(i)

    def _send(self, i):
        b = self.buf[i]
        if not b:
            return
        try:
            self.inq[i].put_nowait({"first_event": self.first_event, "records": b})
        except queue.Full:
            self.stats["shed_batches"] += 1
            self.stats["shed_flows"] += len(b)
        self.buf[i] = []

    def flush(self):
        self.last_flush = time.time()
        for i in range(self.n):
            self._send(i)

    def collect(self) -> list[dict]:
        alerts = []
        while True:
            try:
                kind, wid, payload = self.outq.get_nowait()
            except queue.Empty:
                break
            if kind == "alerts":
                alerts += payload
            else:
                self.worker_stats[wid] = payload
        return alerts

    def alive(self) -> int:
        return sum(p.is_alive() for p in self.procs)

    def close(self):
        for q in self.inq:
            try:
                q.put_nowait(None)
            except queue.Full:
                pass
        for p in self.procs:
            p.join(timeout=3)
            if p.is_alive():
                p.terminate()
