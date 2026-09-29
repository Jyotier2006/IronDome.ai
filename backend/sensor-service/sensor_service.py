"""IronDome.ai passive sensor service (SIH PS 26145).

The streaming service that implements the problem statement's prototype:
ingest -> feature extraction -> model inference -> alert output, plus the feed for the
dashboard of live or replayed detections. It runs inside the monitoring enclave and is
strictly read-only:

  * Ingest is ONE-DIRECTIONAL. The primary uplink is a receive-only UDP collector (the
    transport data diodes carry): NetFlow v5, NetFlow v9, IPFIX, sFlow v5 or JSON flow
    records are read and nothing is ever sent back. Captures are replayed into the same port with
    scripts/replay_capture.py. A built-in traffic lab can also generate the "simulated IP
    data" in-process for demos.
  * Output is intelligence only: standard alert records (timestamp, flow id, threat
    class, confidence, evidence) over REST and Socket.IO.
  * It issues NO mitigation. There is deliberately no block / isolate / rate-limit
    endpoint - a return path into production is out of scope (PS constraint a).

Run:   python sensor_service.py
Env:   PORT (3001)            REST + Socket.IO for the dashboard
       IRONDOME_UDP_PORT      receive-only flow collector (2055)
       IRONDOME_LAB           on | off   built-in traffic lab (default on)
       IRONDOME_SCALE         background traffic scale for the lab (default 1.0)
       IRONDOME_AUTO_SCENARIOS on | off  inject a random attack every ~2 min (default on)
       IRONDOME_WARM_START    seconds of estate history loaded at start (default 300)
       IRONDOME_INTERNAL_CIDRS protected address space (default RFC1918)
       IRONDOME_WORKERS       detection worker processes (default 0 = run in this process)
       IRONDOME_LAB_JA3       on | off   use the lab's simulated JA3 list (default on; off on real networks)
       IRONDOME_SYSLOG        udp://host:514 | tcp://host:6514  forward incidents to a SIEM (enclave side)
       IRONDOME_SYSLOG_FORMAT cef | json (default cef)
       IRONDOME_KAFKA         broker:9092[,broker2:9092]  publish incidents (needs kafka-python)
       IRONDOME_KAFKA_TOPIC   default irondome.alerts
       IRONDOME_ARCHIVE_DIR   write every alert to a hash-chained, HMAC-signed archive here
       IRONDOME_ARCHIVE_KEY   signing key for the archive (required with IRONDOME_ARCHIVE_DIR)
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import sys
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

import socketio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


def _add_core():
    here = Path(__file__).resolve().parent
    for p in [here, *here.parents]:
        if (p / "irondome" / "__init__.py").exists():
            sys.path.insert(0, str(p))
            return p
    raise RuntimeError("irondome core library not found")


ROOT = _add_core()

from irondome import __version__ as CORE_VERSION  # noqa: E402
from irondome import ipfix, netflow, sflow  # noqa: E402
from irondome.correlate import AlertCorrelator  # noqa: E402
from irondome.features import FEATURE_DOCS, FEATURES, TLS_PORTS, FeaturePipeline  # noqa: E402
from irondome.lab import LAB_EPOCH, SCENARIOS as LAB_SCENARIOS, Lab  # noqa: E402
from irondome.schema import ALERT_JSON_SCHEMA, PROTO_NAMES, THREAT_CLASSES, flow_community_id, normalize_flow  # noqa: E402
from irondome.outputs import SignedArchive, from_env as outputs_from_env  # noqa: E402
from irondome.scoring import LEARNING_SECONDS, MODELS_DIR, ThreatScorer  # noqa: E402
from irondome.sharding import ShardRouter  # noqa: E402

PORT = int(os.environ.get("PORT", 3001))
UDP_PORT = int(os.environ.get("IRONDOME_UDP_PORT", 2055))
LAB_ENABLED = os.environ.get("IRONDOME_LAB", "on").lower() in ("on", "1", "true", "yes")
AUTO_SCENARIOS = os.environ.get("IRONDOME_AUTO_SCENARIOS", "on").lower() in ("on", "1", "true", "yes")
SCALE = float(os.environ.get("IRONDOME_SCALE", "1.0"))
WARM_START_SECONDS = float(os.environ.get("IRONDOME_WARM_START", "300"))
WORKERS = max(0, int(os.environ.get("IRONDOME_WORKERS", "0")))
TICK = 0.5                         # seconds between pipeline evaluations / lab steps
AUTO_SCENARIO_GAP = (80.0, 140.0)  # seconds between auto-injected demo scenarios
THROUGHPUT_TARGET_FPS = 5000       # stated sustained-throughput target (docs/THROUGHPUT.md)


# ---------------------------------------------------------------------------
# Sensor state
# ---------------------------------------------------------------------------
class Sensor:
    """Owns the pipeline, scorer, correlator and rolling dashboard state."""

    def __init__(self):
        self.scorer = ThreatScorer()
        cidrs = os.environ.get("IRONDOME_INTERNAL_CIDRS")
        # With workers, the main process keeps only the shared estate context (no extractors)
        self.router: ShardRouter | None = None
        self.pipeline = FeaturePipeline("sensor", "live", internal_cidrs=cidrs, detectors=[] if WORKERS else None)
        self.outputs: list = []
        self.warming = False
        self.alert_counts: dict[str, int] = {}
        self.alerts_total = 0
        self.suppressed_scan_residue = 0
        self._forwarded_rank: dict[str, int] = {}
        self.correlator = AlertCorrelator(window=90.0)
        self.incidents: deque = deque(maxlen=500)
        self.incident_by_id: dict[str, dict] = {}
        self.recent_flows: deque = deque(maxlen=200)
        self.sources = {
            "lab": {"kind": "built-in traffic lab", "transport": "in-process", "enabled": LAB_ENABLED, "records": 0},
            "udp": {"kind": "flow collector (NetFlow v5/v9, IPFIX, sFlow, JSON)",
                    "transport": f"UDP/{UDP_PORT} receive-only", "enabled": True, "records": 0, "datagrams": 0,
                    "errors": 0, "exporters": {},
                    "formats": {"json": 0, "netflow_v5": 0, "netflow_v9": 0, "ipfix": 0, "sflow": 0}},
            "http": {"kind": "REST flow upload", "transport": "HTTP POST /api/ingest/flows", "enabled": True, "records": 0},
        }
        self.detector_modes = {d: self.scorer.models[d].mode for d in self.scorer.models}
        self.latencies: deque = deque(maxlen=500)
        self.reset_counters()

    def reset_counters(self):
        """Zero the dashboard traffic counters (pipeline state and estate context are kept)."""
        self.flow_count = self.byte_count = self.packet_count = 0
        self.encrypted_flows = self.handshake_flows = self.dns_flows = 0
        self.encrypted_bytes = 0
        self.proto_mix: dict[str, int] = {}
        self.recent_flows.clear()
        self.window_flows = self.window_bytes = self.window_pkts = 0
        self.window_since = time.time()
        self.started = time.time()
        self.peak_fps = 0.0
        for s in self.sources.values():
            s["records"] = 0

    # ----- ingest ---------------------------------------------------------
    def ingest(self, rec: dict, wall: float, source: str) -> dict | None:
        norm = normalize_flow(rec, now=wall)
        if norm is None:
            return None
        self.pipeline.ingest(norm, wall)
        if self.router is not None and not self.warming and norm["te"] >= wall - self.pipeline.LATE_HORIZON:
            self.router.route(norm, wall, self.pipeline.ctx)
        self.sources[source]["records"] += 1
        self.flow_count += 1
        self.window_flows += 1
        b = norm["bytes_fwd"] + norm["bytes_bwd"]
        p = norm["pkts_fwd"] + norm["pkts_bwd"]
        self.byte_count += b
        self.packet_count += p
        self.window_bytes += b
        self.window_pkts += p
        pn = PROTO_NAMES.get(norm["proto"], str(norm["proto"]))
        self.proto_mix[pn] = self.proto_mix.get(pn, 0) + 1
        # encrypted = TLS/QUIC by port or by an observed handshake; the handshake share is
        # the subset where JA3/JA4/SNI metadata was captured (what fingerprinting can use)
        handshake = "tls" in norm or "quic" in norm
        dport = norm["dst_port"]
        if handshake or (norm["proto"] == 6 and dport in TLS_PORTS) or (norm["proto"] == 17 and dport == 443):
            self.encrypted_flows += 1
            self.encrypted_bytes += b
        if handshake:
            self.handshake_flows += 1
        if "dns" in norm:
            self.dns_flows += 1
        if self.flow_count % 4 == 0 or ("dns" in norm and self.flow_count % 2 == 0):
            self.recent_flows.appendleft(_flow_summary(norm))
        return norm

    # ----- detection --------------------------------------------------------
    def evaluate(self, wall: float):
        """Score new candidates and correlate them into incidents."""
        if self.router is not None:
            self.router.flush()
            alerts = self.router.collect()
        else:
            cands = self.pipeline.evaluate(now_wall=wall)
            alerts = self.scorer.score_many(cands, source={"pipeline": "sensor", "mode": "live"}) if cands else []
        return self.handle_alerts(alerts, wall) if alerts else ([], [])

    SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    def handle_alerts(self, alerts: list, wall: float):
        """Correlate alerts into incidents, archive every alert, forward new / escalated incidents."""
        new_inc, upd_inc = [], []
        for a in alerts:
            ev_ctx = (a.get("evidence") or {}).get("context") or {}
            if a["threat_class"] == "recon_scan" and a.get("entity", {}).get("ip"):
                self.scorer.note_scanner(a["entity"]["ip"])
            elif (a.get("technique") == "syn_flood" and self.router is not None
                  and self.scorer.scan_residue({"context": ev_ctx})):
                self.suppressed_scan_residue += 1     # the scanner was flagged by another worker
                continue
            if "latency_ms" in a:
                self.latencies.append(a["latency_ms"])
            self.alerts_total += 1
            self.alert_counts[a["threat_class"]] = self.alert_counts.get(a["threat_class"], 0) + 1
            for o in self.outputs:
                if isinstance(o, SignedArchive):
                    o.append(a)
            inc, is_new = self.correlator.add(a, now=wall)
            pub = AlertCorrelator._public(inc)
            self.incident_by_id[pub["incident_id"]] = pub
            rank = self.SEVERITY_RANK.get(pub.get("severity"), 0)
            if is_new or rank > self._forwarded_rank.get(pub["incident_id"], -1):
                self._forwarded_rank[pub["incident_id"]] = rank
                for o in self.outputs:
                    if not isinstance(o, SignedArchive):
                        o.send(pub)
                if len(self._forwarded_rank) > 20_000:
                    self._forwarded_rank.pop(next(iter(self._forwarded_rank)))
            if is_new:
                self.incidents.appendleft(pub)
                new_inc.append(pub)
            else:
                for i, existing in enumerate(self.incidents):
                    if existing["incident_id"] == pub["incident_id"]:
                        self.incidents[i] = pub
                        break
                upd_inc.append(pub)
        return new_inc, upd_inc

    def shed(self) -> int:
        if self.router is None:
            return self.pipeline.shed()
        return self.router.stats["shed_flows"] + sum(w.get("shed", 0) for w in self.router.worker_stats.values())

    def scale_info(self) -> dict:
        if self.router is None:
            return {"workers": 0, "mode": "single process"}
        return {"workers": self.router.n, "alive": self.router.alive(), "mode": "sharded",
                "routed": self.router.stats["routed"], "shed_flows": self.router.stats["shed_flows"],
                "per_worker": {str(k): v for k, v in sorted(self.router.worker_stats.items())}}

    def latency_stats(self) -> dict:
        xs = sorted(self.latencies)
        if not xs:
            return {"p50_ms": None, "p95_ms": None, "max_ms": None, "samples": 0}
        return {"p50_ms": xs[len(xs) // 2], "p95_ms": xs[min(len(xs) - 1, int(len(xs) * 0.95))],
                "max_ms": xs[-1], "samples": len(xs)}

    def flow_stats(self) -> dict:
        now = time.time()
        dt = max(1e-3, now - self.window_since)
        fps = self.window_flows / dt
        self.peak_fps = max(self.peak_fps, fps)
        stats = {
            "ts": now,
            "flows_per_s": round(fps, 1),
            "pkts_per_s": round(self.window_pkts / dt, 0),
            "mbps": round(self.window_bytes * 8 / 1e6 / dt, 2),
            "total_flows": self.flow_count,
            "total_bytes": self.byte_count,
            "peak_flows_per_s": round(self.peak_fps, 1),
            "target_flows_per_s": THROUGHPUT_TARGET_FPS,
            "encrypted_share": round(self.encrypted_flows / max(1, self.flow_count), 3),
            "encrypted_byte_share": round(self.encrypted_bytes / max(1, self.byte_count), 3),
            "handshake_share": round(self.handshake_flows / max(1, self.flow_count), 3),
            "dns_share": round(self.dns_flows / max(1, self.flow_count), 3),
            "protocol_mix": dict(self.proto_mix),
            "latency": self.latency_stats(),
            "context_age_s": round(self.pipeline.context_age(), 0),
            "baseline_learning": self.pipeline.context_age() < LEARNING_SECONDS,
            "watermark_lag_ms": round(max(0.0, now - self.pipeline.watermark) * 1000, 0) if self.pipeline.watermark else None,
            "open_incidents": len(self.correlator.open),
            "shed": self.shed(),
            "workers": self.router.n if self.router else 0,
            "uptime_s": round(now - self.started, 0),
        }
        self.window_flows = self.window_bytes = self.window_pkts = 0
        self.window_since = now
        return stats

    def summary(self) -> dict:
        return {
            "flows": self.flow_count,
            "bytes": self.byte_count,
            "packets": self.packet_count,
            "candidates": (self.scorer.stats["candidates"] if self.router is None else
                           sum(w.get("candidates", 0) for w in self.router.worker_stats.values())),
            "alerts_raw": self.alerts_total,
            "incidents": self.correlator.stats["incidents"],
            "alerts_by_class": dict(self.alert_counts),
            "suppressed_scan_residue": self.scorer.stats["suppressed_scan_residue"] + self.suppressed_scan_residue + (
                sum(w.get("suppressed_scan_residue", 0) for w in self.router.worker_stats.values()) if self.router else 0),
            "detector_modes": self.detector_modes,
            "latency": self.latency_stats(),
            "shed": self.shed(),
            "scale": self.scale_info(),
            "outputs": outputs_status(),
            "threat_intel": self.scorer.intel_sources,
            "uptime_s": round(time.time() - self.started, 0),
        }


def _flow_summary(rec: dict) -> dict:
    s = {
        "flow_id": flow_community_id(rec),
        "ts": rec["te"],
        "src_ip": rec["src_ip"], "src_port": rec["src_port"],
        "dst_ip": rec["dst_ip"], "dst_port": rec["dst_port"],
        "proto": PROTO_NAMES.get(rec["proto"], str(rec["proto"])),
        "bytes": rec["bytes_fwd"] + rec["bytes_bwd"],
        "pkts": rec["pkts_fwd"] + rec["pkts_bwd"],
        "flags": rec.get("flags_fwd", ""),
    }
    if "dns" in rec:
        s["dns"] = {"qname": rec["dns"]["qname"], "qtype": rec["dns"]["qtype"], "rcode": rec["dns"]["rcode"]}
    if "tls" in rec:
        t = rec["tls"]
        s["tls"] = {k: t.get(k, "") for k in ("sni", "ja3", "ja4", "version")}
    if "quic" in rec:
        s["quic"] = True
    return s


# ---------------------------------------------------------------------------
# Receive-only UDP collector
# ---------------------------------------------------------------------------
class FlowCollector(asyncio.DatagramProtocol):
    """Reads flow exports. It holds no reference to the transport's send path and never
    replies - the exporter gets nothing back, exactly as through a data diode."""

    def __init__(self, sensor: "Sensor"):
        self.sensor = sensor
        self.templates = ipfix.TemplateDecoder()      # IPFIX / NetFlow v9 template cache
        self.sflow = sflow.SflowDecoder(sensor="sflow")

    def sweep(self, wall: float):
        """sFlow flows complete on idle / active timeouts, not on arrival: export them."""
        for rec in self.sflow.sweep(wall):
            self.sensor.ingest(rec, wall, "udp")

    def datagram_received(self, data: bytes, addr):
        src = self.sensor.sources["udp"]
        src["datagrams"] += 1
        exporter = addr[0]
        src["exporters"][exporter] = src["exporters"].get(exporter, 0) + 1
        if len(src["exporters"]) > 64:
            src["exporters"].pop(next(iter(src["exporters"])))
        wall = time.time()
        fmts = src["formats"]
        try:
            if netflow.is_netflow_v5(data):
                fmts["netflow_v5"] += 1
                records = netflow.decode(data, sensor=f"netflow:{exporter}")
            elif ipfix.is_ipfix(data):
                fmts["ipfix"] += 1
                records = self.templates.decode(data, exporter)
            elif ipfix.is_netflow_v9(data):
                fmts["netflow_v9"] += 1
                records = self.templates.decode(data, exporter)
            elif sflow.is_sflow_v5(data):
                fmts["sflow"] += 1
                records = self.sflow.decode(data, wall, exporter)
            else:
                fmts["json"] += 1
                text = data.decode("utf-8").strip()
                if text.startswith("["):
                    records = json.loads(text)
                elif "\n" in text:
                    records = [json.loads(line) for line in text.splitlines() if line.strip()]
                else:
                    records = [json.loads(text)]
        except (ValueError, UnicodeDecodeError):
            src["errors"] += 1
            return
        for rec in records:
            if isinstance(rec, dict):
                self.sensor.ingest(rec, wall, "udp")

    def error_received(self, exc):   # pragma: no cover - logged, never answered
        self.sensor.sources["udp"]["errors"] += 1


# ---------------------------------------------------------------------------
# Socket.IO + FastAPI
# ---------------------------------------------------------------------------
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*", logger=False, engineio_logger=False)
sensor = Sensor()
lab: Lab | None = None
collector: FlowCollector | None = None
lab_clock = {"t": LAB_EPOCH}
lab_runs: deque = deque(maxlen=50)
clients: set[str] = set()


def threat_catalog() -> list[dict]:
    return [{"id": key, "ps_ref": tc["ps_ref"], "label": tc["label"], "summary": tc["summary"],
             "base_severity": tc["base_severity"],
             "techniques": [{"id": tk, "label": tv["label"], "mitre": tv["mitre"]} for tk, tv in tc["techniques"].items()],
             "recommended_action": tc["action"]}
            for key, tc in THREAT_CLASSES.items()]


def scenario_catalog() -> list[dict]:
    return [{"id": k, **v} for k, v in LAB_SCENARIOS.items()]


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def model_cards() -> dict:
    card = _load_json(MODELS_DIR / "model_card.json") or {}
    slim = {}
    for det, c in (card.get("detectors") or {}).items():
        slim[det] = {k: v for k, v in c.items() if k != "baselines"}
    return {k: v for k, v in card.items() if k != "detectors"} | {"detectors": slim}


def sources_payload() -> list[dict]:
    out = []
    for key, s in sensor.sources.items():
        item = {"id": key, **{k: v for k, v in s.items() if k != "exporters"}}
        if key == "udp":
            item["exporters"] = len(s["exporters"])
        out.append(item)
    return out


def hello_payload() -> dict:
    return {
        "service": "irondome-sensor", "core_version": CORE_VERSION,
        "read_only": True, "issues_mitigation": False, "decrypts_payload": False,
        "ingest": {"udp_port": UDP_PORT, "lab": LAB_ENABLED},
        "learning_seconds": LEARNING_SECONDS,
        "throughput_target_fps": THROUGHPUT_TARGET_FPS,
        "threat_classes": threat_catalog(),
        "scenarios": scenario_catalog(),
        "detector_modes": sensor.detector_modes,
        "sources": sources_payload(),
        "stats": sensor.summary(),
        "active_runs": [r for r in lab_runs if r.get("end_wall", 0) > time.time()],
    }


@sio.event
async def connect(sid, environ):
    clients.add(sid)
    await sio.emit("hello", hello_payload(), to=sid)
    await sio.emit("incidents_snapshot", list(sensor.incidents)[:100], to=sid)
    await sio.emit("flows_snapshot", list(sensor.recent_flows)[:60], to=sid)


@sio.event
async def disconnect(sid):
    clients.discard(sid)


async def _emit(new_inc, upd_inc):
    for inc in new_inc:
        await sio.emit("alert", inc)
    for inc in upd_inc:
        await sio.emit("alert_update", {"incident_id": inc["incident_id"], "occurrences": inc["occurrences"],
                                        "last_seen": inc.get("last_seen"), "confidence": inc["confidence"],
                                        "severity": inc["severity"], "related_flow_ids": inc.get("related_flow_ids", [])[:16]})


def _run_public(run: dict) -> dict:
    return {k: run[k] for k in ("id", "scenario", "title", "tool", "ps_ref", "threat_class", "attacker", "target", "host",
                                "intensity") if k in run}


def _start_run(name: str, intensity: float = 1.0, duration: float | None = None) -> dict:
    run = lab.start(name, lab_clock["t"], duration=duration, intensity=intensity)
    pub = _run_public(run)
    pub["start_wall"] = time.time()
    pub["end_wall"] = time.time() + (run["end"] - run["start"])
    lab_runs.appendleft(pub)
    return pub


def _warm_start():
    """Replay recent estate history so prevalence and baselines are mature before going live,
    as a deployed sensor would replay the last hour of flow logs after a restart. Windows
    produced by the history are drained without scoring, so warm-up never raises alerts."""
    now = time.time()
    t = LAB_EPOCH
    sensor.warming = True
    while t < LAB_EPOCH + WARM_START_SECONDS:
        for rec in lab.step(t, t + 1.0):
            rec["ts"] = now - WARM_START_SECONDS + (rec["ts"] - LAB_EPOCH)
            rec["te"] = now - WARM_START_SECONDS + (rec["te"] - LAB_EPOCH)
            sensor.ingest(rec, now, "lab")
        t += 1.0
    sensor.pipeline.evaluate(now_wall=now)
    sensor.warming = False
    if sensor.router is not None:
        sensor.router.first_event = sensor.pipeline.first_event
    sensor.reset_counters()
    lab_clock["t"] = t
    print(f"warm start: {WARM_START_SECONDS:.0f}s of estate history loaded "
          f"(context age {sensor.pipeline.context_age():.0f}s)", flush=True)


async def pump():
    """Main loop: step the lab (if enabled), evaluate the pipeline, stream results."""
    rng = random.Random()
    last_stats = 0.0
    next_auto = time.time() + 20.0
    while True:
        wall = time.time()
        if lab is not None:
            t = lab_clock["t"]
            for rec in lab.step(t, t + TICK):
                # map lab event time onto the wall clock so the live watermark applies
                rec["ts"] = wall - (t + TICK - rec["ts"])
                rec["te"] = wall - (t + TICK - rec["te"])
                sensor.ingest(rec, wall, "lab")
            lab_clock["t"] = t + TICK
            if AUTO_SCENARIOS and wall >= next_auto and not lab.active:
                pub = _start_run(rng.choice([s for s in LAB_SCENARIOS if s != "kill_chain"]),
                                 intensity=rng.uniform(0.9, 1.3))
                await sio.emit("scenario", {"event": "start", "auto": True, **pub})
                next_auto = wall + rng.uniform(*AUTO_SCENARIO_GAP)
        new_inc, upd_inc = sensor.evaluate(wall)
        if new_inc or upd_inc:
            await _emit(new_inc, upd_inc)
        if wall - last_stats >= 1.0:
            await sio.emit("flow_stats", sensor.flow_stats())
            await sio.emit("flows_batch", list(sensor.recent_flows)[:25])
            sensor.correlator.expire(wall)
            if collector is not None:
                collector.sweep(wall)
            last_stats = wall
        await asyncio.sleep(max(0.0, TICK - (time.time() - wall)))


@asynccontextmanager
async def lifespan(app: FastAPI):
    global lab, collector
    print(f"IronDome.ai sensor {CORE_VERSION} - detectors {sensor.detector_modes}", flush=True)
    loop = asyncio.get_running_loop()
    import socket as _socket
    usock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    usock.setsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF, 16 * 1024 * 1024)   # absorb export bursts
    usock.bind(("0.0.0.0", UDP_PORT))
    collector = FlowCollector(sensor)
    transport, _ = await loop.create_datagram_endpoint(lambda: collector, sock=usock)
    if WORKERS:
        sensor.router = ShardRouter(WORKERS, os.environ.get("IRONDOME_INTERNAL_CIDRS"), tick=TICK / 2)
        print(f"scale-out: {WORKERS} detection worker processes (shared estate context in this process)", flush=True)
    try:
        sensor.outputs = outputs_from_env()
    except (ValueError, RuntimeError, OSError) as e:
        print(f"alert outputs disabled: {e}", flush=True)
    for o in sensor.outputs:
        print(f"alert output: {o.describe}", flush=True)
    print(f"receive-only flow collector on UDP/{UDP_PORT}; dashboard API on :{PORT}; lab={'on' if LAB_ENABLED else 'off'}",
          flush=True)
    if LAB_ENABLED:
        lab = Lab(seed=None, scale=SCALE)
        await asyncio.to_thread(_warm_start)
    task = asyncio.create_task(pump())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    transport.close()
    for o in sensor.outputs:
        o.close()
    if sensor.router is not None:
        sensor.router.close()


app = FastAPI(title="IronDome.ai Sensor", version=CORE_VERSION, lifespan=lifespan,
              description="Read-only passive threat-detection sensor for unidirectional IP traffic (SIH PS 26145)")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["GET", "POST"],
                   allow_headers=["*"])


class FlowBatch(BaseModel):
    flows: list[dict] = Field(default_factory=list, description="Biflow records (see irondome/schema.py)")
    sensor: str | None = None


class ScenarioRequest(BaseModel):
    scenario: str
    intensity: float = 1.0
    duration: float | None = None


def outputs_status() -> list[dict]:
    return [{"output": o.describe, **o.stats} for o in sensor.outputs]


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "sensor", "read_only": True, "issues_mitigation": False,
            "core_version": CORE_VERSION, "detectors": sensor.detector_modes, "clients": len(clients),
            "udp_port": UDP_PORT, "lab": LAB_ENABLED, "scale": sensor.scale_info(), "outputs": outputs_status()}


@app.get("/api/overview")
async def api_overview():
    return hello_payload()


@app.get("/api/threat-classes")
async def api_threat_classes():
    return {"threat_classes": threat_catalog()}


@app.get("/api/scenarios")
async def api_scenarios():
    return {"scenarios": scenario_catalog(), "runs": list(lab_runs)}


@app.get("/api/schema/alert")
async def api_schema():
    return ALERT_JSON_SCHEMA


@app.get("/api/features")
async def api_features():
    return {d: [{"name": n, "description": FEATURE_DOCS.get(n, "")} for n in FEATURES[d]] for d in FEATURES}


@app.get("/api/models")
async def api_models():
    return model_cards()


@app.get("/api/evaluation")
async def api_evaluation():
    return _load_json(MODELS_DIR / "eval_results.json") or {}


@app.get("/api/sources")
async def api_sources():
    return {"sources": sources_payload()}


@app.get("/api/alerts")
async def api_alerts(limit: int = 100, threat_class: str | None = None):
    items = list(sensor.incidents)
    if threat_class:
        items = [a for a in items if a["threat_class"] == threat_class]
    return {"incidents": items[:limit], "count": len(items)}


@app.get("/api/alerts/{incident_id}")
async def api_alert(incident_id: str):
    inc = sensor.incident_by_id.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")
    return inc


@app.get("/api/stats")
async def api_stats():
    return sensor.summary()


@app.get("/api/flows/recent")
async def api_flows(limit: int = 60):
    return {"flows": list(sensor.recent_flows)[:limit]}


@app.post("/api/ingest/flows")
async def api_ingest(batch: FlowBatch):
    """Convenience upload of flow records. The diode-faithful uplink is the UDP collector."""
    wall = time.time()
    n = 0
    for rec in batch.flows:
        if batch.sensor and "sensor" not in rec:
            rec["sensor"] = batch.sensor
        if sensor.ingest(rec, wall, "http") is not None:
            n += 1
    return {"ingested": n}


@app.post("/api/scenario")
async def api_scenario(req: ScenarioRequest):
    """Demo control for the built-in traffic lab: inject a labelled attack scenario into the
    *simulated traffic source*. This drives the lab that stands in for the production
    network; the sensor itself still only observes."""
    if lab is None:
        raise HTTPException(status_code=409, detail="built-in traffic lab is off (IRONDOME_LAB=off)")
    if req.scenario not in LAB_SCENARIOS:
        raise HTTPException(status_code=400, detail=f"unknown scenario; choose from {list(LAB_SCENARIOS)}")
    pub = _start_run(req.scenario, intensity=max(0.2, min(3.0, req.intensity)), duration=req.duration)
    await sio.emit("scenario", {"event": "start", "auto": False, **pub})
    return {"started": pub}


socket_app = socketio.ASGIApp(sio, app)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(socket_app, host="0.0.0.0", port=PORT, reload=False, log_level="warning")
