"""Alert outputs inside the monitoring enclave: SIEM forwarding and a signed archive.

These outputs carry *intelligence* to analysts' systems on the enclave side of the
diode (SIEM, message bus, evidence store). They never touch the production network the
sensor observes, so the no-return-path rule (PS constraint a) is unaffected. Configure
them with environment variables (see backend/sensor-service/sensor_service.py).

    SyslogForwarder   RFC 5424 syslog over UDP or TCP (RFC 6587 octet counting), with an
                      ArcSight CEF or JSON payload - understood by Splunk, QRadar, ArcSight,
                      Elastic, Wazuh, Graylog...
    KafkaForwarder    JSON messages to a Kafka topic (needs the optional kafka-python package)
    SignedArchive     append-only, daily JSONL files in which every record carries the
                      SHA-256 of the previous record (hash chain) and an HMAC-SHA256 over its
                      own hash: deleting, reordering or editing any record breaks verification
                      (scripts/verify_archive.py)

Forwarders run on a background thread with a bounded queue: a slow or unreachable SIEM
drops (and counts) messages instead of ever stalling detection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

VENDOR, PRODUCT, VERSION = "IronDome.ai", "Passive Sensor", "2.0"
_SYSLOG_SEVERITY = {"critical": 2, "high": 3, "medium": 4, "low": 5}   # RFC 5424 crit/err/warning/notice
_CEF_SEVERITY = {"critical": 10, "high": 8, "medium": 5, "low": 3}
_FACILITY_LOCAL0 = 16


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------
def _cef_header(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|")


def _cef_ext(v) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", " ")


def to_cef(a: dict) -> str:
    f = a.get("flow", {})
    ext = {
        "rt": int(datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00")).timestamp() * 1000),
        "src": f.get("src_ip", ""), "spt": f.get("src_port", ""), "dst": f.get("dst_ip", ""), "dpt": f.get("dst_port", ""),
        "proto": f.get("protocol", ""), "cat": a.get("threat_class", ""),
        "cs1Label": "technique", "cs1": a.get("technique", ""),
        "cs2Label": "flowId", "cs2": a.get("flow_id", ""),
        "cs3Label": "psRef", "cs3": a.get("ps_ref", ""),
        "cs4Label": "mitre", "cs4": ",".join(a.get("mitre_attack", [])),
        "cfp1Label": "confidence", "cfp1": a.get("confidence", ""),
        "cnt": a.get("occurrences", 1), "externalId": a.get("alert_id", ""),
        "msg": a.get("description", ""),
    }
    head = "|".join(_cef_header(x) for x in ("CEF:0", VENDOR, PRODUCT, VERSION,
                                               f"{a.get('threat_class')}:{a.get('technique')}",
                                               a.get("technique_label") or a.get("technique", ""),
                                               _CEF_SEVERITY.get(a.get("severity"), 5)))
    return head + "|" + " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v != "")


def to_syslog(a: dict, payload: str, hostname: str | None = None) -> str:
    pri = _FACILITY_LOCAL0 * 8 + _SYSLOG_SEVERITY.get(a.get("severity"), 4)
    host = (hostname or socket.gethostname() or "-").replace(" ", "_")[:255]
    return f"<{pri}>1 {a.get('timestamp', '-')} {host} irondome - {a.get('threat_class', '-')} - {payload}"


# ---------------------------------------------------------------------------
# Forwarders
# ---------------------------------------------------------------------------
class _Background:
    def __init__(self, maxsize: int = 10_000):
        self.q: queue.Queue = queue.Queue(maxsize=maxsize)
        self.stats = {"queued": 0, "sent": 0, "dropped": 0, "errors": 0}
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._run, name=type(self).__name__, daemon=True)
        self.thread.start()

    def send(self, alert: dict):
        try:
            self.q.put_nowait(alert)
            self.stats["queued"] += 1
        except queue.Full:
            self.stats["dropped"] += 1

    def _run(self):
        while not self._stop.is_set():
            try:
                alert = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._deliver(alert)
                self.stats["sent"] += 1
            except Exception:   # never let an output failure reach the pipeline
                self.stats["errors"] += 1

    def close(self, timeout: float = 2.0):
        deadline = time.time() + timeout
        while not self.q.empty() and time.time() < deadline:
            time.sleep(0.05)
        self._stop.set()

    def _deliver(self, alert: dict):  # pragma: no cover - overridden
        raise NotImplementedError


class SyslogForwarder(_Background):
    """`url` like udp://10.0.5.20:514 or tcp://siem.enclave:6514 ; fmt = cef | json."""

    def __init__(self, url: str, fmt: str = "cef", hostname: str | None = None):
        scheme, _, rest = url.partition("://")
        host, _, port = rest.rpartition(":")
        if scheme not in ("udp", "tcp") or not host or not port.isdigit():
            raise ValueError(f"syslog target must look like udp://host:514 or tcp://host:6514, got {url!r}")
        if fmt not in ("cef", "json"):
            raise ValueError("syslog format must be cef or json")
        self.scheme, self.addr, self.fmt, self.hostname = scheme, (host, int(port)), fmt, hostname
        self.sock = None
        self.describe = f"syslog {fmt.upper()} -> {url}"
        super().__init__()

    def _connect(self):
        if self.scheme == "udp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self.sock = socket.create_connection(self.addr, timeout=3)

    def _deliver(self, alert):
        payload = to_cef(alert) if self.fmt == "cef" else json.dumps(alert, separators=(",", ":"))
        msg = to_syslog(alert, payload, self.hostname).encode("utf-8")
        if self.sock is None:
            self._connect()
        try:
            if self.scheme == "udp":
                self.sock.sendto(msg[:65000], self.addr)
            else:
                self.sock.sendall(str(len(msg)).encode() + b" " + msg)
        except OSError:
            self.sock.close()
            self.sock = None
            raise


class KafkaForwarder(_Background):
    """JSON alerts to a Kafka topic. `bootstrap` = "broker1:9092,broker2:9092"."""

    def __init__(self, bootstrap: str, topic: str = "irondome.alerts", producer=None):
        if producer is None:
            try:
                from kafka import KafkaProducer   # optional dependency: pip install kafka-python
            except ImportError as e:
                raise RuntimeError("Kafka output needs the kafka-python package (pip install kafka-python)") from e
            producer = KafkaProducer(bootstrap_servers=bootstrap.split(","), acks=1, linger_ms=50,
                                     value_serializer=lambda v: json.dumps(v, separators=(",", ":")).encode())
        self.producer, self.topic = producer, topic
        self.describe = f"kafka -> {bootstrap} topic {topic}"
        super().__init__()

    def _deliver(self, alert):
        self.producer.send(self.topic, value=alert, key=str(alert.get("threat_class", "")).encode())


# ---------------------------------------------------------------------------
# Signed, hash-chained archive
# ---------------------------------------------------------------------------
GENESIS = "0" * 64


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_hash(prev: str, seq: int, alert: dict) -> str:
    return hashlib.sha256(prev.encode() + seq.to_bytes(8, "big") + _canonical(alert)).hexdigest()


class SignedArchive:
    """Append-only alert archive: <dir>/alerts-YYYYMMDD.jsonl, one chained, signed record per line."""

    def __init__(self, directory: str | Path, key: bytes):
        if not key:
            raise ValueError("the archive needs a signing key (IRONDOME_ARCHIVE_KEY)")
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.key = key
        self.lock = threading.Lock()
        self.prev, self.seq = GENESIS, 0
        self.stats = {"written": 0, "errors": 0}
        self.describe = f"signed archive -> {self.dir}"
        self._resume()

    def _files(self):
        return sorted(self.dir.glob("alerts-*.jsonl"))

    def _resume(self):
        """Continue the chain from the last record on disk (across restarts and days)."""
        files = self._files()
        if not files:
            return
        last = None
        with open(files[-1], "rb") as f:
            for line in f:
                if line.strip():
                    last = line
        if last:
            rec = json.loads(last)
            self.prev, self.seq = rec["hash"], rec["seq"]

    def append(self, alert: dict):
        with self.lock:
            try:
                seq = self.seq + 1
                h = record_hash(self.prev, seq, alert)
                sig = hmac.new(self.key, h.encode(), hashlib.sha256).hexdigest()
                rec = {"seq": seq, "prev": self.prev, "hash": h, "sig": sig, "alert": alert}
                day = datetime.now(timezone.utc).strftime("%Y%m%d")
                with open(self.dir / f"alerts-{day}.jsonl", "ab") as f:
                    f.write(_canonical(rec) + b"\n")
                    f.flush()
                    os.fsync(f.fileno())
                self.prev, self.seq = h, seq
                self.stats["written"] += 1
            except OSError:
                self.stats["errors"] += 1

    send = append

    def close(self):
        pass


def verify_archive(directory: str | Path, key: bytes) -> dict:
    """Walk every archive file in order and check chain, sequence and signatures."""
    prev, expect = None, None
    n = 0
    for path in sorted(Path(directory).glob("alerts-*.jsonl")):
        with open(path, "rb") as f:
            for lineno, line in enumerate(f, 1):
                if not line.strip():
                    continue
                where = f"{path.name}:{lineno}"
                try:
                    rec = json.loads(line)
                except ValueError:
                    return {"ok": False, "records": n, "error": f"{where}: not valid JSON"}
                if prev is None:
                    prev, expect = rec["prev"], rec["seq"]
                if rec["seq"] != expect:
                    return {"ok": False, "records": n, "error": f"{where}: sequence {rec['seq']}, expected {expect} (record missing?)"}
                if rec["prev"] != prev:
                    return {"ok": False, "records": n, "error": f"{where}: chain broken (previous record altered or removed)"}
                if record_hash(rec["prev"], rec["seq"], rec["alert"]) != rec["hash"]:
                    return {"ok": False, "records": n, "error": f"{where}: content does not match its hash (edited)"}
                good = hmac.new(key, rec["hash"].encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(good, rec["sig"]):
                    return {"ok": False, "records": n, "error": f"{where}: bad signature (wrong key or forged)"}
                prev, expect = rec["hash"], rec["seq"] + 1
                n += 1
    return {"ok": True, "records": n, "error": None, "head": prev}


def from_env(env=os.environ, log=print) -> list:
    """Build the configured outputs from IRONDOME_* environment variables. A misconfigured
    output is reported and skipped; it never stops the sensor or the other outputs."""
    builders = []
    if env.get("IRONDOME_SYSLOG"):
        builders.append(lambda: SyslogForwarder(env["IRONDOME_SYSLOG"], env.get("IRONDOME_SYSLOG_FORMAT", "cef").lower()))
    if env.get("IRONDOME_KAFKA"):
        builders.append(lambda: KafkaForwarder(env["IRONDOME_KAFKA"], env.get("IRONDOME_KAFKA_TOPIC", "irondome.alerts")))
    if env.get("IRONDOME_ARCHIVE_DIR"):
        builders.append(lambda: SignedArchive(env["IRONDOME_ARCHIVE_DIR"], env.get("IRONDOME_ARCHIVE_KEY", "").encode("utf-8")))
    outs = []
    for build in builders:
        try:
            outs.append(build())
        except (ValueError, RuntimeError, OSError) as e:
            log(f"alert output disabled: {e}")
    return outs
