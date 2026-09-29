"""Flow-record format, threat-class registry and the standard alert schema.

FlowRecord
----------
Every collector (UDP flow export, NetFlow v5, PCAP replay) normalises its input
into the same bidirectional flow record ("biflow", in the spirit of IPFIX RFC 5103).
`fwd` is the direction of the connection initiator, `bwd` the responder.

    ts, te                 flow start / last-seen, epoch seconds (float)
    src_ip, dst_ip         initiator / responder address (str)
    src_port, dst_port     ports (int, 0 for ICMP)
    proto                  IP protocol number (6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6)
    pkts_fwd, bytes_fwd    packets / L3 bytes sent by the initiator
    pkts_bwd, bytes_bwd    packets / L3 bytes sent by the responder
    flags_fwd, flags_bwd   union of TCP flags seen per direction, letters of "FSRPAUEC"
    seg                    0 for the first record of a connection, >0 for
                           active-timeout continuation records of long flows
    dns   (optional)       {"qname", "qtype", "rcode", "answers"}
    tls   (optional)       {"version", "sni", "alpn", "ja3", "ja3s", "ja4", "ciphers", "exts"}
    quic  (optional)       {"version"}
    splt  (optional)       {"len": [...], "iat": [...]}  sequence of packet lengths
                           (+ initiator, - responder) and inter-arrival times in ms
                           for the first packets of the flow (encrypted traffic analytics)
    sensor (optional)      identifier of the exporting sensor

Only metadata is carried. There is no payload field: TLS/QUIC sessions are analysed
from handshake metadata and packet-size / timing sequences only (PS constraint b).
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import math
import struct
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0"

SEVERITIES = ("low", "medium", "high", "critical")

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

TCP_FLAG_LETTERS = "FSRPAUEC"

# ---------------------------------------------------------------------------
# Threat classes - one entry per item (a)-(f) of the problem statement.
# ---------------------------------------------------------------------------
THREAT_CLASSES = {
    "volumetric_ddos": {
        "ps_ref": "a",
        "label": "Volumetric / Protocol DDoS",
        "summary": "SYN floods, UDP reflection/amplification and spoofed-source floods, "
                   "identified from flow-level rates and source-IP entropy.",
        "base_severity": "critical",
        "techniques": {
            "syn_flood": {"label": "TCP SYN flood", "mitre": ["T1498.001", "T1499.001"]},
            "udp_icmp_flood": {"label": "UDP / ICMP flood", "mitre": ["T1498.001"]},
            "udp_amplification": {"label": "UDP reflection / amplification", "mitre": ["T1498.002"]},
            "spoofed_flood": {"label": "Spoofed-source flood", "mitre": ["T1498.001"]},
            "slow_http": {"label": "Slow HTTP exhaustion (Slowloris)", "mitre": ["T1499.002"]},
        },
        "action": "Notify the NOC / upstream ISP out-of-band so scrubbing or rate-limiting can be "
                  "applied on the production side. The monitoring enclave has no return path and "
                  "never pushes mitigations itself.",
    },
    "c2_beaconing": {
        "ps_ref": "b",
        "label": "Botnet C2 Beaconing",
        "summary": "Periodicity and inter-arrival analysis on flows that repeat at regular "
                   "intervals toward a small set of destinations.",
        "base_severity": "high",
        "techniques": {
            "periodic_beacon": {"label": "Periodic C2 beacon", "mitre": ["T1071.001", "T1573"]},
        },
        "action": "Raise an incident for the internal host; the endpoint team should isolate and "
                  "image it through normal change control. Hunt for the same destination and "
                  "timing pattern on other hosts.",
    },
    "dga_dns_tunnelling": {
        "ps_ref": "c",
        "label": "DGA Domains & DNS Tunnelling",
        "summary": "Entropy / n-gram analysis of DNS query names plus query-length and "
                   "record-type anomalies.",
        "base_severity": "high",
        "techniques": {
            "dga": {"label": "Algorithmically generated domains (DGA)", "mitre": ["T1568.002"]},
            "dns_tunnelling": {"label": "DNS tunnelling", "mitre": ["T1071.004", "T1572"]},
        },
        "action": "Report the queried base domain to the DNS / resolver team for sinkholing via the "
                  "production-side change process, and open an endpoint investigation on the host.",
    },
    "encrypted_malware": {
        "ps_ref": "d",
        "label": "Malware in Encrypted Sessions",
        "summary": "Detection from TLS/QUIC metadata alone (JA3/JA3S/JA4 fingerprints, packet-size "
                   "and timing sequences) without decrypting payload.",
        "base_severity": "high",
        "techniques": {
            "ja3_watchlist": {"label": "Watch-listed TLS client fingerprint", "mitre": ["T1573.002"]},
            "tls_behaviour": {"label": "Anomalous encrypted-session behaviour", "mitre": ["T1573.002", "T1071.001"]},
        },
        "action": "Correlate the JA3/JA4 fingerprint and destination across the estate; hand the "
                  "host to incident response. No decryption is performed or required.",
    },
    "recon_scan": {
        "ps_ref": "e",
        "label": "Reconnaissance & Port Scanning",
        "summary": "Fan-out patterns from a single source across many destination ports or hosts.",
        "base_severity": "medium",
        "techniques": {
            "vertical_scan": {"label": "Vertical port scan", "mitre": ["T1046"]},
            "horizontal_scan": {"label": "Horizontal host sweep", "mitre": ["T1046", "T1595.001"]},
        },
        "action": "Record the scanning source for threat-intel; if internal, open an investigation. "
                  "Watch for follow-on exploitation of the probed services.",
    },
    "data_exfiltration": {
        "ps_ref": "f",
        "label": "Data Exfiltration",
        "summary": "Asymmetric flow-volume anomalies and unusual outbound-to-inbound byte ratios.",
        "base_severity": "critical",
        "techniques": {
            "volume_asymmetry": {"label": "Asymmetric outbound transfer", "mitre": ["T1041", "T1048"]},
        },
        "action": "Escalate to incident response and data-protection officers; preserve the alert "
                  "record and its related flow records as evidence for forensics.",
    },
}

# Detector name -> threat class. The technique comes from the model's class label
# (multi-class detectors) or is fixed (binary detectors).
DETECTORS = {
    "ddos": {"threat_class": "volumetric_ddos", "technique": None},
    "c2_beacon": {"threat_class": "c2_beaconing", "technique": "periodic_beacon"},
    "dga_domain": {"threat_class": "dga_dns_tunnelling", "technique": "dga"},
    "dns_tunnel": {"threat_class": "dga_dns_tunnelling", "technique": "dns_tunnelling"},
    "encrypted_malware": {"threat_class": "encrypted_malware", "technique": "tls_behaviour"},
    "recon_scan": {"threat_class": "recon_scan", "technique": None},
    "exfiltration": {"threat_class": "data_exfiltration", "technique": "volume_asymmetry"},
}


def technique_info(threat_class: str, technique: str) -> dict:
    tc = THREAT_CLASSES.get(threat_class, {})
    return tc.get("techniques", {}).get(technique, {"label": technique, "mitre": []})


def severity_for(threat_class: str, confidence: float) -> str:
    """Severity = the class's base severity, lowered when the model is less certain."""
    base = THREAT_CLASSES.get(threat_class, {}).get("base_severity", "medium")
    idx = SEVERITIES.index(base)
    if confidence < 0.5:
        idx -= 2
    elif confidence < 0.7:
        idx -= 1
    return SEVERITIES[max(0, idx)]


# ---------------------------------------------------------------------------
# Flow identifiers
# ---------------------------------------------------------------------------
def _ip_bytes(ip: str) -> bytes:
    try:
        return ipaddress.ip_address(ip).packed
    except ValueError:
        return hashlib.sha1(ip.encode()).digest()[:4]


def community_id(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int, seed: int = 0) -> str:
    """Community ID v1 flow hash (Corelight spec) - the same identifier Zeek and
    Suricata emit, so alerts can be pivoted into other tools."""
    a, b = _ip_bytes(src_ip), _ip_bytes(dst_ip)
    sp, dp = int(src_port) & 0xFFFF, int(dst_port) & 0xFFFF
    if (a, sp) > (b, dp):
        a, b, sp, dp = b, a, dp, sp
    data = struct.pack("!H", seed) + a + b + struct.pack("!BB", int(proto) & 0xFF, 0) + struct.pack("!HH", sp, dp)
    return "1:" + base64.b64encode(hashlib.sha1(data).digest()).decode()


def flow_community_id(rec: dict) -> str:
    return community_id(rec["src_ip"], rec["dst_ip"], rec.get("src_port", 0), rec.get("dst_port", 0), rec.get("proto", 0))


def five_tuple(rec: dict) -> dict:
    return {
        "src_ip": rec["src_ip"],
        "src_port": int(rec.get("src_port", 0)),
        "dst_ip": rec["dst_ip"],
        "dst_port": int(rec.get("dst_port", 0)),
        "protocol": PROTO_NAMES.get(int(rec.get("proto", 0)), str(rec.get("proto", 0))),
    }


# ---------------------------------------------------------------------------
# Flow-record normalisation (collector input validation)
# ---------------------------------------------------------------------------
_PROTO_BY_NAME = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}


def _num(v, default=0.0) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    return f if math.isfinite(f) else default


def _int(v, default=0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _flags(v) -> str:
    if isinstance(v, int):
        bits = "FSRPAUEC"
        return "".join(bits[i] for i in range(8) if v & (1 << i))
    if not isinstance(v, str):
        return ""
    return "".join(ch for ch in TCP_FLAG_LETTERS if ch in v.upper())


def normalize_flow(raw: dict, now: float | None = None) -> dict | None:
    """Validate and coerce an incoming flow record. Returns None if unusable."""
    if not isinstance(raw, dict):
        return None
    src, dst = raw.get("src_ip"), raw.get("dst_ip")
    if not isinstance(src, str) or not isinstance(dst, str) or not src or not dst:
        return None
    proto = raw.get("proto", 6)
    if isinstance(proto, str):
        proto = _PROTO_BY_NAME.get(proto.lower(), _int(proto, 0))
    ts = _num(raw.get("ts"), now or 0.0)
    te = _num(raw.get("te"), ts)
    if te < ts:
        te = ts
    rec = {
        "ts": ts,
        "te": te,
        "src_ip": src,
        "dst_ip": dst,
        "src_port": max(0, min(65535, _int(raw.get("src_port")))),
        "dst_port": max(0, min(65535, _int(raw.get("dst_port")))),
        "proto": _int(proto),
        "pkts_fwd": max(0, _int(raw.get("pkts_fwd"))),
        "bytes_fwd": max(0, _int(raw.get("bytes_fwd"))),
        "pkts_bwd": max(0, _int(raw.get("pkts_bwd"))),
        "bytes_bwd": max(0, _int(raw.get("bytes_bwd"))),
        "flags_fwd": _flags(raw.get("flags_fwd", "")),
        "flags_bwd": _flags(raw.get("flags_bwd", "")),
        "seg": max(0, _int(raw.get("seg"))),
    }
    dns = raw.get("dns")
    if isinstance(dns, dict) and isinstance(dns.get("qname"), str) and dns["qname"]:
        rec["dns"] = {
            "qname": dns["qname"].strip().rstrip(".").lower()[:255],
            "qtype": str(dns.get("qtype", "A")).upper()[:10],
            "rcode": str(dns.get("rcode", "NOERROR")).upper()[:12],
            "answers": max(0, _int(dns.get("answers"))),
        }
    tls = raw.get("tls")
    if isinstance(tls, dict):
        rec["tls"] = {k: tls[k] for k in ("version", "sni", "alpn", "ja3", "ja3s", "ja4", "ciphers", "exts") if k in tls}
    quic = raw.get("quic")
    if isinstance(quic, dict):
        rec["quic"] = {"version": str(quic.get("version", ""))[:16]}
    splt = raw.get("splt")
    if isinstance(splt, dict) and isinstance(splt.get("len"), list):
        lens = [_int(x) for x in splt["len"][:32]]
        iats = [max(0.0, _num(x)) for x in (splt.get("iat") or [])[:32]]
        rec["splt"] = {"len": lens, "iat": iats}
    if isinstance(raw.get("sensor"), str):
        rec["sensor"] = raw["sensor"][:64]
    return rec


# ---------------------------------------------------------------------------
# Standard alert schema (PS constraint e)
# ---------------------------------------------------------------------------
def utc_iso(ts: float | None = None) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc) if ts is not None else datetime.now(timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


ALERT_JSON_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:irondome-ai:schema:alert:1.0",
    "title": "IronDome.ai standard alert record",
    "type": "object",
    "required": [
        "schema_version", "alert_id", "timestamp", "flow_id", "flow", "threat_class",
        "technique", "confidence", "severity", "evidence", "detector",
    ],
    "properties": {
        "schema_version": {"const": SCHEMA_VERSION},
        "alert_id": {"type": "string", "description": "UUID of the alert"},
        "timestamp": {"type": "string", "format": "date-time", "description": "UTC time the alert was raised"},
        "first_seen": {"type": "string", "format": "date-time", "description": "Event time of the first contributing flow"},
        "last_seen": {"type": "string", "format": "date-time", "description": "Event time of the last contributing flow"},
        "flow_id": {"type": "string", "description": "Community ID v1 of the representative flow"},
        "related_flow_ids": {"type": "array", "items": {"type": "string"}},
        "flow": {
            "type": "object",
            "description": "Representative 5-tuple",
            "required": ["src_ip", "dst_ip", "protocol"],
            "properties": {
                "src_ip": {"type": "string"}, "src_port": {"type": "integer"},
                "dst_ip": {"type": "string"}, "dst_port": {"type": "integer"},
                "protocol": {"type": "string"},
            },
        },
        "entity": {"type": "object", "description": "What the detector aggregated over (victim, source, host pair, flow)"},
        "threat_class": {"enum": list(THREAT_CLASSES)},
        "ps_ref": {"enum": ["a", "b", "c", "d", "e", "f"]},
        "threat_label": {"type": "string"},
        "technique": {"type": "string"},
        "technique_label": {"type": "string"},
        "mitre_attack": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "severity": {"enum": list(SEVERITIES)},
        "description": {"type": "string"},
        "recommended_action": {"type": "string"},
        "detector": {
            "type": "object",
            "required": ["name", "model", "mode"],
            "properties": {
                "name": {"type": "string"}, "model": {"type": "string"}, "version": {"type": "string"},
                "mode": {"enum": ["ml", "ml+intel", "ml+behaviour", "intel", "heuristic-fallback"]},
                "threshold": {"type": "number"},
            },
        },
        "evidence": {
            "type": "object",
            "description": "Supporting evidence: feature values, the features that deviate most from the "
                           "benign baseline, and detector-specific context (top talkers, domains, fingerprints)",
        },
        "source": {"type": "object", "description": "Pipeline that produced the alert (live / replay, capture name, sensor)"},
        "occurrences": {"type": "integer", "minimum": 1},
        "latency_ms": {"type": "number", "description": "Processing latency: last contributing flow ingested -> alert raised"},
    },
}


def validate_alert(alert: dict) -> list[str]:
    """Light-weight structural validation (no jsonschema dependency)."""
    errors = []
    for key in ALERT_JSON_SCHEMA["required"]:
        if key not in alert:
            errors.append(f"missing field: {key}")
    if alert.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version mismatch")
    if alert.get("threat_class") not in THREAT_CLASSES:
        errors.append(f"unknown threat_class: {alert.get('threat_class')}")
    conf = alert.get("confidence")
    if not isinstance(conf, (int, float)) or not 0.0 <= conf <= 1.0:
        errors.append("confidence must be a number in [0, 1]")
    if alert.get("severity") not in SEVERITIES:
        errors.append("invalid severity")
    flow = alert.get("flow") or {}
    for key in ("src_ip", "dst_ip", "protocol"):
        if key not in flow:
            errors.append(f"flow.{key} missing")
    if not isinstance(alert.get("evidence"), dict):
        errors.append("evidence must be an object")
    return errors
