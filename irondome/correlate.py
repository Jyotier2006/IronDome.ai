"""Alert correlation and deduplication.

Streaming detectors emit an alert per contributing window/flow, so a single incident
(a scan, a beacon, a flood, a long exfil) produces many near-identical alerts. The
`AlertCorrelator` collapses alerts that share an incident key into one *incident*
alert that carries an occurrence count, a first/last-seen span, a rolling max
confidence and merged evidence. This is what the dashboard and any downstream SIEM
should consume - one row per incident, not per flow.

An incident is keyed by (threat_class, primary entity). Within `window` seconds of the
last contributing alert the incident stays open and is updated in place; after that a
new sighting opens a fresh incident. Correlation is advisory only - it never drops the
underlying evidence, and it issues no mitigation (the enclave is read-only).
"""

from __future__ import annotations

import time
from collections import OrderedDict


def incident_key(alert: dict) -> str:
    e = alert.get("entity", {})
    tc = alert.get("threat_class", "?")
    etype = e.get("type")
    if etype == "destination":       # DDoS: victim
        return f"{tc}|dst={e.get('ip')}"
    if etype == "source":            # scan: scanner
        return f"{tc}|src={e.get('ip')}"
    if etype == "host_pair":         # beacon / exfil: internal host -> external dst
        return f"{tc}|{e.get('src_ip')}->{e.get('dst_ip')}"
    if etype == "host_domain":       # tunnel
        return f"{tc}|{e.get('ip')}|{e.get('domain')}"
    if etype in ("host", "flow"):    # DGA (host) / encrypted-malware (flow -> by src+dst)
        return f"{tc}|{e.get('ip') or e.get('src_ip')}->{e.get('dst_ip', '')}"
    return f"{tc}|{alert.get('flow_id', '')}"


class AlertCorrelator:
    def __init__(self, window: float = 90.0, max_incidents: int = 5000):
        self.window = window
        self.max_incidents = max_incidents
        self.open: "OrderedDict[str, dict]" = OrderedDict()
        self.stats = {"in": 0, "incidents": 0, "updates": 0}

    def _now_from(self, alert):
        ts = alert.get("last_seen") or alert.get("timestamp")
        return ts

    def add(self, alert: dict, now: float | None = None):
        """Feed one raw alert. Returns (incident, is_new). `incident` is the merged alert."""
        self.stats["in"] += 1
        key = incident_key(alert)
        now = now if now is not None else time.time()
        inc = self.open.get(key)
        last = alert.get("last_seen", alert.get("timestamp"))
        if inc is not None and (now - inc["_wall"]) <= self.window:
            self.open.move_to_end(key)
            inc["occurrences"] += 1
            inc["_wall"] = now
            inc["last_seen"] = max(inc.get("last_seen", last), last)
            if alert["confidence"] > inc["confidence"]:
                inc["confidence"] = alert["confidence"]
                inc["severity"] = alert["severity"]
                inc["technique"] = alert["technique"]
                inc["technique_label"] = alert.get("technique_label", inc.get("technique_label"))
                inc["description"] = alert["description"]
                inc["evidence"] = alert["evidence"]
            for fid in alert.get("related_flow_ids", []):
                if fid and fid not in inc["related_flow_ids"]:
                    inc["related_flow_ids"].append(fid)
            inc["related_flow_ids"] = inc["related_flow_ids"][:64]
            self.stats["updates"] += 1
            return inc, False
        # new incident
        inc = dict(alert)
        inc["incident_id"] = alert.get("alert_id")
        inc["occurrences"] = alert.get("occurrences", 1)
        inc["related_flow_ids"] = list(alert.get("related_flow_ids", []))
        inc["_wall"] = now
        self.open[key] = inc
        if len(self.open) > self.max_incidents:
            self.open.popitem(last=False)
        self.stats["incidents"] += 1
        return inc, True

    def expire(self, now: float | None = None):
        """Drop incidents whose window has elapsed (call periodically)."""
        now = now if now is not None else time.time()
        for key in list(self.open):
            if now - self.open[key]["_wall"] > self.window:
                del self.open[key]
            else:
                break   # OrderedDict is in recency order

    def active(self) -> list[dict]:
        return [self._public(i) for i in self.open.values()]

    @staticmethod
    def _public(inc: dict) -> dict:
        return {k: v for k, v in inc.items() if not k.startswith("_")}
