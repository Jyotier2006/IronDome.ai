"""Model inference: turn feature candidates into standardized alert records.

`ThreatScorer` loads the per-detector calibrated models (model_microservice/models/
*.joblib) and, optionally, a JA3 threat-intel watchlist. For each candidate emitted
by the FeaturePipeline it computes P(attack) and the most likely technique, and -
when the score clears the detector's calibrated threshold - emits an alert that
conforms to schema.ALERT_JSON_SCHEMA (PS constraint e).

If a model file is missing or scikit-learn is unavailable, that detector falls back
to a transparent heuristic so the pipeline still runs (clearly flagged mode:
"heuristic-fallback"). DGA and encrypted-malware also fold in evidence the models
do not see: the DGA per-domain model is applied to each candidate domain, and the
JA3 watchlist upgrades known C2 fingerprints to high confidence.
"""

from __future__ import annotations

import math
import time
import uuid
from pathlib import Path

from .lexical import domain_features
from .schema import (
    DETECTORS, THREAT_CLASSES, severity_for, technique_info, THREAT_CLASSES as TC, utc_iso, validate_alert,
)

MODELS_DIR = Path(__file__).resolve().parent.parent / "model_microservice" / "models"
INTEL_DIR = Path(__file__).resolve().parent.parent / "backend" / "sensor-service" / "intel"


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


class _Loaded:
    __slots__ = ("model", "features", "classes", "threshold", "mode")

    def __init__(self, model, features, classes, threshold, mode):
        self.model = model
        self.features = features
        self.classes = classes
        self.threshold = threshold
        self.mode = mode


# ---------------------------------------------------------------------------
# Heuristic fallbacks - transparent rules used only when a model is unavailable.
# Each returns (p_attack, technique_or_None).
# ---------------------------------------------------------------------------
def _h_ddos(f):
    score = 0.0
    if f["flows_per_s"] > 150 or f["pkts_per_s"] > 20000:
        score = max(score, 0.6)
    if f["syn_only_ratio"] > 0.7:
        return min(1.0, score + 0.35), "syn_flood"
    if f["amp_port_ratio"] > 0.5:
        return min(1.0, score + 0.35), "udp_amplification"
    if f["slow_ratio"] > 0.5:
        return max(score, 0.8), "slow_http"
    if f["flows_per_src"] < 1.5 and f["uniq_src"] > 200:
        return min(1.0, score + 0.3), "spoofed_flood"
    if f["udp_ratio"] > 0.6 and f["unanswered_ratio"] > 0.8:
        return min(1.0, score + 0.3), "udp_icmp_flood"
    return score, None


def _h_scan(f):
    if f["uniq_pairs"] >= 12 and f["failed_ratio"] > 0.5 and f["no_payload_ratio"] > 0.5 and f["attempts_per_pair"] < 2:
        return 0.85, "vertical_scan" if f["max_ports_per_host"] >= f["max_hosts_per_port"] else "horizontal_scan"
    return 0.2, None


def _h_beacon(f):
    if f["n_conns"] >= 6 and f["iat_cv"] < 0.25 and f["iat_regularity"] > 0.6 and f["dst_prevalence"] <= 4:
        return 0.8, "periodic_beacon"
    return 0.2, None


def _h_dga(f):
    bad = (f["bigram_score"] <= -1.9) + (f["dict_coverage"] < 0.2) + (f["entropy"] >= 3.4) + (f["length"] >= 15)
    return (0.8, "dga") if bad >= 2 else (0.2, None)


def _h_tunnel(f):
    if f["queries"] >= 8 and f["unique_ratio"] > 0.8 and (f["mean_sub_len"] > 25 or f["txt_null_ratio"] > 0.3):
        return 0.85, "dns_tunnelling"
    return 0.2, None


def _h_tls(f):
    if f["sni_present"] < 0.5 and f["alpn_present"] < 0.5 and f["ja3_prevalence"] <= 3 and f["bytes_bwd"] < 6000:
        return 0.7, "tls_behaviour"
    return 0.2, None


def _h_exfil(f):
    if f["bytes_out_mb"] > 1 and f["out_in_ratio_log"] > 0.4 and f["dst_prevalence"] <= 3 and f["host_out_zscore"] > 3:
        return 0.85, "volume_asymmetry"
    return 0.25, None


HEURISTICS = {"ddos": _h_ddos, "recon_scan": _h_scan, "c2_beacon": _h_beacon, "dga_domain": _h_dga,
              "dns_tunnel": _h_tunnel, "encrypted_malware": _h_tls, "exfiltration": _h_exfil}


class ThreatScorer:
    def __init__(self, models_dir: Path | None = None, load_intel: bool = True):
        self.models_dir = Path(models_dir) if models_dir else MODELS_DIR
        self.models: dict[str, _Loaded] = {}
        self.ja3_watchlist: dict[str, str] = {}          # ja3 -> family / listing reason
        self.ja3_source: dict[str, str] = {}             # ja3 -> list it came from
        self.intel_sources: list[dict] = []
        self.recent_scanners: dict[str, float] = {}      # source ip -> wall time last flagged
        self.stats = {"candidates": 0, "alerts": 0, "by_detector": {}, "by_class": {}, "suppressed_scan_residue": 0}
        self._load_models()
        if load_intel:
            self._load_intel()

    def _load_models(self):
        try:
            import joblib
        except Exception:
            joblib = None
        from .features import FEATURES
        for det in DETECTORS:
            path = self.models_dir / f"{det}.joblib"
            if joblib is not None and path.exists():
                try:
                    d = joblib.load(path)
                    self.models[det] = _Loaded(d["model"], d["features"], d["classes"], d["threshold"], "ml")
                    continue
                except Exception as e:  # pragma: no cover
                    print(f"[scoring] failed to load {path.name}: {e}; using heuristic fallback")
            self.models[det] = _Loaded(None, FEATURES[det], _fallback_classes(det), 0.5, "heuristic-fallback")

    def _load_intel(self):
        """JA3 watchlists. `sslbl_ja3.csv` is abuse.ch's public SSL Blacklist JA3 feed (real
        malware fingerprints); `lab_ja3_fingerprints.json` holds the traffic lab's simulated
        malware families and only means something while the lab is the traffic source - set
        IRONDOME_LAB_JA3=off on a real network. Every hit records which list matched."""
        import csv
        import json
        import os
        sslbl = INTEL_DIR / "sslbl_ja3.csv"
        if sslbl.exists():
            n = 0
            with open(sslbl, encoding="utf-8") as f:
                for row in csv.reader(line for line in f if line.strip() and not line.startswith("#")):
                    if len(row) >= 4 and len(row[0]) == 32:
                        self.ja3_watchlist[row[0]] = row[3].strip() or "malware"
                        self.ja3_source[row[0]] = "abuse.ch SSLBL"
                        n += 1
            self.intel_sources.append({"name": "abuse.ch SSLBL JA3 fingerprints", "file": sslbl.name, "entries": n})
        lab = INTEL_DIR / "lab_ja3_fingerprints.json"
        if lab.exists() and os.environ.get("IRONDOME_LAB_JA3", "on").lower() not in ("off", "0", "false", "no"):
            try:
                doc = json.loads(lab.read_text(encoding="utf-8"))
                entries = doc.get("entries", [])
                for e in entries:
                    self.ja3_watchlist.setdefault(e["ja3"], e.get("family", "lab family"))
                    self.ja3_source.setdefault(e["ja3"], "traffic-lab fingerprints")
                self.intel_sources.append({"name": "traffic-lab simulated malware fingerprints", "file": lab.name,
                                           "entries": len(entries)})
            except (ValueError, KeyError):
                pass

    # ----- scan residue ---------------------------------------------------
    DGA_NX_MIN = 8                  # distinct failed names from one host in 60 s
    SCANNER_MEMORY_S = 300.0
    SCAN_RESIDUE_MAX_RATE = 500.0   # half-open flows/s from one source; above this it is a flood

    def note_scanner(self, ip: str, wall: float | None = None):
        self.recent_scanners[ip] = wall if wall is not None else time.time()
        if len(self.recent_scanners) > 5000:
            cutoff = time.time() - self.SCANNER_MEMORY_S
            self.recent_scanners = {k: v for k, v in self.recent_scanners.items() if v >= cutoff}

    def is_recent_scanner(self, ip: str) -> bool:
        t = self.recent_scanners.get(ip)
        return t is not None and time.time() - t <= self.SCANNER_MEMORY_S

    def scan_residue(self, cand: dict) -> bool:
        """True when a SYN-flood window is really a port scan seen from the target's side:
        one source sends most of the half-open connections, at scan-like rates, while
        fanning out over many ports or already flagged as a scanner. A genuine flood (many
        sources, or one source hammering a port at flood rates) is never suppressed."""
        h = (cand.get("context") or {}).get("half_open_top_source")
        if not h or h["per_s"] > self.SCAN_RESIDUE_MAX_RATE:
            return False
        known = self.is_recent_scanner(h["ip"])
        return (h["share"] >= 0.6 and (h["distinct_ports"] >= 10 or known)) or (known and h["share"] >= 0.5)

    # ----- batch scoring (fast path) --------------------------------------
    def score_many(self, cands: list, source: dict | None = None) -> list:
        """Score a batch of candidates, running one predict_proba per detector.

        A single calibrated predict_proba carries ~85 ms of fixed overhead, so scoring
        candidates one at a time is ~450x slower than batching them. The streaming
        pipeline emits candidates in bursts (per evaluate() call), which this batches.
        """
        if not cands:
            return []
        try:
            import numpy as np
        except Exception:
            return [a for c in cands if (a := self.score(c, source))]
        # DGA is scored per-domain; handle it through the per-candidate path.
        alerts = []
        groups: dict[str, list] = {}
        for c in cands:
            self.stats["candidates"] += 1
            if c["detector"] == "dga_domain":
                a = self._score_dga(c, source)
                if a:
                    alerts.append(a)
            else:
                groups.setdefault(c["detector"], []).append(c)
        for det in sorted(groups, key=lambda d: 0 if d == "recon_scan" else 1):   # learn scanners first
            items = groups[det]
            m = self.models[det]
            if m.model is None:
                for c in items:
                    p, tech = HEURISTICS[det](c["features"])
                    a = self._maybe_alert(det, c, c["features"], p, _map_technique(det, tech), source)
                    if a:
                        alerts.append(a)
                continue
            X = np.array([[float(c["features"][k]) for k in m.features] for c in items], dtype=np.float64)
            probs = m.model.predict_proba(X)
            for i, c in enumerate(items):
                p_attack, tech_label = _decide(det, c["features"], probs[i], m.classes)
                a = self._maybe_alert(det, c, c["features"], p_attack, _map_technique(det, tech_label), source)
                if det == "encrypted_malware":
                    a = self._apply_watchlist(c, a, source)
                a = self._post(det, c, a)
                if a:
                    alerts.append(a)
        return alerts

    def _apply_watchlist(self, cand, alert, source):
        ja3 = (cand.get("context") or {}).get("ja3")
        if ja3 and ja3 in self.ja3_watchlist and (alert is None or alert["confidence"] < 0.9):
            src = self.ja3_source.get(ja3, "watchlist")
            conf = 0.9 if src == "abuse.ch SSLBL" else 0.97
            alert = self._build_alert("encrypted_malware", cand, cand["features"], conf, "ja3_watchlist", source,
                                      extra_evidence={"ja3_watchlist_family": self.ja3_watchlist[ja3],
                                                      "intel_source": src}, detector_mode="ml+intel")
        return alert

    def _post(self, det, cand, alert):
        """Cross-detector rules applied to a finished alert."""
        if alert is None:
            return None
        if det == "recon_scan":
            ip = (alert.get("entity") or {}).get("ip")
            if ip:
                self.note_scanner(ip)
        elif det == "ddos" and alert.get("technique") == "syn_flood" and self.scan_residue(cand):
            self.stats["suppressed_scan_residue"] += 1
            self.stats["alerts"] -= 1
            self.stats["by_detector"]["ddos"] -= 1
            self.stats["by_class"]["volumetric_ddos"] -= 1
            return None
        return alert

    # ----- scoring --------------------------------------------------------
    def _predict(self, det: str, feats: dict):
        """Return (p_attack, technique, class_probs|None)."""
        m = self.models[det]
        if m.model is None:
            p, tech = HEURISTICS[det](feats)
            return p, tech, None
        import numpy as np
        x = np.array([[float(feats[k]) for k in m.features]], dtype=np.float64)
        probs = m.model.predict_proba(x)[0]
        p_attack, tech_label = _decide(det, feats, probs, m.classes)
        return p_attack, tech_label, probs

    def score(self, cand: dict, source: dict | None = None) -> dict | None:
        det = cand["detector"]
        self.stats["candidates"] += 1
        feats = cand["features"]

        if det == "dga_domain":
            return self._score_dga(cand, source)

        p_attack, tech_label, _ = self._predict(det, feats)
        tech = _map_technique(det, tech_label)
        alert = self._maybe_alert(det, cand, feats, p_attack, tech, source)

        # encrypted-malware: a JA3 watchlist hit overrides a low model score
        if det == "encrypted_malware" and self.models[det].mode != "heuristic-fallback":
            alert = self._apply_watchlist(cand, alert, source)
        return self._post(det, cand, alert)

    def _score_dga(self, cand: dict, source):
        """DGA detector aggregates per-domain lexical scores over a host's suspicious domains."""
        items = cand.get("items") or []
        scored = []
        for it in items:
            f = it.get("features") or domain_features(it["domain"])
            p, _, _ = self._predict("dga_domain", f)
            scored.append((p, it))
        malicious = [(p, it) for p, it in scored if p >= self.models["dga_domain"].threshold]
        feats = dict(cand["features"])
        nx_ratio = cand["context"].get("nx_ratio", 0.0)
        if len(malicious) >= 3:
            malicious.sort(key=lambda pi: -pi[0])
            conf = float(sum(p for p, _ in malicious) / len(malicious))
            conf = min(0.99, conf + 0.05 * math.log2(len(malicious)))
            feats["malicious_domains"] = len(malicious)
            top = [{"domain": it["domain"], "score": round(p, 3), "rcode": it.get("rcode")} for p, it in malicious[:8]]
            return self._build_alert("dga_domain", cand, feats, conf, "dga", source,
                                     extra_evidence={"malicious_domain_count": len(malicious), "example_domains": top,
                                                     "nx_ratio": round(nx_ratio, 3), "basis": "lexical"})
        # Behavioural path: dictionary-word DGAs look like ordinary names one at a time, but
        # an infected host walks many never-registered names, so most lookups fail.
        nx_items = sorted(((p, it) for p, it in scored if it.get("rcode") == "NXDOMAIN"), key=lambda pi: -pi[0])
        if len(nx_items) >= self.DGA_NX_MIN and nx_ratio >= 0.5:
            lex = sum(p for p, _ in nx_items[:8]) / 8
            if lex >= 0.1:
                conf = round(min(0.95, 0.55 + 0.3 * nx_ratio + 0.1 * lex), 4)
                feats["nx_domains"] = len(nx_items)
                top = [{"domain": it["domain"], "score": round(p, 3), "rcode": "NXDOMAIN"} for p, it in nx_items[:8]]
                return self._build_alert("dga_domain", cand, feats, conf, "dga", source,
                                         extra_evidence={"nxdomain_distinct_names": len(nx_items), "example_domains": top,
                                                         "nx_ratio": round(nx_ratio, 3), "mean_lexical_score": round(lex, 3),
                                                         "basis": "nxdomain behaviour"},
                                         detector_mode="ml+behaviour")
        return None

    def _maybe_alert(self, det, cand, feats, p_attack, tech, source):
        if p_attack < self.models[det].threshold:
            return None
        # Baseline-learning period: prevalence and host baselines are meaningless until the
        # sensor has observed the estate for a while (after a cold start everything looks
        # "rare"). During that period prevalence-dependent detectors alert only on
        # overwhelming evidence. A sensor normally warm-starts from recent flow history.
        if cand.get("context_age_s", LEARNING_SECONDS) < LEARNING_SECONDS and not _overwhelming(det, feats):
            return None
        # Encrypted-malware precision gate. Per-flow scoring of all encrypted traffic is
        # inherently noisy, so a non-watchlisted alert must clear two independent signals,
        # the way JA3-based detection works in practice:
        #   (1) an *unusual* TLS client - a JA3 present but rare in the estate (few hosts),
        #       not a common browser/app fingerprint and not a fingerprint-less flow (QUIC), and
        #   (2) a suspicious server name - absent SNI, an IP literal, a high-entropy/DGA name,
        #       or a rarely-abused TLS, rather than a clean corporate/CDN domain.
        # A watchlisted JA3 bypasses this gate (handled by the caller).
        if det == "encrypted_malware":
            ja3 = (cand.get("context") or {}).get("ja3")
            unusual_client = bool(ja3) and feats.get("ja3_prevalence", 0) <= 5
            suspicious_sni = (feats.get("sni_present", 0) < 1 or feats.get("sni_is_ip", 0) >= 1
                              or feats.get("sni_tld_rarity", 0) >= 2 or feats.get("sni_entropy", 0) > 3.2)
            if not (unusual_client and suspicious_sni):
                return None
        return self._build_alert(det, cand, feats, p_attack, tech, source)

    def _build_alert(self, det, cand, feats, confidence, technique, source, extra_evidence=None,
                     detector_mode=None):
        m = self.models[det]
        tc = DETECTORS[det]["threat_class"]
        spec = THREAT_CLASSES[tc]
        tinfo = technique_info(tc, technique)
        now = time.time()
        first = cand.get("first_seen", now)
        last = cand.get("last_seen", now)
        evidence = {
            "features": {k: round(float(v), 4) for k, v in feats.items()},
            "top_deviations": _top_deviations(det, feats, m),
        }
        ctx = cand.get("context")
        if ctx:
            evidence["context"] = ctx
        if extra_evidence:
            evidence.update(extra_evidence)
        alert = {
            "schema_version": "1.0",
            "alert_id": str(uuid.uuid4()),
            "timestamp": utc_iso(now),
            "first_seen": utc_iso(first),
            "last_seen": utc_iso(last),
            "flow_id": cand.get("flow_id", ""),
            "related_flow_ids": cand.get("related_flow_ids", []),
            "flow": cand.get("flow", {}),
            "entity": cand.get("entity", {}),
            "threat_class": tc,
            "ps_ref": spec["ps_ref"],
            "threat_label": spec["label"],
            "technique": technique,
            "technique_label": tinfo.get("label", technique),
            "mitre_attack": tinfo.get("mitre", []),
            "confidence": round(float(confidence), 4),
            "severity": severity_for(tc, confidence),
            "description": _describe(det, cand, feats, technique),
            "recommended_action": spec["action"],
            "detector": {"name": det, "model": TITLES.get(det, det),
                         "version": "2.0", "mode": detector_mode or m.mode, "threshold": m.threshold},
            "evidence": evidence,
            "occurrences": 1,   # correlated sightings; per-window flow counts live in evidence.context
        }
        if source:
            alert["source"] = source
        if "ingest_wall" in cand:
            alert["latency_ms"] = round((time.time() - cand["ingest_wall"]) * 1000.0, 1)
        self.stats["alerts"] += 1
        self.stats["by_detector"][det] = self.stats["by_detector"].get(det, 0) + 1
        self.stats["by_class"][tc] = self.stats["by_class"].get(tc, 0) + 1
        return alert


TITLES = {
    "ddos": "Volumetric/protocol DDoS classifier",
    "recon_scan": "Reconnaissance/port-scan classifier",
    "c2_beacon": "C2 beaconing classifier",
    "dga_domain": "DGA domain classifier",
    "dns_tunnel": "DNS tunnelling classifier",
    "encrypted_malware": "Encrypted-session malware classifier",
    "exfiltration": "Data exfiltration classifier",
}


LEARNING_SECONDS = 300.0
_PREVALENCE_DETECTORS = {"exfiltration", "c2_beacon", "encrypted_malware"}


def _overwhelming(det: str, feats: dict) -> bool:
    """Evidence strong enough to alert even before the estate baseline has matured."""
    if det not in _PREVALENCE_DETECTORS:
        return True                     # detector does not depend on estate context
    if det == "exfiltration":
        return feats.get("bytes_out_mb", 0) >= 50 and feats.get("out_in_ratio_log", 0) >= 1.0
    if det == "c2_beacon":
        return feats.get("n_conns", 0) >= 10 and feats.get("iat_cv", 1) <= 0.25 and feats.get("dst_prevalence", 99) <= 2
    return False                        # encrypted_malware: only the JA3 watchlist path alerts cold


def _fallback_classes(det):
    from .samples import LABELS
    return LABELS[det]


# ---------------------------------------------------------------------------
# Evidence-consistency guard
# ---------------------------------------------------------------------------
# A model can extrapolate badly on inputs unlike its training data (e.g. calling a
# TCP-only web window a "UDP/ICMP flood"). Every technique therefore has a minimal
# physical precondition on the flow evidence; a class whose precondition fails is
# removed from the decision. The reported technique is always one the cited evidence
# supports, which keeps every alert explainable to an analyst.
_SUPPORT = {
    "ddos": {
        "syn_flood": lambda f: f["tcp_ratio"] >= 0.5 and f["syn_only_ratio"] >= 0.3,
        "udp_icmp_flood": lambda f: f["udp_ratio"] + f["icmp_ratio"] >= 0.5,
        "udp_amplification": lambda f: f["udp_ratio"] >= 0.5 and f["amp_port_ratio"] >= 0.3,
        "spoofed_flood": lambda f: f["src_entropy_norm"] >= 0.8 and f["flows_per_src"] <= 2.0 and f["uniq_src"] >= 50,
        # Slowloris holds many slow connections per attacking host; one idle keep-alive
        # connection from each of many browsers is ordinary web traffic
        "slow_http": lambda f: f["tcp_ratio"] >= 0.5 and f["slow_ratio"] >= 0.2 and f["flows_per_src"] >= 1.5,
    },
    "c2_beacon": {
        # implants sleep seconds to minutes between check-ins; sub-second repeats are a
        # burst (e.g. a browser opening parallel connections), not a beacon
        "beacon": lambda f: f["iat_median"] >= 1.0,
    },
    "recon_scan": {
        # scan probes are header-only / tiny; a flood spraying random ports carries payload
        "vertical_scan": lambda f: f["max_ports_per_host"] >= 10 and f["no_payload_ratio"] >= 0.4,
        "horizontal_scan": lambda f: f["max_hosts_per_port"] >= 10 and f["no_payload_ratio"] >= 0.4,
    },
}


def technique_supported(det: str, class_label: str, feats: dict) -> bool:
    rule = _SUPPORT.get(det, {}).get(class_label)
    if rule is None:
        return True
    try:
        return bool(rule(feats))
    except KeyError:
        return True


def _decide(det: str, feats: dict, probs, classes) -> tuple[float, str]:
    """P(attack) and technique from class probabilities, restricted to techniques the
    evidence supports. Class 0 is always benign."""
    valid = [i for i in range(1, len(classes)) if technique_supported(det, classes[i], feats)]
    if not valid:
        return 0.0, classes[1]
    p_attack = float(sum(probs[i] for i in valid))
    best = max(valid, key=lambda i: probs[i])
    return p_attack, classes[best]


def _map_technique(det, class_label):
    """Map a model's class label to a schema technique id."""
    fixed = DETECTORS[det].get("technique")
    if fixed:
        return fixed
    mapping = {
        "syn_flood": "syn_flood", "udp_icmp_flood": "udp_icmp_flood", "udp_amplification": "udp_amplification",
        "spoofed_flood": "spoofed_flood", "slow_http": "slow_http",
        "vertical_scan": "vertical_scan", "horizontal_scan": "horizontal_scan",
        "beacon": "periodic_beacon", "malware": "tls_behaviour", "tunnel": "dns_tunnelling",
        "exfiltration": "volume_asymmetry", "dga": "dga",
    }
    return mapping.get(class_label, class_label)


def _top_deviations(det, feats, m, k=4):
    """The features that deviate most from the benign baseline, if a model card exists."""
    base = _baselines(det)
    if not base:
        return []
    scored = []
    for name, val in feats.items():
        b = base.get(name)
        if not b or b.get("std", 0) <= 0:
            continue
        z = (val - b["mean"]) / b["std"]
        if abs(z) >= 1.0:
            scored.append((abs(z), {"feature": name, "value": round(float(val), 4),
                                    "benign_mean": b["mean"], "z_score": round(float(z), 2)}))
    scored.sort(key=lambda s: -s[0])
    return [d for _, d in scored[:k]]


_BASELINE_CACHE: dict = {}


def _baselines(det):
    if det in _BASELINE_CACHE:
        return _BASELINE_CACHE[det]
    import json
    card = MODELS_DIR / "model_card.json"
    base = {}
    if card.exists():
        try:
            doc = json.loads(card.read_text(encoding="utf-8"))
            base = doc.get("detectors", {}).get(det, {}).get("baselines", {})
        except Exception:
            base = {}
    _BASELINE_CACHE[det] = base
    return base


def _describe(det, cand, feats, technique):
    e = cand.get("entity", {})
    ctx = cand.get("context", {})
    tinfo = technique_info(DETECTORS[det]["threat_class"], technique)
    label = tinfo.get("label", technique)
    if det == "ddos":
        return (f"{label}: {ctx.get('flows', 0)} flows/{int(ctx.get('bytes', 0)/1e6)}MB toward {e.get('ip')} "
                f"in {ctx.get('window', {}).get('seconds', 2)}s from {int(feats.get('uniq_src', 0))} sources.")
    if det == "recon_scan":
        return (f"{label} from {e.get('ip')}: {int(feats.get('uniq_pairs', 0))} host/port probes across "
                f"{int(feats.get('uniq_hosts', 0))} hosts and {int(feats.get('uniq_ports', 0))} ports, "
                f"{int(100*feats.get('failed_ratio', 0))}% unanswered.")
    if det == "c2_beacon":
        return (f"Periodic beaconing {e.get('src_ip')} -> {e.get('dst_ip')}:{e.get('dst_port')}: "
                f"{int(feats.get('n_conns', 0))} check-ins every ~{ctx.get('interval_s', '?')}s "
                f"(jitter {ctx.get('jitter_pct', '?')}%).")
    if det == "dga_domain":
        return (f"Host {e.get('ip')} queried {feats.get('malicious_domains', 0)} algorithmically-generated domains "
                f"({int(100*ctx.get('nx_ratio', 0))}% NXDOMAIN) - likely DGA C2 rendezvous.")
    if det == "dns_tunnel":
        return (f"DNS tunnelling {e.get('ip')} -> {e.get('domain')}: {int(feats.get('queries', 0))} encoded queries, "
                f"mean subdomain {int(feats.get('mean_sub_len', 0))} chars, {int(100*feats.get('unique_ratio', 0))}% unique.")
    if det == "encrypted_malware":
        ja3 = (ctx or {}).get("ja3", "?")
        return (f"Encrypted session {e.get('src_ip')} -> {e.get('dst_ip')}:{e.get('dst_port')} matches malware C2 "
                f"behaviour (JA3 {ja3}, no SNI/ALPN, low server volume) - no decryption performed.")
    if det == "exfiltration":
        return (f"Data exfiltration {e.get('src_ip')} -> {e.get('dst_ip')}: {feats.get('bytes_out_mb', 0):.1f}MB out vs "
                f"{feats.get('bytes_in_mb', 0):.2f}MB in to a rarely-seen destination "
                f"({int(feats.get('dst_prevalence', 0))} hosts use it).")
    return f"{label} detected for {e}."
