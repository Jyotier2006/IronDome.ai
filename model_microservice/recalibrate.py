"""Re-calibrate detector thresholds on captures from the network being protected.

    python recalibrate.py --capture site_monday.pcapng --capture site_tuesday.jsonl.gz --dry-run
    python recalibrate.py --capture site.pcapng                       # benign-only baseline capture
    python recalibrate.py --capture lab_attacks.pcapng --truth lab_attacks.truth.json

The shipped models were trained on the traffic lab (plus real popular domains for DGA).
Every network has its own "normal", so before going live the sensor should be run over
captures from the site itself:

  1. The capture(s) are replayed through the same streaming pipeline the sensor runs, and
     every candidate window is scored by the current model.
  2. Candidates are labelled: with --truth (the ground-truth format written by
     scripts/traffic_lab.py, or your own red-team log in the same format) a candidate is an
     attack if its time overlaps an attack window and it involves the attacker or target;
     everything else is treated as benign. Without --truth the whole capture is assumed to
     be benign - use a baseline period you trust.
  3. Per detector, the new threshold is the smallest value that keeps the false-positive
     rate on the site's benign windows within --max-fpr (default 0.5 %). Thresholds are only
     ever raised, never lowered below the lab-validated value; recall on labelled attacks is
     reported at the old and new threshold so the cost of the change is visible.
  4. Unless --dry-run, the models are backed up to models/backup-<time>/ and re-written with
     the new thresholds and a `site_calibration` record; docs/RECALIBRATION.md is written.

Restart the sensor to load the new thresholds.
"""

from __future__ import annotations

import argparse
import gzip
import json
import math
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import joblib  # noqa: E402
import numpy as np  # noqa: E402

from irondome.features import FeaturePipeline  # noqa: E402
from irondome.lexical import domain_features  # noqa: E402
from irondome.pcap import read_flows  # noqa: E402
from irondome.schema import normalize_flow  # noqa: E402
from irondome.schema import DETECTORS  # noqa: E402
from irondome.scoring import MODELS_DIR, ThreatScorer, _decide, _map_technique  # noqa: E402

REPORT = ROOT / "docs" / "RECALIBRATION.md"


def load_capture(path: Path) -> list[dict]:
    name = path.name.lower()
    if name.endswith((".jsonl", ".jsonl.gz", ".ndjson")):
        opener = gzip.open if name.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8") as f:
            raw = [json.loads(line) for line in f if line.strip()]
    else:
        raw = [r for batch in read_flows(str(path), sensor=f"recal:{path.name}") for r in batch]
    recs = [n for r in raw if (n := normalize_flow(r)) is not None]
    return sorted(recs, key=lambda r: r["te"])


def candidates(records: list[dict]) -> list[dict]:
    pipe = FeaturePipeline("recalibrate", "replay")
    out, last = [], None
    for r in records:
        pipe.ingest(r, r["te"])
        if last is None:
            last = r["te"]
        if r["te"] - last >= 1.0:
            out += pipe.evaluate(now_wall=r["te"])
            last = r["te"]
    return out + pipe.flush()


def involved_ips(c: dict) -> set:
    e = c.get("entity", {})
    ips = {e.get("ip"), e.get("src_ip"), e.get("dst_ip")}
    ctx = c.get("context") or {}
    for s in ctx.get("top_sources", []):
        ips.add(s.get("ip"))
    return {i for i in ips if i}


def label(c: dict, truth: list[dict]) -> str:
    """'attack' when the window overlaps an attack of this detector's class and involves the
    attacker or target; 'ambiguous' when it overlaps an attack of another class on the same
    hosts (left out of both sets); otherwise 'benign'."""
    ips = involved_ips(c)
    cls = DETECTORS[c["detector"]]["threat_class"]
    verdict = "benign"
    for t in truth:
        if c["last_seen"] < t["start"] or c["first_seen"] > t["end"] + 15:
            continue
        names = {t.get("attacker"), t.get("host")} | {x.strip() for x in str(t.get("target", "")).split(",")}
        if ips & {n for n in names if n}:
            if t.get("threat_class") in (cls, "multiple"):
                return "attack"
            verdict = "ambiguous"
    return verdict


def scores(scorer: ThreatScorer, det: str, cands: list[dict]) -> np.ndarray:
    """Model score of each window, or -1 where the sensor's other gates (evidence
    consistency, learning period, encrypted-traffic precision gate, scan residue) would
    stop the alert anyway - only windows that can actually alert count toward the rate."""
    m = scorer.models[det]
    X = np.array([[float(c["features"][k]) for k in m.features] for c in cands], dtype=np.float64)
    probs = m.model.predict_proba(X)
    out = []
    old = m.threshold
    m.threshold = 0.0
    try:
        for i, c in enumerate(cands):
            p, tech = _decide(det, c["features"], probs[i], m.classes)
            ja3 = (c.get("context") or {}).get("ja3")
            if det == "encrypted_malware" and ja3 in scorer.ja3_watchlist:
                out.append(2.0)          # watch-listed fingerprint: alerts whatever the threshold
                continue
            a = scorer._maybe_alert(det, c, c["features"], p, _map_technique(det, tech), None)
            out.append(p if scorer._post(det, c, a) is not None else -1.0)
    finally:
        m.threshold = old
    return np.array(out)


def dga_domain_scores(scorer: ThreatScorer, cands: list[dict]) -> np.ndarray:
    """The DGA model scores individual domains: collect every queried domain in the windows."""
    m = scorer.models["dga_domain"]
    doms = sorted({it["domain"] for c in cands for it in (c.get("items") or [])})
    if not doms:
        return np.zeros(0)
    X = np.array([[float(domain_features(d)[k]) for k in m.features] for d in doms], dtype=np.float64)
    return m.model.predict_proba(X)[:, 1]


def new_threshold(benign: np.ndarray, old: float, max_fpr: float) -> float:
    if len(benign) == 0:
        return old
    allowed = int(math.floor(max_fpr * len(benign)))
    s = np.sort(benign)[::-1]
    cut = s[allowed] if allowed < len(s) else 0.0      # scores strictly above `cut` may be flagged
    cut = min(cut, 1.0)                                  # watch-list hits (2.0) are not threshold-bound
    above = math.ceil(float(np.nextafter(cut, 2.0)) * 10_000) / 10_000   # round UP: stay strictly above the cut
    return max(old, min(1.0, above))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--capture", type=Path, action="append", required=True, help="PCAP/PCAPNG/JSONL (repeatable)")
    ap.add_argument("--truth", type=Path, help="ground-truth JSON of attack windows in the captures")
    ap.add_argument("--max-fpr", type=float, default=0.005)
    ap.add_argument("--dry-run", action="store_true", help="report only, do not rewrite the models")
    args = ap.parse_args()

    truth = json.loads(args.truth.read_text(encoding="utf-8"))["scenarios"] if args.truth else []
    scorer = ThreatScorer()
    cands: list[dict] = []
    total = 0
    for path in args.capture:
        recs = load_capture(path)
        total += len(recs)
        c = candidates(recs)
        print(f"{path.name}: {len(recs):,} flows -> {len(c):,} candidate windows", flush=True)
        cands += c

    rows = []
    for det, m in scorer.models.items():
        if m.model is None:
            continue
        mine = [c for c in cands if c["detector"] == det]
        if det == "dga_domain":
            ben_c = [c for c in mine if label(c, truth) == "benign"]
            benign, attack = dga_domain_scores(scorer, ben_c), np.zeros(0)
            unit = "domains"
        else:
            if not mine:
                rows.append({"detector": det, "windows": 0, "benign": 0, "attack": 0, "old": m.threshold,
                             "new": m.threshold, "fpr_old": None, "fpr_new": None, "recall_old": None, "recall_new": None,
                             "unit": "windows"})
                continue
            sc = scores(scorer, det, mine)
            labels = np.array([label(c, truth) for c in mine])
            benign, attack = sc[labels == "benign"], sc[labels == "attack"]
            unit = "windows"
        new = new_threshold(benign, m.threshold, args.max_fpr)
        rate = (lambda a, t: float((a >= t).mean()) if len(a) else None)
        rows.append({"detector": det, "windows": len(mine), "benign": int(len(benign)), "attack": int(len(attack)),
                     "old": m.threshold, "new": new, "fpr_old": rate(benign, m.threshold), "fpr_new": rate(benign, new),
                     "recall_old": rate(attack, m.threshold), "recall_new": rate(attack, new), "unit": unit})

    pct = (lambda x: "-" if x is None else f"{100 * x:.2f}%")
    print(f"\n{'detector':18s} {'benign':>9s} {'attack':>7s}  {'threshold':>17s}  {'site FPR':>17s}  {'recall':>15s}")
    for r in rows:
        print(f"{r['detector']:18s} {r['benign']:>9,} {r['attack']:>7,}  {r['old']:>7} -> {r['new']:<7}  "
              f"{pct(r['fpr_old']):>7} -> {pct(r['fpr_new']):<7}  {pct(r['recall_old']):>6} -> {pct(r['recall_new']):<6}")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    changed = [r for r in rows if r["new"] != r["old"]]
    if not args.dry_run and changed:
        backup = MODELS_DIR / f"backup-{stamp}"
        backup.mkdir(parents=True, exist_ok=True)
        for r in changed:
            path = MODELS_DIR / f"{r['detector']}.joblib"
            shutil.copy2(path, backup / path.name)
            d = joblib.load(path)
            d["threshold"] = r["new"]
            d["site_calibration"] = {"at": stamp, "captures": [p.name for p in args.capture], "max_fpr": args.max_fpr,
                                     "previous_threshold": r["old"], "benign_" + r["unit"]: r["benign"]}
            joblib.dump(d, path, compress=3)
        print(f"\n{len(changed)} model(s) updated; originals in {backup}. Restart the sensor to load them.")
    elif not changed:
        print("\nAll thresholds already meet the false-positive budget on this site data - nothing to change.")

    L = ["# Site re-calibration", "",
         f"_Generated {stamp} by `model_microservice/recalibrate.py`{' (dry run)' if args.dry_run else ''}._", "",
         f"Captures: {', '.join(p.name for p in args.capture)} ({total:,} flows). "
         f"Labels: {'ground truth ' + args.truth.name if args.truth else 'none - whole capture treated as benign'}. "
         f"False-positive budget: {100 * args.max_fpr:.1f}%.", "",
         "| Detector | Benign | Attack | Threshold | FPR on site benign | Recall on labelled attacks |",
         "|---|---|---|---|---|---|"]
    for r in rows:
        L.append(f"| `{r['detector']}` | {r['benign']:,} {r['unit']} | {r['attack']:,} | {r['old']} → {r['new']} | "
                 f"{pct(r['fpr_old'])} → {pct(r['fpr_new'])} | {pct(r['recall_old'])} → {pct(r['recall_new'])} |")
    L += ["", "Thresholds are only raised, never lowered below the lab-validated value. The DGA row counts "
              "individual queried domains, because that model scores one domain at a time."]
    REPORT.write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"-> {REPORT}")


if __name__ == "__main__":
    main()
