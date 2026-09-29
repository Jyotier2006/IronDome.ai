"""End-to-end pipeline evaluation on replayed lab captures.

Unlike model_training_pipeline.py (which scores individual feature vectors), this
runs whole captures through the *streaming* FeaturePipeline + ThreatScorer exactly as
the live sensor does, and scores the resulting alerts against the lab's ground truth:

  * detection      did at least one correct-class alert land inside the attack window
                   on the right entity, and how long after the attack started
  * false positives alerts raised during a benign-only capture (per hour)
  * throughput     flows processed per second, end-to-end alert latency

    python evaluate_pipeline.py                 # standard run
    python evaluate_pipeline.py --repeats 5     # more seeds per scenario
    python evaluate_pipeline.py --quick
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def _add_core():
    here = Path(__file__).resolve().parent
    for p in [here, *here.parents]:
        if (p / "irondome" / "__init__.py").exists():
            sys.path.insert(0, str(p))
            return p
    raise RuntimeError("core not found")


ROOT = _add_core()

from irondome import lab  # noqa: E402
from irondome.features import FeaturePipeline  # noqa: E402
from irondome.correlate import AlertCorrelator  # noqa: E402
from irondome.scoring import LEARNING_SECONDS, ThreatScorer  # noqa: E402
from irondome.schema import THREAT_CLASSES, validate_alert  # noqa: E402

REPORT = ROOT / "docs" / "EVAL_REPORT.md"

SCENARIOS = ["syn_flood", "spoofed_flood", "udp_flood", "udp_amplification", "slowloris",
             "port_scan", "host_sweep", "c2_beacon", "dga", "dns_tunnel", "encrypted_malware", "exfiltration"]


def _entity_ips(alert):
    e = alert.get("entity", {})
    f = alert.get("flow", {})
    return {v for v in (e.get("ip"), e.get("src_ip"), e.get("dst_ip"), f.get("src_ip"), f.get("dst_ip")) if v}


def run_capture(scorer, records, batch_window=1.0):
    """Replay records through the streaming pipeline; return (alerts, timing)."""
    pipe = FeaturePipeline("eval", "replay")
    alerts = []
    t0 = time.time()
    last_eval = None
    pending = []
    for r in records:
        pipe.ingest(r, r["te"])
        wm = r["te"]
        if last_eval is None:
            last_eval = wm
        if wm - last_eval >= batch_window:
            pending = pipe.evaluate(now_wall=wm)
            if pending:
                alerts += scorer.score_many(pending, source={"pipeline": "replay"})
            last_eval = wm
    alerts += scorer.score_many(pipe.flush(), source={"pipeline": "replay"})
    return alerts, time.time() - t0, pipe


def _t(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def eval_scenario(scorer, scenario, seed, warmup=LEARNING_SECONDS + 30.0):
    recs, gt = lab.generate_capture(scenario, seed=seed, warmup=warmup, gap=15)
    truth = gt[0]
    attack_start = truth["start"]
    alerts, secs, pipe = run_capture(scorer, recs)
    targets = {truth.get("target"), truth.get("attacker"), truth.get("host")}
    targets = {t for t in targets if t}
    want_class = truth["threat_class"]
    detections = []
    off = []
    for a in alerts:
        # last_seen = event time of the last contributing flow, i.e. when the evidence was
        # complete. (first_seen of a windowed detector can predate the attack, because the
        # window also holds earlier benign flows.)
        last = _t(a["last_seen"])
        in_window = attack_start <= last <= truth["end"] + 15
        on_target = bool(_entity_ips(a) & targets) or any(
            t in str(a.get("evidence", {}).get("context", {})) for t in targets)
        if a["threat_class"] == want_class and in_window and on_target:
            detections.append(last - attack_start)
        elif not (in_window and on_target):
            off.append(a)
    corr = AlertCorrelator(window=90.0)
    off_incidents = 0
    off_classes: dict[str, int] = {}
    for a in sorted(off, key=lambda a: _t(a["last_seen"])):
        _, new = corr.add(a, now=_t(a["last_seen"]))
        if new:
            off_incidents += 1
            off_classes[a["threat_class"]] = off_classes.get(a["threat_class"], 0) + 1
    return {
        "scenario": scenario, "seed": seed, "records": len(recs), "alerts": len(alerts),
        "detected": bool(detections), "time_to_detect": round(min(detections), 1) if detections else None,
        "correct_alerts": len(detections), "off_target_or_time": off_incidents, "off_classes": off_classes,
        "flows_per_s": round(len(recs) / secs, 0) if secs else 0,
        "schema_errors": sum(len(validate_alert(a)) for a in alerts),
    }


def eval_benign(scorer, seed, minutes=10.0):
    """Benign-only estate. The first LEARNING_SECONDS are the baseline-learning (cold start)
    period and are reported separately; steady-state false positives are counted after it,
    both as raw alerts and as correlated incidents (what the dashboard shows)."""
    learn_min = LEARNING_SECONDS / 60.0
    recs, _ = lab.generate_capture(None, seed=seed, warmup=0, duration=(learn_min + minutes) * 60)
    alerts, secs, pipe = run_capture(scorer, recs)
    learning_end = recs[0]["ts"] + LEARNING_SECONDS
    steady = [a for a in alerts if _t(a["last_seen"]) >= learning_end]
    cold = [a for a in alerts if _t(a["last_seen"]) < learning_end]
    corr = AlertCorrelator(window=90.0)
    incidents = 0
    for a in sorted(steady, key=lambda a: _t(a["last_seen"])):
        _, new = corr.add(a, now=_t(a["last_seen"]))
        incidents += new
    by_class = {}
    for a in steady:
        by_class[a["threat_class"]] = by_class.get(a["threat_class"], 0) + 1
    return {"minutes": minutes, "records": len(recs), "false_alerts": len(steady),
            "fp_per_hour": round(len(steady) / minutes * 60, 2),
            "false_incidents": incidents, "incidents_per_hour": round(incidents / minutes * 60, 2),
            "cold_start_alerts": len(cold), "by_class": by_class,
            "flows_per_s": round(len(recs) / secs, 0) if secs else 0}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--benign-minutes", type=float, default=15.0)
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    repeats = 1 if args.quick else args.repeats
    benign_min = 4.0 if args.quick else args.benign_minutes

    scorer = ThreatScorer()
    modes = {d: scorer.models[d].mode for d in scorer.models}
    print(f"IronDome.ai pipeline evaluation - detector modes: {modes}", flush=True)
    if any(m == "heuristic-fallback" for m in modes.values()):
        print("  (some detectors are using heuristic fallback - run model_training_pipeline.py first)", flush=True)

    rows = []
    t0 = time.time()
    for sc in SCENARIOS:
        runs = [eval_scenario(scorer, sc, seed=100 + i) for i in range(repeats)]
        det = sum(r["detected"] for r in runs)
        ttd = [r["time_to_detect"] for r in runs if r["time_to_detect"] is not None]
        agg = {
            "scenario": sc, "ps_ref": THREAT_CLASSES[lab.SCENARIOS[sc]["threat_class"]]["ps_ref"] if lab.SCENARIOS[sc]["threat_class"] in THREAT_CLASSES else "-",
            "runs": repeats, "detected": det, "detection_rate": det / repeats,
            "median_ttd": round(sorted(ttd)[len(ttd) // 2], 1) if ttd else None,
            "fps": round(sum(r["off_target_or_time"] for r in runs) / repeats, 1),
            "off_classes": {k: sum(r["off_classes"].get(k, 0) for r in runs) for r in runs for k in r["off_classes"]},
            "flows_per_s": round(sum(r["flows_per_s"] for r in runs) / repeats),
            "schema_errors": sum(r["schema_errors"] for r in runs),
        }
        rows.append(agg)
        print(f"  {sc:18s} PS({agg['ps_ref']}) detected {det}/{repeats}  TTD~{agg['median_ttd']}s  "
              f"off-target incidents/run={agg['fps']} {agg['off_classes'] or ''}  {agg['flows_per_s']} flows/s  "
              f"schema errors={agg['schema_errors']}", flush=True)

    print("  benign baseline ...", flush=True)
    benign = eval_benign(scorer, seed=999, minutes=benign_min)
    print(f"    steady state: {benign['false_alerts']} false alerts / {benign['false_incidents']} incidents in "
          f"{benign_min:.0f} min = {benign['incidents_per_hour']} incidents/hour  {benign['by_class']}  "
          f"(cold-start learning period: {benign['cold_start_alerts']} alerts)", flush=True)

    meta = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "repeats": repeats, "detector_modes": modes, "seconds": round(time.time() - t0, 1),
            "scenarios": rows, "benign": benign}
    (ROOT / "docs").mkdir(exist_ok=True)
    write_report(meta)
    (ROOT / "model_microservice" / "models" / "eval_results.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(f"done in {meta['seconds']}s -> {REPORT}", flush=True)


def write_report(meta):
    L = ["# End-to-end pipeline evaluation", "",
         f"_Generated {meta['generated_at']} — each scenario replayed {meta['repeats']} time(s) through the "
         f"streaming pipeline and scored against lab ground truth._", "",
         "Every capture is a benign estate (48 workstations, servers, DNS, backups, calls) with one attack "
         "scenario injected after a 5-minute benign warm-up. **Detection** counts a run where a correct-class "
         "alert's evidence completed inside the attack window on the right entity; **TTD** is the median event "
         "time from attack start to that point; **off-target incidents/run** counts correlated incidents outside "
         "the attack window or entity (a proxy for false positives), with the classes involved.", "",
         "| PS | Scenario | Detected | Detection rate | Median TTD | Off-target incidents/run | Throughput (replay) |",
         "|---|---|---|---|---|---|---|"]
    for r in meta["scenarios"]:
        ttd = f"{r['median_ttd']}s" if r["median_ttd"] is not None else "—"
        oc = ", ".join(f"{k} ×{v}" for k, v in (r.get("off_classes") or {}).items())
        L.append(f"| ({r['ps_ref']}) | `{r['scenario']}` | {r['detected']}/{r['runs']} | "
                 f"{100*r['detection_rate']:.0f}% | {ttd} | {r['fps']}{f' ({oc})' if oc else ''} | {r['flows_per_s']} flows/s |")
    b = meta["benign"]
    L += ["", "## Benign baseline (false positives)", "",
          f"A benign-only estate was replayed for {LEARNING_SECONDS / 60:.0f} minutes of baseline learning plus "
          f"**{b['minutes']:.0f} minutes of steady state** ({b['records']} flows in total). In steady state it produced "
          f"**{b['false_alerts']} false alerts, correlated into {b['false_incidents']} incidents "
          f"= {b['incidents_per_hour']} false incidents per hour** "
          f"(by threat class: `{b['by_class']}`). During the cold-start learning period "
          f"{b['cold_start_alerts']} alert(s) were raised; the live sensor avoids that period by warm-starting "
          "its estate baseline from recent flow history.", "",
          f"Sustained replay throughput: **~{b['flows_per_s']:.0f} flows/second** (single process, "
          "including feature extraction, model inference and alert construction).", "",
          "_All figures are on synthetic lab traffic; deployments should re-validate on their own captures._"]
    REPORT.write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
