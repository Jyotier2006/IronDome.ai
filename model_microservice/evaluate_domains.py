"""Evaluate the DGA detector on real, labelled domain lists.

    python evaluate_domains.py --benign ../data/opendns_top.txt
    python evaluate_domains.py --benign ../data/tranco_top.txt --split test
    python evaluate_domains.py --dga my_dga_domains.csv --benign ../data/opendns_top.txt --json out.json

Lists: one domain per line, or CSV lines such as "rank,domain", "family,domain" or
"domain,family" (the field containing a dot is the domain, another field the family).
Lines starting with # are ignored.

Two numbers are reported per list:
  model    - share of domains the per-domain model scores at or above its threshold
  pipeline - the same, but only for domains that pass the sensor's pre-filter
             (the sensor only sends suspicious-looking names to the model, and raises a
             host alert only when >= 3 of a host's domains are flagged within 60 s)
With --split, only domains in that partition of the training split are scored, so
domains the model was trained on can be excluded (use --split test for held-out numbers).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from irondome.domains import domain_split  # noqa: E402
from irondome.features import dga_prefilter  # noqa: E402
from irondome.lexical import domain_features  # noqa: E402
from irondome.scoring import ThreatScorer  # noqa: E402


def load_list(path: Path):
    """[(domain, family)]"""
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip().strip('"') for p in line.replace("\t", ",").split(",")]
        doms = [p for p in parts if "." in p and " " not in p]
        if not doms:
            continue
        dom = doms[0].lower().rstrip(".")
        fam = next((p for p in parts if p and p != doms[0] and not p.isdigit()), "")
        out.append((dom, fam))
    return out


def score_list(scorer, items, split=None):
    m = scorer.models["dga_domain"]
    if m.model is None:
        sys.exit("no trained dga_domain model found - run model_training_pipeline.py first")
    import numpy as np
    if split:
        items = [(d, f) for d, f in items if domain_split(d) == split]
    feats = [domain_features(d) for d, _ in items]
    X = np.array([[float(f[k]) for k in m.features] for f in feats], dtype=np.float64)
    p = m.model.predict_proba(X)[:, 1] if len(X) else np.zeros(0)
    rows = []
    for (d, fam), f, pi in zip(items, feats, p):
        flagged = pi >= m.threshold
        rows.append({"domain": d, "family": fam, "score": float(pi), "model": bool(flagged),
                     "pipeline": bool(flagged and dga_prefilter(f, "NOERROR"))})
    return rows


def summary(rows):
    n = len(rows) or 1
    return {"n": len(rows), "model_rate": sum(r["model"] for r in rows) / n,
            "pipeline_rate": sum(r["pipeline"] for r in rows) / n}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benign", type=Path, action="append", default=[], help="benign domain list (repeatable)")
    ap.add_argument("--dga", type=Path, action="append", default=[], help="DGA domain list (repeatable)")
    ap.add_argument("--split", choices=["train", "validation", "test", "stress"],
                    help="only score domains in this partition of the training split")
    ap.add_argument("--json", type=Path, help="write the results as JSON")
    args = ap.parse_args()
    if not args.benign and not args.dga:
        ap.error("give at least one --benign or --dga list")

    scorer = ThreatScorer(load_intel=False)
    thr = scorer.models["dga_domain"].threshold
    print(f"DGA model threshold {thr}" + (f", partition '{args.split}' only" if args.split else ""))
    result = {"threshold": thr, "split": args.split, "benign": {}, "dga": {}}

    for path in args.benign:
        rows = score_list(scorer, load_list(path), args.split)
        s = summary(rows)
        top = sorted((r for r in rows if r["model"]), key=lambda r: -r["score"])[:12]
        print(f"\nbenign  {path.name}: {s['n']:,} domains  false positives: model {100 * s['model_rate']:.2f}%  "
              f"pipeline {100 * s['pipeline_rate']:.2f}%")
        if top:
            print("  highest-scoring benign domains: " + ", ".join(r["domain"] for r in top))
        result["benign"][path.name] = {**s, "top_false_positives": [r["domain"] for r in top]}

    for path in args.dga:
        rows = score_list(scorer, load_list(path), args.split)
        s = summary(rows)
        print(f"\nDGA     {path.name}: {s['n']:,} domains  detected: model {100 * s['model_rate']:.1f}%  "
              f"pipeline {100 * s['pipeline_rate']:.1f}%")
        fams = defaultdict(list)
        for r in rows:
            fams[r["family"] or "(unlabelled)"].append(r)
        per = {f: summary(rs) for f, rs in fams.items()}
        if len(per) > 1:
            for f, fs in sorted(per.items(), key=lambda kv: kv[1]["model_rate"]):
                print(f"  {f:28s} {fs['n']:6,}  model {100 * fs['model_rate']:5.1f}%  pipeline {100 * fs['pipeline_rate']:5.1f}%")
        result["dga"][path.name] = {**s, "families": per}

    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"\n-> {args.json}")


if __name__ == "__main__":
    main()
