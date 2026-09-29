"""IronDome.ai - model training & validation pipeline (SIH PS 26145).

Trains one calibrated classifier per detector on labelled samples produced by the
traffic lab and extracted by the *same* streaming FeaturePipeline the sensor runs.

    python model_training_pipeline.py                # full run (a few minutes)
    python model_training_pipeline.py --quick        # small smoke-test run
    python model_training_pipeline.py --only ddos,dga_domain

Methodology
  * four disjoint, independently seeded data sets per detector:
      train       fit the model
      validation  choose the decision threshold, compute feature importance
      test        held-out evaluation, same distribution as training
      stress      held-out evaluation on a *shifted* distribution (weaker / slower /
                  stealthier attacks, harder negatives) - never seen in training
  * model: HistGradientBoostingClassifier (class-balanced) wrapped in 3-fold isotonic
    calibration, so the reported confidence behaves like a probability
  * outputs: models/<detector>.joblib, models/model_card.json, docs/MODEL_REPORT.md,
    backend/sensor-service/intel/lab_ja3_fingerprints.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path


def _add_core_to_path():
    here = Path(__file__).resolve().parent
    for p in [here, *here.parents]:
        if (p / "irondome" / "__init__.py").exists():
            sys.path.insert(0, str(p))
            return p
    raise RuntimeError("irondome core library not found")


ROOT = _add_core_to_path()

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import sklearn  # noqa: E402
from sklearn.calibration import CalibratedClassifierCV  # noqa: E402
from sklearn.ensemble import HistGradientBoostingClassifier  # noqa: E402
from sklearn.inspection import permutation_importance  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    average_precision_score, brier_score_loss, confusion_matrix, f1_score, precision_recall_fscore_support,
    roc_auc_score,
)

from irondome import __version__ as CORE_VERSION  # noqa: E402
from irondome.features import FEATURE_DOCS, FEATURES  # noqa: E402
from irondome.samples import LABELS, generate  # noqa: E402
from irondome.schema import DETECTORS, THREAT_CLASSES  # noqa: E402
from irondome.traffic import lab_ja3_watchlist  # noqa: E402

MODELS_DIR = Path(__file__).resolve().parent / "models"
REPORT_PATH = ROOT / "docs" / "MODEL_REPORT.md"
INTEL_PATH = ROOT / "backend" / "sensor-service" / "intel" / "lab_ja3_fingerprints.json"

# training samples per class; validation / test = 30 % of that, stress = 20 %
SIZES = {
    "ddos": 700,
    "recon_scan": 900,
    "c2_beacon": 2500,
    "dga_domain": 10000,
    "dns_tunnel": 1500,
    "encrypted_malware": 3000,
    "exfiltration": 2000,
}
SPLITS = {"train": (1.0, 11, False), "validation": (0.3, 23, False), "test": (0.3, 37, False), "stress": (0.2, 53, True)}

TITLES = {
    "ddos": "Volumetric / protocol DDoS classifier",
    "recon_scan": "Reconnaissance / port-scan classifier",
    "c2_beacon": "C2 beaconing (periodicity) classifier",
    "dga_domain": "DGA domain (lexical) classifier",
    "dns_tunnel": "DNS tunnelling classifier",
    "encrypted_malware": "Encrypted-session malware classifier",
    "exfiltration": "Data exfiltration (volume asymmetry) classifier",
}


def _chunk(args):
    detector, label, n, seed, shift, split = args
    return label, *generate(detector, label, n, seed, shift, split=split)


BENIGN_FACTOR = 3   # extra benign samples in held-out splits so false-positive rates are measurable


def build_split(pool, detector, split, per_class, workers):
    frac, seed_base, shift = SPLITS[split]
    n_base = max(20, int(per_class * frac))
    chunks = []
    step = max(40, math.ceil(n_base / max(1, workers)))
    for li, label in enumerate(LABELS[detector]):
        n = n_base * (BENIGN_FACTOR if li == 0 and split != "train" else 1)
        done = 0
        k = 0
        while done < n:
            m = min(step, n - done)
            seed = int(hashlib.sha1(f"{detector}|{label}|{split}|{seed_base}|{k}".encode()).hexdigest()[:8], 16)
            chunks.append((detector, label, m, seed, shift, split))
            done += m
            k += 1
    X, y, metas = [], [], []
    for label, rows, mts in pool.map(_chunk, chunks):
        X += rows
        y += [LABELS[detector].index(label)] * len(rows)
        metas += mts
    return np.asarray(X, dtype=np.float64), np.asarray(y, dtype=np.int64), metas


def make_model():
    # Early stopping keeps the forest small (these tasks converge well before the cap),
    # and ensemble=False calibrates one model on cross-validated predictions instead of
    # averaging three - inference cost is dominated by the number of trees walked.
    base = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1, max_leaf_nodes=31,
                                          l2_regularization=1.0, class_weight="balanced",
                                          early_stopping=True, validation_fraction=0.12, n_iter_no_change=15,
                                          tol=1e-4, random_state=7)
    return CalibratedClassifierCV(base, method="isotonic", cv=3, ensemble=False)


def attack_score(probs):
    return 1.0 - probs[:, 0]   # class 0 is always "benign"


MAX_FPR = 0.005   # operating-point budget: at most 0.5 % of benign validation windows flagged


def choose_threshold(y_val, score_val, max_fpr=MAX_FPR):
    """Operating point on P(attack): the best-F1 threshold among those whose false-positive
    rate on validation stays within `max_fpr` (streaming detectors score benign windows
    continuously, so the FP budget comes first). Ties -> middle of the optimal range."""
    truth = y_val != 0
    benign = ~truth
    grid = np.linspace(0.05, 0.97, 93)
    f1s = np.array([f1_score(truth, score_val >= t, zero_division=0) for t in grid])
    fprs = np.array([(score_val[benign] >= t).mean() if benign.any() else 0.0 for t in grid])
    ok = fprs <= max_fpr
    if not ok.any():
        return round(float(grid[np.argmin(fprs)]), 3)
    best_f1 = f1s[ok].max()
    best = grid[ok & (f1s >= best_f1 - 1e-6)]
    return round(float(np.median(best)), 3)


def ece(prob, truth, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    total = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (prob >= lo) & (prob < hi) if hi < 1 else (prob >= lo) & (prob <= hi)
        if m.any():
            total += m.mean() * abs(prob[m].mean() - truth[m].mean())
    return float(total)


def evaluate(model, X, y, classes, threshold, metas):
    probs = model.predict_proba(X)
    score = attack_score(probs)
    truth = y != 0
    flagged = score >= threshold
    # detection (benign vs attack)
    p, r, f, _ = precision_recall_fscore_support(truth, flagged, average="binary", zero_division=0)
    benign = ~truth
    out = {
        "samples": int(len(y)),
        "precision": round(float(p), 4),
        "recall": round(float(r), 4),
        "f1": round(float(f), 4),
        "false_positive_rate": round(float(flagged[benign].mean()) if benign.any() else 0.0, 4),
        "roc_auc": round(float(roc_auc_score(truth, score)), 4) if 0 < truth.sum() < len(truth) else None,
        "pr_auc": round(float(average_precision_score(truth, score)), 4) if truth.any() else None,
        "brier": round(float(brier_score_loss(truth, score)), 4),
        "ece": round(ece(score, truth.astype(float)), 4),
    }
    # technique / class level
    if len(classes) > 2:
        pred = np.where(flagged, 1 + np.argmax(probs[:, 1:], axis=1), 0)
        pc, rc, fc, sc = precision_recall_fscore_support(y, pred, labels=list(range(len(classes))), zero_division=0)
        out["per_class"] = {c: {"precision": round(float(pc[i]), 4), "recall": round(float(rc[i]), 4),
                                "f1": round(float(fc[i]), 4), "support": int(sc[i])} for i, c in enumerate(classes)}
        out["macro_f1"] = round(float(np.mean(fc)), 4)
        out["confusion_matrix"] = confusion_matrix(y, pred, labels=list(range(len(classes)))).tolist()
    else:
        out["confusion_matrix"] = confusion_matrix(truth, flagged, labels=[False, True]).astype(int).tolist()
    # behaviour per sample kind (e.g. DGA family, benign hard-negative type)
    kinds = {}
    for i, m in enumerate(metas):
        k = m.get("kind", "?")
        d = kinds.setdefault(k, {"n": 0, "flagged": 0, "attack": bool(truth[i])})
        d["n"] += 1
        d["flagged"] += int(flagged[i])
    out["per_kind"] = {k: {"n": v["n"], ("detection_rate" if v["attack"] else "false_positive_rate"):
                           round(v["flagged"] / v["n"], 4)} for k, v in sorted(kinds.items())}
    return out


def baselines(X, names):
    out = {}
    for j, n in enumerate(names):
        col = X[:, j]
        out[n] = {"mean": round(float(col.mean()), 6), "std": round(float(col.std()), 6),
                  "p50": round(float(np.percentile(col, 50)), 6), "p95": round(float(np.percentile(col, 95)), 6)}
    return out


def importances(model, X, y, names, threshold):
    idx = np.random.RandomState(0).choice(len(y), size=min(1500, len(y)), replace=False)
    Xs, ys = X[idx], (y[idx] != 0)

    class _Binary:  # wrap so importance is measured on the benign-vs-attack decision
        def fit(self, *a):
            return self

        def predict(self, Xp):
            return attack_score(model.predict_proba(Xp)) >= threshold

        def score(self, Xp, yp):
            return f1_score(yp, self.predict(Xp), zero_division=0)

    res = permutation_importance(_Binary(), Xs, ys, n_repeats=3, random_state=0, scoring=None)
    order = np.argsort(-res.importances_mean)
    return [{"feature": names[i], "importance": round(float(res.importances_mean[i]), 4)} for i in order[:10]]


def inference_speed(model, X):
    rows = X[np.random.RandomState(1).choice(len(X), size=min(1000, len(X)), replace=True)]
    model.predict_proba(rows)
    t = time.perf_counter()
    for _ in range(3):
        model.predict_proba(rows)
    return round((time.perf_counter() - t) / (3 * len(rows)) * 1e6, 2)


def train_detector(pool, detector, per_class, workers):
    names = FEATURES[detector]
    classes = LABELS[detector]
    t0 = time.time()
    data = {s: build_split(pool, detector, s, per_class, workers) for s in SPLITS}
    gen_s = time.time() - t0
    Xtr, ytr, _ = data["train"]
    print(f"  data: " + ", ".join(f"{s}={len(v[1])}" for s, v in data.items()) + f"  ({gen_s:.1f}s)", flush=True)

    t1 = time.time()
    model = make_model()
    model.fit(Xtr, ytr)
    fit_s = time.time() - t1

    Xv, yv, mv = data["validation"]
    threshold = choose_threshold(yv, attack_score(model.predict_proba(Xv)))
    metrics = {s: evaluate(model, *data[s][:2], classes, threshold, data[s][2]) for s in ("validation", "test", "stress")}
    card_info = DETECTORS[detector]
    tc = card_info["threat_class"]
    card = {
        "detector": detector,
        "title": TITLES[detector],
        "threat_class": tc,
        "ps_ref": THREAT_CLASSES[tc]["ps_ref"],
        "algorithm": f"HistGradientBoostingClassifier ({model.calibrated_classifiers_[0].estimator.n_iter_} "
                     "boosting iterations after early stopping, 31 leaves, class-balanced) "
                     "+ isotonic probability calibration fitted on 3-fold cross-validated predictions",
        "classes": classes,
        "features": [{"name": n, "description": FEATURE_DOCS.get(n, "")} for n in names],
        "threshold": threshold,
        "threshold_rule": f"attack if 1 - P(benign) >= threshold (best F1 on validation within a "
                          f"{MAX_FPR:.1%} false-positive budget)",
        "train": {"samples": int(len(ytr)), "per_class": {c: int((ytr == i).sum()) for i, c in enumerate(classes)},
                  "generation_seconds": round(gen_s, 1), "fit_seconds": round(time.time() - t1, 1)},
        "metrics": metrics,
        "baselines": baselines(Xtr[ytr == 0], names),
        "importance": importances(model, Xv, yv, names, threshold),
        "inference_us_per_row": inference_speed(model, Xv),
    }
    if detector == "dga_domain":
        card["real_world"] = real_world_dga(model, threshold, names)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    path = MODELS_DIR / f"{detector}.joblib"
    joblib.dump({"model": model, "detector": detector, "features": names, "classes": classes,
                 "threshold": threshold, "core_version": CORE_VERSION}, path, compress=3)
    card["file"] = path.name
    card["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    te = metrics["test"]
    st = metrics["stress"]
    print(f"  fit {fit_s:.1f}s  thr={threshold}  test P={te['precision']} R={te['recall']} F1={te['f1']} "
          f"FPR={te['false_positive_rate']} AUC={te['roc_auc']} | stress R={st['recall']} FPR={st['false_positive_rate']}",
          flush=True)
    return card


def real_world_dga(model, threshold, names):
    """False-positive rates of the DGA model on real popular domains it never trained on:
    the held-out Tranco test partition, and the OpenDNS top list (all of it, and only the
    domains outside the training partition)."""
    from irondome.domains import OPENDNS, TRANCO, domain_split, list_header, read_list, real_benign
    from irondome.features import dga_prefilter
    from irondome.lexical import domain_features

    def rates(domains):
        if not domains:
            return None
        feats = [domain_features(d) for d in domains]
        p = model.predict_proba(np.array([[float(f[k]) for k in names] for f in feats]))[:, 1]
        flagged = p >= threshold
        piped = [bool(fl and dga_prefilter(f, "NOERROR")) for fl, f in zip(flagged, feats)]
        top = [domains[i] for i in np.argsort(-p)[:10] if flagged[i]]
        return {"domains": len(domains), "model_fpr": round(float(flagged.mean()), 4),
                "pipeline_fpr": round(sum(piped) / len(piped), 4), "top_false_positives": top}

    out = {}
    if TRANCO.exists():
        out["tranco_test"] = {"list": list_header(TRANCO), **(rates(list(real_benign("test"))) or {})}
    if OPENDNS.exists():
        odns = sorted(set(read_list(OPENDNS)))
        out["opendns_all"] = {"list": list_header(OPENDNS), **(rates(odns) or {})}
        out["opendns_not_in_training"] = {"list": list_header(OPENDNS),
                                          **(rates([d for d in odns if domain_split(d) != "train"]) or {})}
    for k, v in out.items():
        if "model_fpr" in v:
            print(f"  real-world {k}: {v['domains']} domains, false positives model {100 * v['model_fpr']:.2f}% "
                  f"pipeline {100 * v['pipeline_fpr']:.2f}%", flush=True)
    return out


def build_lexical(use_real: bool):
    """Build irondome/lexical_model.json from the Tranco *training* partition (before any
    worker starts, so every process computes features with the same tables)."""
    from irondome import lexical
    from irondome.domains import TRANCO, list_header, real_benign
    if not use_real:
        return lexical.LEXICAL_MODEL
    train = list(real_benign("train"))
    if not train:
        print("  no data/tranco_top.txt - keeping the existing lexical model "
              "(python scripts/fetch_domain_lists.py to use real domains)", flush=True)
        return lexical.LEXICAL_MODEL
    doc = lexical.build_lexical_model(train, source=f"{list_header(TRANCO)} - training partition")
    lexical.LEXICAL_MODEL_PATH.write_text(json.dumps(doc, separators=(",", ":")) + "\n", encoding="utf-8")
    info = lexical._load_lexical_model()
    print(f"  lexical model: {doc['corpus_domains']} real training domains, {len(doc['vocabulary'])} vocabulary "
          f"tokens, {len(doc['tld_rarity'])} suffixes -> {lexical.LEXICAL_MODEL_PATH.name}", flush=True)
    return info


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def _pct(x):
    return "-" if x is None else f"{100 * x:.1f}%"


def write_report(cards, meta):
    L = []
    L.append("# Model validation report")
    L.append("")
    L.append(f"_Auto-generated by `model_microservice/model_training_pipeline.py` on {meta['generated_at']} "
             f"(core {meta['core_version']}, scikit-learn {meta['sklearn']}, Python {meta['python']}"
             f"{', QUICK run' if meta['quick'] else ''})._")
    L.append("")
    L.append("Every number below comes from data the model never saw during training. **Test** has the same "
             "distribution as training; **Stress** is deliberately shifted (weaker, slower or stealthier attacks and "
             "harder benign look-alikes) to show how the models degrade. Benign domains for the DGA model come from "
             "the real Tranco top-sites list (held-out partitions for validation and test); everything else is "
             "synthetic lab traffic, so deployments should re-validate on captures from their own network "
             "(`model_microservice/recalibrate.py`; methodology: the *ML pipeline* section of `README.md`).")
    L.append("")
    L.append("| PS | Detector | Test precision | Test recall | Test F1 | Test FPR | ROC-AUC | Stress recall | Stress FPR | Threshold | Inference |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for det, c in cards.items():
        te, st = c["metrics"]["test"], c["metrics"]["stress"]
        L.append(f"| ({c['ps_ref']}) | `{det}` | {_pct(te['precision'])} | {_pct(te['recall'])} | {te['f1']:.3f} | "
                 f"{_pct(te['false_positive_rate'])} | {te['roc_auc']} | {_pct(st['recall'])} | "
                 f"{_pct(st['false_positive_rate'])} | {c['threshold']} | {c['inference_us_per_row']} µs/row |")
    L.append("")
    for det, c in cards.items():
        L.append(f"## ({c['ps_ref']}) {c['title']} — `{det}`")
        L.append("")
        L.append(f"- **Algorithm:** {c['algorithm']}")
        L.append(f"- **Classes:** {', '.join(c['classes'])}")
        L.append(f"- **Training samples:** {c['train']['samples']} "
                 f"({', '.join(f'{k}: {v}' for k, v in c['train']['per_class'].items())})")
        L.append(f"- **Decision threshold:** {c['threshold']} — {c['threshold_rule']}")
        L.append("")
        L.append("| Split | Samples | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC | Brier | ECE |")
        L.append("|---|---|---|---|---|---|---|---|---|---|")
        for s in ("validation", "test", "stress"):
            m = c["metrics"][s]
            L.append(f"| {s} | {m['samples']} | {_pct(m['precision'])} | {_pct(m['recall'])} | {m['f1']:.3f} | "
                     f"{_pct(m['false_positive_rate'])} | {m['roc_auc']} | {m['pr_auc']} | {m['brier']} | {m['ece']} |")
        L.append("")
        if "per_class" in c["metrics"]["test"]:
            L.append("Per-technique results on the test set:")
            L.append("")
            L.append("| Class | Precision | Recall | F1 | Support |")
            L.append("|---|---|---|---|---|")
            for k, v in c["metrics"]["test"]["per_class"].items():
                L.append(f"| {k} | {_pct(v['precision'])} | {_pct(v['recall'])} | {v['f1']:.3f} | {v['support']} |")
            L.append("")
        L.append("Behaviour by scenario (test → stress):")
        L.append("")
        L.append("| Scenario | Metric | Test | Stress |")
        L.append("|---|---|---|---|")
        tk, sk = c["metrics"]["test"]["per_kind"], c["metrics"]["stress"]["per_kind"]
        for k in sorted(set(tk) | set(sk)):
            metric = "detection rate" if "detection_rate" in (tk.get(k) or sk.get(k)) else "false-positive rate"
            key = "detection_rate" if metric == "detection rate" else "false_positive_rate"
            L.append(f"| {k} | {metric} | {_pct(tk[k][key]) if k in tk else '-'} | {_pct(sk[k][key]) if k in sk else '-'} |")
        L.append("")
        if c.get("real_world"):
            L.append("**Real-world check: popular benign domains the model never trained on**")
            L.append("")
            L.append("| List | Domains | Flagged by the model | Flagged after the sensor's pre-filter | Highest-scoring examples |")
            L.append("|---|---|---|---|---|")
            for k, v in c["real_world"].items():
                if "model_fpr" in v:
                    L.append(f"| {k.replace('_', ' ')} ({v['list']}) | {v['domains']:,} | {_pct(v['model_fpr'])} | "
                             f"{_pct(v['pipeline_fpr'])} | {', '.join(v['top_false_positives'][:5]) or '-'} |")
            L.append("")
            L.append("A host alert additionally needs at least 3 flagged domains from the same host within 60 s. "
                     "Recall on real DGA families is measured with `evaluate_domains.py --dga <list>`.")
            L.append("")
        L.append("Most influential features (permutation importance on validation):")
        L.append("")
        L.append("| Feature | Importance | Meaning |")
        L.append("|---|---|---|")
        docs = {f["name"]: f["description"] for f in c["features"]}
        for imp in c["importance"]:
            L.append(f"| `{imp['feature']}` | {imp['importance']} | {docs.get(imp['feature'], '')} |")
        L.append("")
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text("\n".join(L) + "\n", encoding="utf-8")


def write_intel():
    INTEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    wl = lab_ja3_watchlist()
    doc = {
        "description": "JA3 fingerprints of the traffic lab's simulated malware families. NOT real threat "
                       "intelligence: it only matches lab traffic (disable with IRONDOME_LAB_JA3=off). Real "
                       "fingerprints come from abuse.ch SSLBL in sslbl_ja3.csv.",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "entries": [{"ja3": k, "family": v, "source": "traffic-lab"} for k, v in sorted(wl.items())],
    }
    INTEL_PATH.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="small data sets (smoke test)")
    ap.add_argument("--only", default="", help="comma-separated detectors to (re)train")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--no-real-domains", action="store_true",
                    help="do not use data/tranco_top.txt for the DGA model even if present")
    args = ap.parse_args()

    detectors = [d for d in SIZES if not args.only or d in args.only.split(",")]
    card_path = MODELS_DIR / "model_card.json"
    existing = {}
    if card_path.exists() and args.only:
        existing = json.loads(card_path.read_text(encoding="utf-8")).get("detectors", {})

    print(f"IronDome.ai training - core {CORE_VERSION}, scikit-learn {sklearn.__version__}, "
          f"{args.workers} worker(s){' [quick]' if args.quick else ''}", flush=True)
    t_all = time.time()
    cards = dict(existing)
    lexical_info = build_lexical(not args.no_real_domains and "dga_domain" in detectors)
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for det in detectors:
            print(f"[{det}]", flush=True)
            per_class = SIZES[det] // (6 if args.quick else 1)
            cards[det] = train_detector(pool, det, per_class, args.workers)
    cards = {d: cards[d] for d in SIZES if d in cards}
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "core_version": CORE_VERSION,
        "sklearn": sklearn.__version__,
        "numpy": np.__version__,
        "python": platform.python_version(),
        "quick": args.quick,
        "lexical_model": lexical_info,
        "total_seconds": round(time.time() - t_all, 1),
    }
    card_path.write_text(json.dumps({**meta, "detectors": cards}, indent=2) + "\n", encoding="utf-8")
    write_report(cards, meta)
    write_intel()
    print(f"done in {meta['total_seconds']}s -> {card_path}, {REPORT_PATH}, {INTEL_PATH}", flush=True)


if __name__ == "__main__":
    main()
