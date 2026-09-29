# IronDome.ai models: training, evaluation, re-calibration

Offline tooling for the seven detectors the sensor loads from `models/`.

```bash
pip install -r requirements.txt
python ../scripts/fetch_domain_lists.py      # optional: real Tranco / OpenDNS lists for the DGA model
python model_training_pipeline.py            # ~1.5 min: models/*.joblib, model_card.json, docs/MODEL_REPORT.md
python evaluate_pipeline.py                  # ~6 min: end-to-end replay vs ground truth -> docs/EVAL_REPORT.md
python evaluate_domains.py --benign ../data/opendns_top.txt --dga your_dga_list.csv
python recalibrate.py --capture site_baseline.pcapng --dry-run
```

| Script | What it does |
|---|---|
| `model_training_pipeline.py` | Generates labelled windows with the traffic lab and the sensor's own feature extractors. Benign DGA domains come from the real Tranco list when downloaded. Trains HistGradientBoosting + isotonic calibration per detector and chooses thresholds within a 0.5% false-positive budget. Reports test and shifted "stress" results and a real-world domain check |
| `evaluate_pipeline.py` | Replays captures with injected attacks through the full streaming pipeline: detection rate, time-to-detect, off-target incidents and the false-incident rate on a benign-only estate |
| `evaluate_domains.py` | DGA detector on any labelled domain lists: per-list false positives, per-family recall |
| `recalibrate.py` | Replays captures from *your* network, measures each detector's false-alarm rate on its benign windows and raises thresholds that exceed the budget (never lowers them). Checks recall on labelled attack windows, backs up the old models and writes `docs/RECALIBRATION.md` |

## Validating on real traffic

The shipped models learned attacks from the traffic lab, which emulates the tools named in
the PS. Before relying on them in a new network:

1. Record a benign baseline with the sensor's tap (tcpdump / Wireshark) and run
   `recalibrate.py --capture baseline.pcapng`.
2. In an isolated lab VM, run the real tools (hping3, nmap, dnscat2, iodine, a C2
   framework) against lab targets, record with tcpdump, write the attack windows in the
   ground-truth format of `captures/*.truth.json`, and run
   `recalibrate.py --capture redteam.pcapng --truth redteam.truth.json --dry-run` to see recall.
3. Check the DGA model with `evaluate_domains.py --dga <labelled DGA list>`.

## Docker

```bash
docker build -f model_microservice/Dockerfile -t irondome-training .      # from the repository root
docker run --rm -v "$PWD/model_microservice/models:/app/model_microservice/models" -v "$PWD/docs:/app/docs" -v "$PWD/data:/app/data" irondome-training
```
