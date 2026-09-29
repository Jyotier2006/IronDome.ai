# Site re-calibration

_Generated 20260929T180258Z by `model_microservice/recalibrate.py` (dry run)._

Captures: recon_tunnel_tls.jsonl.gz (10,138 flows). Labels: ground truth recon_tunnel_tls.truth.json. False-positive budget: 0.5%.

| Detector | Benign | Attack | Threshold | FPR on site benign | Recall on labelled attacks |
|---|---|---|---|---|---|
| `ddos` | 32 windows | 0 | 0.595 → 0.595 | 0.00% → 0.00% | - → - |
| `c2_beacon` | 26 windows | 0 | 0.83 → 0.83 | 0.00% → 0.00% | - → - |
| `dga_domain` | 0 domains | 0 | 0.965 → 0.965 | - → - | - → - |
| `dns_tunnel` | 0 windows | 30 | 0.51 → 0.51 | - → - | 100.00% → 100.00% |
| `encrypted_malware` | 1,149 windows | 78 | 0.275 → 0.275 | 0.00% → 0.00% | 82.05% → 82.05% |
| `recon_scan` | 13 windows | 16 | 0.82 → 0.82 | 0.00% → 0.00% | 100.00% → 100.00% |
| `exfiltration` | 0 windows | 0 | 0.68 → 0.68 | - → - | - → - |

Thresholds are only raised, never lowered below the lab-validated value. The DGA row counts individual queried domains, because that model scores one domain at a time.
