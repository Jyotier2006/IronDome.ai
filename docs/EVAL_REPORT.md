# End-to-end pipeline evaluation

_Generated 2026-09-29T18:52:22+00:00 — each scenario replayed 3 time(s) through the streaming pipeline and scored against lab ground truth._

Every capture is a benign estate (48 workstations, servers, DNS, backups, calls) with one attack scenario injected after a 5-minute benign warm-up. **Detection** counts a run where a correct-class alert's evidence completed inside the attack window on the right entity; **TTD** is the median event time from attack start to that point; **off-target incidents/run** counts correlated incidents outside the attack window or entity (a proxy for false positives), with the classes involved.

| PS | Scenario | Detected | Detection rate | Median TTD | Off-target incidents/run | Throughput (replay) |
|---|---|---|---|---|---|---|
| (a) | `syn_flood` | 3/3 | 100% | 2.0s | 0.0 | 10357 flows/s |
| (a) | `spoofed_flood` | 3/3 | 100% | 2.0s | 0.0 | 8896 flows/s |
| (a) | `udp_flood` | 3/3 | 100% | 2.0s | 0.0 | 8247 flows/s |
| (a) | `udp_amplification` | 3/3 | 100% | 2.0s | 0.0 | 7103 flows/s |
| (a) | `slowloris` | 3/3 | 100% | 12.0s | 0.0 | 4667 flows/s |
| (e) | `port_scan` | 3/3 | 100% | 1.1s | 0.0 | 3161 flows/s |
| (e) | `host_sweep` | 3/3 | 100% | 1.4s | 1.0 (recon_scan ×3) | 1971 flows/s |
| (b) | `c2_beacon` | 3/3 | 100% | 36.0s | 0.0 | 3823 flows/s |
| (c) | `dga` | 3/3 | 100% | 1.6s | 0.0 | 3470 flows/s |
| (c) | `dns_tunnel` | 3/3 | 100% | 1.1s | 0.0 | 4421 flows/s |
| (d) | `encrypted_malware` | 3/3 | 100% | 3.2s | 0.0 | 4451 flows/s |
| (f) | `exfiltration` | 3/3 | 100% | 10.0s | 0.0 | 4370 flows/s |

## Benign baseline (false positives)

A benign-only estate was replayed for 5 minutes of baseline learning plus **15 minutes of steady state** (109279 flows in total). In steady state it produced **0 false alerts, correlated into 0 incidents = 0.0 false incidents per hour** (by threat class: `{}`). During the cold-start learning period 0 alert(s) were raised; the live sensor avoids that period by warm-starting its estate baseline from recent flow history.

Sustained replay throughput: **~4263 flows/second** (single process, including feature extraction, model inference and alert construction).

_All figures are on synthetic lab traffic; deployments should re-validate on their own captures._
