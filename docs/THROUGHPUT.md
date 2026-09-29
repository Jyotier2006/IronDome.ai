# Throughput

PS constraint (d) asks every solution to state and demonstrate the traffic rate it was tested against. This file is written by `scripts/benchmark_throughput.py`.

## Method

- A realistic flow mix from the traffic lab (48-workstation estate at 3× scale, plus SYN flood, port scan, DNS tunnel, C2 beacon and exfiltration) is re-timed to look live.
- For each target rate it is exported **one-way over UDP** to the sensor's receive-only collector in MTU-sized datagrams (≤ 1400 bytes, about 4–5 flows each) — the same path a flow exporter behind a data diode uses.
- Each step runs 15 s. The sensor's own counters give the flows it received and processed (feature extraction, model inference, correlation and alerting all included), so loss is measured, not assumed.
- A step passes if loss < 0.5% and p95 alert latency ≤ 3 s.

## Results

_Measured 2026-09-29T15:33:35+00:00 on Windows-11-10.0.26200-SP0 (Python 3.14.2), sender and sensor on the same machine, single sensor process._

| Target flows/s | Sent flows/s | Processed flows/s | Loss | p95 alert latency | Monitored traffic |
|---|---|---|---|---|---|
| 1,000 | 1,000 | 1,000 | 0.00% | - | ~579.3 Mbps |
| 2,500 | 2,500 | 2,500 | 0.00% | 1.13 s | ~639.4 Mbps |
| 5,000 | 4,999 | 4,999 | 0.00% | 2.66 s | ~1,076.2 Mbps |
| 7,500 | 7,499 | 4,778 | 36.28% | 3.15 s | ~4,464.8 Mbps |

## Stated target

**Sustained: 4,999 flow records per second per sensor process** (~1,076.2 Mbps of monitored traffic at a mean of 52.2 KB per flow), with 0.00% loss and p95 alert latency 2.66 s.

## Scaling beyond one process (not yet implemented)

The figure above is for one sensor process. Scaling out is roadmap work, and not simply a matter of hash-sharding flows: some detectors aggregate across hosts (horizontal sweeps span many destinations; prevalence counts how many internal hosts contact a destination), so a multi-process deployment needs flows partitioned by protected host *and* a shared estate-context store (prevalence, host baselines) that all partitions read.

