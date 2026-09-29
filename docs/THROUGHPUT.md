# Throughput

PS constraint (d) asks every solution to state and demonstrate the traffic rate it was tested against. This file is written by `scripts/benchmark_throughput.py`. Throughput is stated in **flow records per second**, the unit the PS accepts. Bandwidth is not quoted, because it depends entirely on the flow-size mix of the (simulated) traffic.

## Method

- A realistic flow mix from the traffic lab (48-workstation estate at 3× scale, plus SYN flood, port scan, DNS tunnel, C2 beacon and exfiltration) is re-timed to look live.
- For each target rate it is exported **one-way over UDP** to the sensor's receive-only collector in MTU-sized datagrams (≤ 1400 bytes, about 4–5 flows each), the same path a flow exporter behind a data diode uses.
- The sensor's own counters give the flows it received and processed (feature extraction, model inference, correlation and alerting all included), so loss is measured, not assumed.
- A step passes if loss < 0.5% and p95 alert latency ≤ 3 s.

## Stated target

- **single process: 4,999 flow records per second**, 0.00% loss, p95 alert latency 2.34 s.
- **4 worker processes: 4,999 flow records per second**, 0.00% loss, p95 alert latency 1.01 s.

## Results: single process

_Measured 2026-09-29T18:41:19+00:00 on Windows-11-10.0.26200-SP0 (Python 3.14.2, 20 logical CPUs), sender and sensor on the same machine, 15 s per step._

| Target flows/s | Sent flows/s | Processed flows/s | Loss | p95 alert latency | Result |
|---|---|---|---|---|---|
| 1,000 | 1,000 | 1,000 | 0.00% | - | within budget |
| 2,500 | 2,500 | 2,500 | 0.00% | 0.97 s | within budget |
| 5,000 | 4,999 | 4,999 | 0.00% | 2.34 s | within budget |
| 7,500 | 7,499 | 2,483 | 66.89% | 6.75 s | over budget |

## Results: 4 worker processes

_Measured 2026-09-29T18:43:04+00:00 on Windows-11-10.0.26200-SP0 (Python 3.14.2, 20 logical CPUs), sender and sensor on the same machine, 15 s per step._

| Target flows/s | Sent flows/s | Processed flows/s | Loss | p95 alert latency | Result |
|---|---|---|---|---|---|
| 5,000 | 4,999 | 4,999 | 0.00% | 1.01 s | within budget |
| 7,500 | 7,500 | 7,500 | 0.00% | 5.03 s | over budget |
| 10,000 | 10,000 | 10,000 | 0.00% | 5.03 s | over budget |
| 12,500 | 12,498 | 12,498 | 0.00% | 3.30 s | over budget |
| 15,000 | 15,000 | 15,000 | 0.00% | 3.89 s | over budget |

## How scale-out works

With `IRONDOME_WORKERS=N`, feature extraction and inference run in N worker processes. Flows are partitioned by protected host (and by initiator for scan detection), and the main process keeps the shared estate context (prevalence, context age) and attaches it to every routed flow. See `ARCHITECTURE.md`, section 3. Ingest, routing and correlation remain in one process, which bounds the gain; scaling across machines would need that context in a shared store.

Loss counts every flow the collector received but a pipeline or worker queue shed. With workers, the limit is latency rather than loss: partitioning by protected host sends all traffic aimed at one very busy host (here the web server that is also the flood victim) to one worker, which then lags. In the 4-worker run that worker handled about 600k of the 1.17M routed records while the other three handled about 200k each, so p95 latency, not loss, sets the budgeted rate.

