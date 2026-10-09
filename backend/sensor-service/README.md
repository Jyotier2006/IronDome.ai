# IronDome.ai sensor service

The passive sensor: a receive-only flow collector, the streaming detection pipeline and
the REST + Socket.IO API the dashboard uses. It never sends anything to the network it
observes and has no mitigation endpoint.

```bash
pip install -r requirements.txt
python sensor_service.py                          # API :3001, collector UDP :2055, built-in traffic lab on
IRONDOME_LAB=off python sensor_service.py          # real exporters / replays only
IRONDOME_WORKERS=4 python sensor_service.py        # scale-out across 4 detection processes
```

## Inputs (UDP 2055, receive-only)

| Format | Notes |
|---|---|
| JSON biflow records | one per line or a JSON array; carries DNS/TLS/QUIC metadata, so every detector works |
| NetFlow v5 | counters only; one direction per record |
| NetFlow v9 / IPFIX | template-based; IPFIX RFC 5103 reverse elements fill the responder side |
| sFlow v5 | sampled packet headers rebuilt into flows and scaled by the sampling rate |

Also `POST /api/ingest/flows` for uploads. `scripts/replay_capture.py` sends any PCAP or
JSONL capture in any of these formats.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | 3001 | REST + Socket.IO |
| `IRONDOME_UDP_PORT` | 2055 | flow collector |
| `IRONDOME_LAB` | on | built-in simulated traffic source |
| `IRONDOME_AUTO_SCENARIOS` | off | `on` injects a random attack every ~2 minutes; off, attacks run only when injected from the dashboard |
| `IRONDOME_SCALE` | 1.0 | lab background volume |
| `IRONDOME_WARM_START` | 300 | seconds of estate history loaded at start |
| `IRONDOME_INTERNAL_CIDRS` | RFC 1918 | protected address space |
| `IRONDOME_WORKERS` | 0 | detection worker processes (0 = in this process) |
| `IRONDOME_LAB_JA3` | on | lab's simulated JA3 list; `off` on real networks (abuse.ch SSLBL stays on) |
| `IRONDOME_SYSLOG` / `IRONDOME_SYSLOG_FORMAT` | – / cef | `udp://host:514` or `tcp://host:6514`; CEF or JSON |
| `IRONDOME_KAFKA` / `IRONDOME_KAFKA_TOPIC` | – / irondome.alerts | Kafka output (needs `kafka-python`) |
| `IRONDOME_ARCHIVE_DIR` / `IRONDOME_ARCHIVE_KEY` | – | hash-chained, HMAC-signed alert archive |

SIEM, Kafka and archive outputs belong inside the monitoring enclave. Every raw alert
is archived. The SIEM gets new incidents and severity escalations. A misconfigured output
is logged and skipped, and never stops detection.

## API

| Endpoint | Purpose |
|---|---|
| `GET /health` | liveness, `read_only`, `issues_mitigation: false`, scale-out and output status |
| `GET /api/alerts`, `GET /api/alerts/{id}` | correlated incidents |
| `GET /api/stats`, `GET /api/flows/recent`, `GET /api/sources` | counters, latency, sampled flows, per-format ingest counts |
| `GET /api/schema/alert` | alert JSON Schema |
| `GET /api/models`, `GET /api/evaluation`, `GET /api/features`, `GET /api/threat-classes`, `GET /api/scenarios` | model cards, evaluation, catalogues |
| `POST /api/ingest/flows` | flow upload (data in only) |
| `POST /api/scenario` | inject a traffic-lab scenario (drives the simulated source, not the sensor) |

Socket.IO events: `hello`, `incidents_snapshot`, `flows_snapshot`, `alert`, `alert_update`,
`flow_stats`, `flows_batch`, `scenario`.

## Threat intelligence

`intel/sslbl_ja3.csv` is abuse.ch's public SSL Blacklist JA3 feed: 97 real malware
fingerprints, no longer updated by abuse.ch since 2021. Refresh it with
`python scripts/update_threat_intel.py` (or `--from-file` inside an air-gapped enclave).
`intel/lab_ja3_fingerprints.json` holds the traffic lab's simulated families and is only
meaningful with the lab (`IRONDOME_LAB_JA3=off` disables it). Every JA3 alert names the
list that matched.
