"""Replay a packet or flow capture into the sensor's one-way collector.

    python scripts/replay_capture.py captures/kill_chain.pcap
    python scripts/replay_capture.py lab_hping3_synflood.pcapng --speed 1
    python scripts/replay_capture.py captures/kill_chain.jsonl --sensor 10.0.0.5:2055

Inputs: classic PCAP, PCAPNG (e.g. from tcpdump / Wireshark while running hping3,
dnscat2, iodine, nmap ...), or JSONL flow records. The file is opened read-only and its
SHA-256 is printed for chain of custody. PCAPs are turned into bidirectional flow
records by the same flow assembler the sensor uses; records are then re-timed so the
capture appears live and fired over UDP - fire-and-forget, nothing is read back.

--speed > 1 compresses time; rate features scale with it, so use 1 for faithful
detection and higher speeds only for quick demos.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from irondome.export import UdpFlowExporter  # noqa: E402
from irondome.pcap import read_flows  # noqa: E402


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_records(path: Path) -> list[dict]:
    name = path.name.lower()
    if name.endswith((".jsonl", ".jsonl.gz", ".ndjson")):
        opener = gzip.open if name.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
    flows = []
    for batch in read_flows(str(path), sensor=f"replay:{path.name}"):
        flows += batch
    return flows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture", type=Path)
    ap.add_argument("--sensor", default="127.0.0.1:2055", help="host:port of the receive-only collector")
    ap.add_argument("--speed", type=float, default=1.0, help="time compression factor (1 = original timing)")
    ap.add_argument("--loop", action="store_true", help="replay continuously")
    args = ap.parse_args()

    if not args.capture.exists():
        sys.exit(f"capture not found: {args.capture}")
    host, port = args.sensor.rsplit(":", 1)
    digest = sha256(args.capture)
    print(f"capture  {args.capture}  ({args.capture.stat().st_size / 1e6:.1f} MB)")
    print(f"sha256   {digest}")
    t0 = time.time()
    records = sorted(load_records(args.capture), key=lambda r: r["te"])
    if not records:
        sys.exit("no flow records in capture")
    span = records[-1]["te"] - records[0]["te"]
    print(f"records  {len(records):,} flows spanning {span:.0f} s (parsed in {time.time() - t0:.1f} s)")
    print(f"sending  one-way to udp://{host}:{port} at {args.speed}x ...")

    ex = UdpFlowExporter(host, int(port))
    speed = max(0.01, args.speed)
    try:
        while True:
            base_event = records[0]["te"]
            base_wall = time.time()
            for i, rec in enumerate(records):
                due = base_wall + (rec["te"] - base_event) / speed
                delay = due - time.time()
                if delay > 0.02:
                    ex.flush()
                    time.sleep(delay)
                shift = due - rec["te"]                     # re-time: the capture appears live
                out = dict(rec)
                out["ts"] = rec["ts"] + shift if speed == 1 else due - (rec["te"] - rec["ts"]) / speed
                out["te"] = due
                ex.add(out)
                if i % 5000 == 0 and i:
                    print(f"  {i:,}/{len(records):,} flows sent", flush=True)
            ex.flush()
            print(f"done: {ex.records:,} flows in {ex.datagrams:,} datagrams")
            if not args.loop:
                break
    except KeyboardInterrupt:
        ex.flush()
        print(f"\nstopped: {ex.records:,} flows sent")
    finally:
        ex.close()


if __name__ == "__main__":
    main()
