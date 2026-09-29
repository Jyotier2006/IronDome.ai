"""IronDome.ai traffic lab - the simulated IP data source (production side of the diode).

    python scripts/traffic_lab.py list
    python scripts/traffic_lab.py capture --scenario kill_chain --out captures/kill_chain.jsonl
    python scripts/traffic_lab.py capture --scenario syn_flood --scenario dns_tunnel --out captures/demo.jsonl --pcap captures/demo.pcap
    python scripts/traffic_lab.py stream --sensor 127.0.0.1:2055 --scenario port_scan --at 60 --auto

capture  builds an offline capture: benign warm-up, then each scenario in turn. Writes
         JSONL flow records (gzip if the name ends in .gz), optionally a PCAP that opens in
         Wireshark, and a <name>.truth.json ground-truth file for evaluation.
stream   runs the lab in real time and exports flows one-way over UDP to the sensor's
         collector (run the sensor with IRONDOME_LAB=off). It first sends --warm seconds
         of history so the sensor's estate baseline is mature (history older than the
         sensor's late horizon only updates context, never windows), then goes live.
         Scheduled / automatic injections are printed here - the sensor is never told.
"""

from __future__ import annotations

import argparse
import gzip
import json
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from irondome.export import UdpFlowExporter, public_record  # noqa: E402
from irondome.lab import LAB_EPOCH, SCENARIOS, Lab, generate_capture  # noqa: E402


def cmd_list(_args):
    print(f"{'scenario':20s} {'PS':4s} {'emulates':34s} description")
    for k, v in SCENARIOS.items():
        print(f"{k:20s} ({v['ps_ref']})  {v['tool']:34s} {v['description']}")


def cmd_capture(args):
    names = args.scenario or ["kill_chain"]
    for n in names:
        if n not in SCENARIOS:
            sys.exit(f"unknown scenario {n}; see `list`")
    t = time.time()
    records, truth = generate_capture(names, seed=args.seed, warmup=args.warmup, gap=args.gap, scale=args.scale)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    opener = gzip.open if out.name.endswith(".gz") else open
    with opener(out, "wt", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(public_record(r), separators=(",", ":")) + "\n")
    stem = out.name.split(".")[0]
    truth_path = out.with_name(f"{stem}.truth.json")
    truth_path.write_text(json.dumps({"scenarios": truth, "lab_epoch": LAB_EPOCH, "seed": args.seed}, indent=2) + "\n",
                          encoding="utf-8")
    print(f"{len(records):,} flow records -> {out}  ({out.stat().st_size / 1e6:.1f} MB, {time.time() - t:.1f} s)")
    print(f"ground truth -> {truth_path}")
    if args.pcap:
        from irondome.pcap import write_pcap
        pcap = Path(args.pcap)
        pcap.parent.mkdir(parents=True, exist_ok=True)
        stats = write_pcap(str(pcap), records, snaplen=args.snaplen, seed=args.seed)
        print(f"{stats['packets']:,} packets -> {pcap}  ({pcap.stat().st_size / 1e6:.1f} MB, snaplen {args.snaplen})")


def cmd_stream(args):
    host, port = args.sensor.rsplit(":", 1)
    ex = UdpFlowExporter(host, int(port))
    lab = Lab(seed=args.seed, scale=args.scale)
    rng = random.Random(args.seed)
    now = time.time()

    if args.warm > 0:   # history burst: re-timed into the past, sent as fast as possible
        t = LAB_EPOCH
        # the end of the history lands 35 s ago - beyond the sensor's 30 s late horizon, so
        # it only builds estate context (prevalence, baselines) and never touches windows
        shift = (now - 35.0) - (LAB_EPOCH + args.warm)
        while t < LAB_EPOCH + args.warm:
            for rec in lab.step(t, t + 1.0):
                out = dict(rec)
                out["ts"] = rec["ts"] + shift
                out["te"] = rec["te"] + shift
                ex.add(out)
            t += 1.0
        ex.flush()
        print(f"warm history: {ex.records:,} flows sent (estate baseline for the sensor)")
    offset = time.time() - t if args.warm > 0 else time.time() - LAB_EPOCH
    lab_t = time.time() - offset

    schedule = sorted(zip(args.at or [], args.scenario or []), key=lambda x: x[0])
    start = time.time()
    next_auto = start + 30.0
    print(f"streaming live flows one-way to udp://{host}:{port}  (Ctrl+C to stop)")
    try:
        while True:
            wall = time.time()
            for rec in lab.step(lab_t, lab_t + 0.5):
                out = dict(rec)
                out["ts"] = rec["ts"] + offset
                out["te"] = rec["te"] + offset
                ex.add(out)
            ex.flush()
            lab_t += 0.5
            elapsed = wall - start
            while schedule and schedule[0][0] <= elapsed:
                _, name = schedule.pop(0)
                run = lab.start(name, lab_t)
                print(f"[t+{elapsed:5.0f}s] injected {run['title']} (PS {run['ps_ref']}) attacker={run['attacker']} target={run['target']}")
            if args.auto and wall >= next_auto and not lab.active:
                name = rng.choice([s for s in SCENARIOS if s != "kill_chain"])
                run = lab.start(name, lab_t)
                print(f"[t+{elapsed:5.0f}s] auto-injected {run['title']} (PS {run['ps_ref']}) attacker={run['attacker']} target={run['target']}")
                next_auto = wall + rng.uniform(80, 140)
            time.sleep(max(0.0, 0.5 - (time.time() - wall)))
    except KeyboardInterrupt:
        print(f"\nstopped: {ex.records:,} flows in {ex.datagrams:,} datagrams")
    finally:
        ex.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list scenarios").set_defaults(fn=cmd_list)

    c = sub.add_parser("capture", help="write an offline capture")
    c.add_argument("--scenario", action="append", help="scenario to include (repeatable)")
    c.add_argument("--out", default="captures/kill_chain.jsonl")
    c.add_argument("--pcap", help="also synthesise a PCAP")
    c.add_argument("--snaplen", type=int, default=128)
    c.add_argument("--warmup", type=float, default=120.0)
    c.add_argument("--gap", type=float, default=20.0)
    c.add_argument("--scale", type=float, default=1.0)
    c.add_argument("--seed", type=int, default=7)
    c.set_defaults(fn=cmd_capture)

    s = sub.add_parser("stream", help="live one-way UDP export to the sensor")
    s.add_argument("--sensor", default="127.0.0.1:2055")
    s.add_argument("--scale", type=float, default=1.0)
    s.add_argument("--warm", type=float, default=300.0, help="seconds of history to send first (0 = none)")
    s.add_argument("--scenario", action="append", help="scenario to schedule (pair with --at)")
    s.add_argument("--at", action="append", type=float, help="seconds after start for the matching --scenario")
    s.add_argument("--auto", action="store_true", help="inject a random scenario every ~2 minutes")
    s.add_argument("--seed", type=int, default=None)
    s.set_defaults(fn=cmd_stream)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
