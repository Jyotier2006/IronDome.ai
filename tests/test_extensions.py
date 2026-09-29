"""Tests for the flow-export formats, alert outputs, scale-out and detection guards.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import random
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "model_microservice"))

from irondome import ipfix, outputs, pcap, sflow  # noqa: E402
from irondome import traffic as T  # noqa: E402
from irondome.domains import domain_split  # noqa: E402
from irondome.netutil import split_domain  # noqa: E402
from irondome.scoring import ThreatScorer, technique_supported  # noqa: E402


def _recs(now):
    tcp = [T.make_record(now - 3, now - 1, "10.10.1.5", 50000 + i, "93.184.216.34", 443, 6, 10, 1500, 8, 9000,
                         "SAPF", "SAPF") for i in range(4)]
    v6 = T.make_record(now - 2, now - 1, "2001:db8::1", 5353, "2001:db8::2", 53, 17, 1, 80, 1, 200)
    return tcp + [v6]


class TestFlowExportFormats(unittest.TestCase):
    def test_ipfix_biflow_roundtrip(self):
        now = time.time()
        dec = ipfix.TemplateDecoder()
        out = dec.decode(ipfix.encode_ipfix(_recs(now)), "192.0.2.1")
        self.assertEqual(len(out), 5)
        r = out[0]
        self.assertEqual((r["src_ip"], r["dst_port"], r["pkts_fwd"], r["bytes_bwd"], r["flags_bwd"]),
                         ("10.10.1.5", 443, 10, 9000, "FSPA"))
        self.assertAlmostEqual(r["te"] - r["ts"], 2.0, places=2)
        self.assertEqual(out[-1]["src_ip"], "2001:db8::1")

    def test_data_before_template_is_dropped_then_decoded(self):
        now = time.time()
        dec = ipfix.TemplateDecoder()
        self.assertEqual(dec.decode(ipfix.encode_ipfix(_recs(now), with_templates=False), "x"), [])
        self.assertEqual(dec.stats["unknown_template"], 2)
        dec.decode(ipfix.encode_ipfix(_recs(now)[:1]), "x")                  # template arrives
        self.assertEqual(len(dec.decode(ipfix.encode_ipfix(_recs(now), with_templates=False), "x")), 5)

    def test_netflow_v9_roundtrip(self):
        now = time.time()
        out = ipfix.TemplateDecoder().decode(ipfix.encode_netflow_v9(_recs(now), now=now), "192.0.2.2")
        self.assertEqual(len(out), 4)                                        # v9 exporter here is IPv4-only
        self.assertEqual((out[0]["src_port"], out[0]["pkts_fwd"], out[0]["flags_fwd"]), (50000, 10, "FSPA"))

    def test_malformed_input_never_raises(self):
        dec = ipfix.TemplateDecoder()
        rng = random.Random(3)
        good = ipfix.encode_ipfix(_recs(time.time()))
        for _ in range(200):
            b = bytearray(good)
            for _ in range(8):
                b[rng.randrange(len(b))] = rng.randrange(256)
            dec.decode(bytes(b), "fuzz")
            dec.decode(bytes(b[: rng.randrange(len(b))]), "fuzz")
        s = sflow.SflowDecoder()
        for _ in range(100):
            s.decode(bytes(rng.randrange(256) for _ in range(rng.randrange(20, 400))), time.time())

    def test_sflow_sampled_flow_is_rebuilt_and_scaled(self):
        rng, sy = random.Random(1), pcap._Synth(1)
        now = time.time()
        conn = T.tcp_conn(rng, now - 5, 2.0, "10.10.1.5", "93.184.216.34", 443, up=20000, down=400000)
        frames = []
        for r in T.segment(conn):
            frames += pcap._tcp_packets(sy, r, rng)
        frames.sort(key=lambda f: f[0])
        sampled = [(f, orig) for _, f, orig, _ in frames][::4]
        dec = sflow.SflowDecoder()
        out = []
        for i in range(0, len(sampled), 10):
            out += dec.decode(sflow.encode_sflow(sampled[i:i + 10], rate=4, seq=i), now)
        out += dec.sweep(now + 60)
        self.assertEqual(len(out), 1)
        true_pkts = conn["pkts_fwd"] + conn["pkts_bwd"]
        est = out[0]["pkts_fwd"] + out[0]["pkts_bwd"]
        self.assertLess(abs(est - true_pkts) / true_pkts, 0.1, "1-in-4 sampling should estimate within 10 %")
        self.assertEqual(out[0]["sampling_rate"], 4)


class TestOutputs(unittest.TestCase):
    ALERT = {"alert_id": "a-1", "timestamp": "2026-09-29T10:00:00.000Z", "threat_class": "recon_scan", "ps_ref": "e",
             "technique": "vertical_scan", "technique_label": "Vertical port scan", "severity": "medium",
             "confidence": 0.97, "flow_id": "1:abc=", "mitre_attack": ["T1046"], "occurrences": 1,
             "flow": {"src_ip": "198.51.100.9", "src_port": 40000, "dst_ip": "10.10.2.80", "dst_port": 22, "protocol": "TCP"},
             "description": "Vertical port scan a=b|c"}

    def test_cef_is_well_formed(self):
        cef = outputs.to_cef(self.ALERT)
        head = cef.split("|")
        self.assertEqual(head[:4], ["CEF:0", "IronDome.ai", "Passive Sensor", "2.0"])
        self.assertIn("src=198.51.100.9", cef)
        self.assertIn("cfp1=0.97", cef)
        self.assertIn(r"msg=Vertical port scan a\=b|c", cef)                 # '=' escaped in extensions
        self.assertTrue(outputs.to_syslog(self.ALERT, cef).startswith("<132>1 2026-09-29T10:00:00.000Z "))

    def test_syslog_udp_delivery(self):
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(3)
        fwd = outputs.SyslogForwarder(f"udp://127.0.0.1:{rx.getsockname()[1]}", "cef")
        try:
            fwd.send(self.ALERT)
            msg = rx.recv(65535).decode()
            self.assertIn("CEF:0|IronDome.ai|", msg)
        finally:
            fwd.close()
            rx.close()

    def test_archive_detects_edit_delete_and_wrong_key(self):
        with tempfile.TemporaryDirectory() as d:
            arc = outputs.SignedArchive(d, b"k1")
            for i in range(5):
                arc.append({**self.ALERT, "alert_id": f"a-{i}"})
            self.assertTrue(outputs.verify_archive(d, b"k1")["ok"])
            self.assertFalse(outputs.verify_archive(d, b"other")["ok"])
            arc2 = outputs.SignedArchive(d, b"k1")                          # resumes the chain after restart
            arc2.append({**self.ALERT, "alert_id": "a-5"})
            self.assertEqual(outputs.verify_archive(d, b"k1")["records"], 6)
            f = next(Path(d).glob("alerts-*.jsonl"))
            lines = f.read_text(encoding="utf-8").splitlines()
            f.write_text("\n".join(lines[:2] + lines[3:]) + "\n", encoding="utf-8")        # delete a record
            self.assertIn("sequence", outputs.verify_archive(d, b"k1")["error"])
            edited = lines[:]
            edited[1] = edited[1].replace("a-1", "a-X")                                      # edit a record
            f.write_text("\n".join(edited) + "\n", encoding="utf-8")
            self.assertIn("edited", outputs.verify_archive(d, b"k1")["error"])

    def test_misconfigured_outputs_are_skipped(self):
        msgs = []
        outs = outputs.from_env({"IRONDOME_SYSLOG": "http://nope", "IRONDOME_ARCHIVE_DIR": "x"}, log=msgs.append)
        self.assertEqual(outs, [])
        self.assertEqual(len(msgs), 2)


class TestDetectionGuards(unittest.TestCase):
    def test_scan_residue_rule(self):
        s = ThreatScorer(load_intel=False)
        scan_like = {"context": {"half_open_top_source": {"ip": "198.51.100.9", "share": 0.9, "per_s": 40, "distinct_ports": 60}}}
        one_port_flood = {"context": {"half_open_top_source": {"ip": "198.51.100.9", "share": 0.95, "per_s": 40, "distinct_ports": 1}}}
        fast_flood = {"context": {"half_open_top_source": {"ip": "198.51.100.9", "share": 1.0, "per_s": 5000, "distinct_ports": 60}}}
        self.assertTrue(s.scan_residue(scan_like))
        self.assertFalse(s.scan_residue(one_port_flood))
        self.assertFalse(s.scan_residue(fast_flood))
        s.note_scanner("198.51.100.9")                                       # flagged by the recon detector
        self.assertTrue(s.scan_residue(one_port_flood))
        self.assertFalse(s.scan_residue(fast_flood))

    def test_beacon_and_slowloris_guards(self):
        self.assertFalse(technique_supported("c2_beacon", "beacon", {"iat_median": 0.04}))
        self.assertTrue(technique_supported("c2_beacon", "beacon", {"iat_median": 30.0}))
        web = {"tcp_ratio": 1.0, "slow_ratio": 0.5, "flows_per_src": 1.03}
        self.assertFalse(technique_supported("ddos", "slow_http", web))
        self.assertTrue(technique_supported("ddos", "slow_http", {**web, "flows_per_src": 40.0}))

    def test_dynamic_dns_label_and_split_partition(self):
        self.assertEqual(split_domain("qx7zkt1b.ddns.net"), ("", "qx7zkt1b", "ddns.net"))
        self.assertEqual(split_domain("ddns.net"), ("", "ddns", "net"))
        self.assertEqual(domain_split("www.example.com"), domain_split("example.com"))

    def test_recalibration_threshold_only_rises_and_meets_budget(self):
        import numpy as np
        from recalibrate import new_threshold
        benign = np.linspace(0, 1, 1001)
        t = new_threshold(benign, 0.5, 0.005)
        self.assertGreater(t, 0.99)
        self.assertLessEqual((benign >= t).mean(), 0.005)
        self.assertEqual(new_threshold(np.zeros(100), 0.7, 0.005), 0.7)


class TestScaleOut(unittest.TestCase):
    def test_two_workers_detect_flood_and_scan(self):
        from irondome.features import FeaturePipeline
        from irondome.sharding import ShardRouter
        router = ShardRouter(2, tick=0.25)
        try:
            main = FeaturePipeline("main", "live", detectors=[])
            rng = random.Random(4)
            ex = T.Exporter()
            now = time.time()
            T.SynFlood(rng, "10.10.2.80", 443, 1500, sources=40, answer_prob=0.2, start=now - 4, end=now - 2).emit(ex, now - 4, now - 2)
            T.PortScan(rng, "198.51.100.9", ["10.10.2.25"], list(range(1, 400)), 120, style="vertical",
                       start=now - 4, end=now - 1).emit(ex, now - 4, now - 1)
            for r in ex.drain_all():
                main.ingest(r, time.time())
                router.route(r, time.time(), main.ctx)
            router.flush()
            got, deadline = [], time.time() + 45
            while time.time() < deadline and {"volumetric_ddos", "recon_scan"} - {a["threat_class"] for a in got}:
                time.sleep(0.5)
                got += router.collect()
            classes = {a["threat_class"] for a in got}
            self.assertIn("volumetric_ddos", classes)
            self.assertIn("recon_scan", classes)
            self.assertEqual(router.alive(), 2)
        finally:
            router.close()


if __name__ == "__main__":
    unittest.main()
