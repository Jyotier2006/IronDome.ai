"""Unit tests for the IronDome.ai core library.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import random
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from irondome import dnsmsg, netflow, pcap, tls  # noqa: E402
from irondome import traffic as T  # noqa: E402
from irondome.correlate import AlertCorrelator  # noqa: E402
from irondome.export import public_record  # noqa: E402
from irondome.features import FeaturePipeline  # noqa: E402
from irondome.lab import generate_capture  # noqa: E402
from irondome.schema import community_id, normalize_flow, validate_alert  # noqa: E402
from irondome.scoring import ThreatScorer, technique_supported  # noqa: E402

CHROME = {
    "version": 0x0303,
    "ciphers": [0x0A0A, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
    "extensions": [0x1A1A, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
    "groups": [0x2A2A, 29, 23, 24], "point_formats": [0],
    "sig_algs": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
    "alpn": ["h2", "http/1.1"], "versions": [0x3A3A, 0x0304, 0x0303],
}


class TestIdentifiersAndFingerprints(unittest.TestCase):
    def test_community_id_spec_vector(self):
        # published Community ID v1 example (both directions hash identically)
        self.assertEqual(community_id("128.232.110.120", "66.35.250.204", 34855, 80, 6), "1:LQU9qZlK+B5F3KDmev6m5PMibrg=")
        self.assertEqual(community_id("66.35.250.204", "128.232.110.120", 80, 34855, 6), "1:LQU9qZlK+B5F3KDmev6m5PMibrg=")

    def test_ja4_spec_example_and_chrome_ja3(self):
        ch = tls.parse_client_hello(tls.build_client_hello(CHROME, "www.example.com"))
        self.assertEqual(tls.ja4(ch), "t13d1516h2_8daaf6152771_e5627efa2ab1")   # FoxIO JA4 README example
        self.assertEqual(tls.ja3(ch), "cd08e31494f9531f560d64c695473da9")       # well-known Chrome JA3
        self.assertEqual(ch["sni"], "www.example.com")

    def test_truncated_hello_is_not_fingerprinted(self):
        raw = tls.build_client_hello(CHROME, "a.example")
        self.assertIsNone(tls.parse_client_hello(raw[:120]))

    def test_profile_hello_matches_wire(self):
        for name in ("firefox", "schannel", "mal_minimal", "mal_legacy_ssl"):
            wire = tls.parse_client_hello(tls.build_client_hello(T.TLS_PROFILES[name], "x.example"))
            model = tls.profile_hello(T.TLS_PROFILES[name], "x.example")
            self.assertEqual(tls.ja3(wire), tls.ja3(model), name)
            self.assertEqual(tls.ja4(wire), tls.ja4(model), name)


class TestWireFormats(unittest.TestCase):
    def test_dns_roundtrip_with_exact_padding(self):
        q = dnsmsg.build_query(7, "abc.tunnel.example", "TXT")
        self.assertEqual(dnsmsg.parse(q)["qname"], "abc.tunnel.example")
        natural = dnsmsg.min_response_len("abc.tunnel.example", "TXT", "NOERROR", 1)
        r = dnsmsg.build_response(7, "abc.tunnel.example", "TXT", "NOERROR", 1, total_len=natural + 200)
        self.assertEqual(len(r), natural + 200)
        m = dnsmsg.parse(r)
        self.assertTrue(m["qr"])
        self.assertEqual((m["qtype"], m["rcode"], m["answers"]), ("TXT", "NOERROR", 1))
        nx = dnsmsg.parse(dnsmsg.build_response(9, "zz.example", "A", "NXDOMAIN", 1))
        self.assertEqual((nx["rcode"], nx["answers"]), ("NXDOMAIN", 0))

    def test_netflow_v5_roundtrip(self):
        recs = [T.make_record(1000.0 + i, 1001.0 + i, "10.1.1.1", 40000 + i, "8.8.8.8", 53, 17, 3, 300, 0, 0)
                for i in range(5)]
        out = netflow.decode(netflow.encode(recs, now=1006.0))
        self.assertEqual(len(out), 5)
        self.assertEqual((out[0]["src_ip"], out[0]["dst_port"], out[0]["pkts_fwd"], out[0]["bytes_fwd"]),
                         ("10.1.1.1", 53, 3, 300))
        self.assertAlmostEqual(out[0]["ts"], 1000.0, places=2)

    def test_segment_totals_are_exact(self):
        rng = random.Random(1)
        c = T.tcp_conn(rng, 50.0, 37.0, "10.0.0.5", "8.8.4.4", 443, up=5_000_000, down=120_000)
        segs = T.segment(c)
        self.assertEqual(len(segs), 4)
        for d in ("fwd", "bwd"):
            self.assertEqual(sum(s[f"pkts_{d}"] for s in segs), c[f"pkts_{d}"])
            self.assertEqual(sum(s[f"bytes_{d}"] for s in segs), c[f"bytes_{d}"])
        self.assertEqual([s["seg"] for s in segs], [0, 1, 2, 3])


class TestPcapRoundtrip(unittest.TestCase):
    def test_capture_to_pcap_and_back(self):
        records, _ = generate_capture("dns_tunnel", seed=3, warmup=20, gap=5)
        records = [r for r in records if r["pkts_fwd"] + r["pkts_bwd"] <= 400][:3000]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.pcap")
            pcap.write_pcap(path, records, snaplen=160)
            flows = [f for batch in pcap.read_flows(path) for f in batch]
        self.assertGreater(len(flows), 0.9 * len(records))
        want_ja3 = {r["tls"]["ja3"] for r in records if "tls" in r}
        got_ja3 = {f["tls"]["ja3"] for f in flows if "tls" in f and f["tls"].get("ja3")}
        self.assertTrue(want_ja3 and want_ja3 <= got_ja3, "JA3 must survive the PCAP round trip")
        want_q = {r["dns"]["qname"] for r in records if "dns" in r}
        got_q = {f["dns"]["qname"] for f in flows if "dns" in f}
        self.assertGreaterEqual(len(want_q & got_q), 0.95 * len(want_q))


class TestFeatures(unittest.TestCase):
    def _run(self, records):
        pipe = FeaturePipeline("t", "replay")
        for r in records:
            pipe.ingest(r, 0.0)
        return pipe.flush()

    def test_syn_flood_features(self):
        rng = random.Random(2)
        ex = T.Exporter()
        T.SynFlood(rng, "10.10.2.80", 443, 800, sources=20, answer_prob=0.0, start=1000.0, end=1002.0).emit(ex, 1000.0, 1002.0)
        cands = [c for c in self._run(ex.drain_all()) if c["detector"] == "ddos"]
        self.assertTrue(cands)
        f = cands[0]["features"]
        self.assertGreater(f["syn_only_ratio"], 0.95)
        self.assertGreater(f["flows_per_s"], 300)

    def test_vertical_scan_features(self):
        rng = random.Random(3)
        ex = T.Exporter()
        T.PortScan(rng, "198.51.100.9", ["10.10.2.80"], list(range(1, 400)), 100, style="vertical",
                   start=0.0, end=30.0).emit(ex, 0.0, 30.0)
        cands = [c for c in self._run(ex.drain_all()) if c["detector"] == "recon_scan"]
        self.assertTrue(cands)
        f = cands[0]["features"]
        self.assertGreater(f["uniq_ports"], 200)
        self.assertGreater(f["no_payload_ratio"], 0.9)

    def test_late_records_only_feed_context(self):
        pipe = FeaturePipeline("t", "live")
        now = 10_000.0
        old = T.make_record(now - 100, now - 99, "10.10.1.5", 5000, "93.184.216.34", 443, 6, 3, 300, 3, 900, "SAF", "SAF")
        pipe.ingest(old, now)
        self.assertEqual(pipe.late, 1)
        self.assertEqual(pipe.ctx.dst_prevalence("93.184.216.34", now), 1)   # context still learned
        self.assertEqual(sum(len(w) for w in pipe.extractors[0].windows.values()), 0)   # no window touched


class TestSchemaAndScoring(unittest.TestCase):
    def test_normalize_flow(self):
        self.assertIsNone(normalize_flow({"dst_ip": "1.2.3.4"}))
        r = normalize_flow({"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "proto": "udp", "src_port": "53",
                            "dst_port": 99999, "flags_fwd": 18, "dns": {"qname": "Example.COM."}}, now=5.0)
        self.assertEqual((r["proto"], r["src_port"], r["dst_port"], r["flags_fwd"]), (17, 53, 65535, "SA"))
        self.assertEqual(r["dns"]["qname"], "example.com")

    def test_normalize_flow_bounds_hostile_values(self):
        now = 1_758_000_000.0
        r = normalize_flow({"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": -1e30, "te": 1e30, "proto": 10 ** 20,
                            "bytes_fwd": int("9" * 400), "pkts_fwd": "9" * 400, "bytes_bwd": float("inf"),
                            "tls": {"sni": 12345, "ja3": ["x"], "alpn": ["h2", "http/1.1"], "ciphers": "abc",
                                    "exts": [1, 2, 3], "version": None},
                            "splt": {"len": [10 ** 30, -(10 ** 30), "x"], "iat": [1e300, -5]}}, now=now)
        self.assertEqual((r["ts"], r["te"]), (now, now))     # out-of-range timestamps fall back to arrival time
        self.assertEqual(r["proto"], 255)
        self.assertLessEqual(r["bytes_fwd"], 10 ** 15)
        self.assertLessEqual(r["pkts_fwd"], 10 ** 12)
        self.assertEqual(r["bytes_bwd"], 0)
        self.assertEqual(r["tls"], {"alpn": "h2", "ciphers": 0, "exts": 3})   # wrong-typed handshake fields dropped
        self.assertEqual(r["splt"]["len"], [65535, -65535, 0])
        self.assertEqual(r["splt"]["iat"][1], 0.0)
        r = normalize_flow({"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": now - 1e6, "te": now})
        self.assertEqual(r["te"] - r["ts"], 86400.0)          # a flow cannot start more than a day before it ends

    def test_hostile_record_cannot_poison_live_windows(self):
        # one absurd record used to overflow float maths inside a window, so every later
        # evaluate() of that window raised and the live sensor's loop stopped for good
        pipe = FeaturePipeline("t", "live")
        now = 1_758_000_000.0
        for i in range(3):
            pipe.ingest(normalize_flow({"src_ip": "10.10.1.5", "dst_ip": "93.184.216.34", "src_port": 40000 + i,
                                        "dst_port": 443, "proto": 6, "ts": now - 1, "te": now,
                                        "bytes_fwd": int("9" * 400), "pkts_fwd": 10 ** 40}, now=now), now)
        for k in range(1, 12):
            pipe.evaluate(now_wall=now + k * 10)              # must not raise

    def test_evidence_consistency_guard(self):
        tcp_only = {"tcp_ratio": 1.0, "udp_ratio": 0.0, "icmp_ratio": 0.0, "syn_only_ratio": 0.0, "amp_port_ratio": 0.0,
                    "src_entropy_norm": 0.5, "flows_per_src": 3.0, "uniq_src": 30, "slow_ratio": 0.0}
        self.assertFalse(technique_supported("ddos", "udp_icmp_flood", tcp_only))
        self.assertFalse(technique_supported("ddos", "syn_flood", tcp_only))
        self.assertTrue(technique_supported("ddos", "syn_flood", {**tcp_only, "syn_only_ratio": 0.9}))

    def test_scored_alert_matches_schema(self):
        scorer = ThreatScorer()
        rng = random.Random(4)
        ex = T.Exporter()
        T.SynFlood(rng, "10.10.2.80", 443, 1500, sources=40, answer_prob=0.2, start=1000.0, end=1002.0).emit(ex, 1000.0, 1002.0)
        pipe = FeaturePipeline("t", "replay")
        for r in ex.drain_all():
            pipe.ingest(r, 0.0)
        alerts = scorer.score_many(pipe.flush())
        self.assertTrue(alerts, "a 1,500 SYN/s flood must raise an alert")
        a = alerts[0]
        self.assertEqual(validate_alert(a), [])
        self.assertEqual((a["threat_class"], a["technique"]), ("volumetric_ddos", "syn_flood"))
        self.assertTrue(a["flow_id"].startswith("1:"))

    def test_correlator_collapses_repeats(self):
        corr = AlertCorrelator(window=60)
        base = {"alert_id": "a1", "threat_class": "recon_scan", "technique": "vertical_scan", "confidence": 0.9,
                "severity": "medium", "entity": {"type": "source", "ip": "1.2.3.4"}, "related_flow_ids": ["x"],
                "last_seen": "t", "description": "d", "evidence": {}}
        _, new1 = corr.add(dict(base), now=0.0)
        inc, new2 = corr.add({**base, "alert_id": "a2", "confidence": 0.95}, now=10.0)
        _, new3 = corr.add({**base, "alert_id": "a3", "entity": {"type": "source", "ip": "5.6.7.8"}}, now=11.0)
        self.assertEqual((new1, new2, new3), (True, False, True))
        self.assertEqual((inc["occurrences"], inc["confidence"]), (2, 0.95))

    def test_exports_never_leak_ground_truth(self):
        rec = {"src_ip": "10.0.0.1", "tls": {"ja3": "abc", "_profile": "mal_minimal"}, "_label": "attack"}
        out = public_record(rec)
        self.assertNotIn("_label", out)
        self.assertNotIn("_profile", out["tls"])


if __name__ == "__main__":
    unittest.main()
