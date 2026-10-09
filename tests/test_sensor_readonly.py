"""PS constraint (a): the sensor ingests one-way and has no return path.

    python -m unittest discover -s tests -v

Needs the sensor's dependencies (backend/sensor-service/requirements.txt); skipped otherwise.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend" / "sensor-service"))

from irondome import netflow  # noqa: E402
from irondome import traffic as T  # noqa: E402

MITIGATION_WORDS = ("block", "isolate", "mitigat", "quarantine", "firewall", "respond", "response", "kill", "shun",
                    "null-route", "blackhole", "rate-limit", "throttle", "reset")


class TestReadOnlySensor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import sensor_service
        except ImportError as e:    # fastapi / python-socketio not installed
            raise unittest.SkipTest(f"sensor dependencies not installed: {e}")
        cls.svc = sensor_service

    def test_api_exposes_no_mitigation_path(self):
        routes = [(r.path, set(getattr(r, "methods", None) or ())) for r in self.svc.app.routes]
        writes = {path for path, methods in routes if methods - {"GET", "HEAD"}}
        # the only non-GET routes feed data IN: a flow upload and the simulated-traffic lab control
        self.assertEqual(writes, {"/api/ingest/flows", "/api/scenario"})
        for path, _ in routes:
            self.assertFalse(any(w in path.lower() for w in MITIGATION_WORDS), path)

    def test_collector_keeps_no_transport(self):
        # asyncio hands the transport to connection_made(); the collector does not override it,
        # so it never holds a handle it could send with
        self.assertIs(self.svc.FlowCollector.connection_made, asyncio.BaseProtocol.connection_made)

    def test_udp_collector_ingests_and_never_replies(self):
        svc = self.svc

        async def run():
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(lambda: svc.FlowCollector(svc.sensor),
                                                               local_addr=("127.0.0.1", 0))
            port = transport.get_extra_info("sockname")[1]
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.setblocking(False)
            try:
                before = svc.sensor.sources["udp"]["records"]
                now = time.time()
                rec = T.make_record(now - 1, now, "10.10.1.5", 50000, "93.184.216.34", 443, 6, 6, 900, 5, 4000, "SAP", "SAP")
                client.sendto(json.dumps(rec).encode(), ("127.0.0.1", port))      # JSON flow record
                client.sendto(netflow.encode([rec], now=now), ("127.0.0.1", port))  # NetFlow v5 datagram
                await asyncio.sleep(0.5)
                received = svc.sensor.sources["udp"]["records"] - before
                try:
                    reply = client.recv(65535)
                except (BlockingIOError, ConnectionResetError):
                    reply = None
                return received, reply
            finally:
                client.close()
                transport.close()

        received, reply = asyncio.run(run())
        self.assertEqual(received, 2, "both the JSON record and the NetFlow v5 record are ingested")
        self.assertIsNone(reply, "the collector must never send anything back to the exporter")

    def test_collector_accepts_ipfix_netflow9_and_sflow(self):
        import random
        from irondome import ipfix, pcap, sflow
        svc = self.svc
        col = svc.FlowCollector(svc.sensor)
        now = time.time()
        rec = T.make_record(now - 2, now - 1, "10.10.1.5", 50000, "93.184.216.34", 443, 6, 6, 900, 5, 4000, "SAP", "SAP")
        before = dict(svc.sensor.sources["udp"]["formats"])
        n0 = svc.sensor.sources["udp"]["records"]
        col.datagram_received(ipfix.encode_ipfix([rec]), ("192.0.2.1", 4739))
        col.datagram_received(ipfix.encode_netflow_v9([rec], now=now), ("192.0.2.2", 2055))
        rng, sy = random.Random(2), pcap._Synth(2)
        frames = [(f, orig) for _, f, orig, _ in pcap._tcp_packets(sy, rec, rng)]
        col.datagram_received(sflow.encode_sflow(frames, rate=1), ("192.0.2.3", 6343))
        col.sweep(now + 60)
        fmts = svc.sensor.sources["udp"]["formats"]
        for f in ("ipfix", "netflow_v9", "sflow"):
            self.assertEqual(fmts[f], before[f] + 1, f)
        self.assertEqual(svc.sensor.sources["udp"]["records"] - n0, 3)

    def test_malformed_datagrams_are_counted_never_raised(self):
        import random
        svc = self.svc
        col = svc.FlowCollector(svc.sensor)
        rng = random.Random(5)
        junk = [b"", b"null", b"[1, 2]", b'{"src_ip": 5}', b"\xff\xfe", b'{"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "tls": {"ja3": {}}}']
        junk += [bytes(rng.randrange(256) for _ in range(rng.randrange(1, 300))) for _ in range(200)]
        errors = svc.sensor.sources["udp"]["errors"]
        for d in junk:
            col.datagram_received(d, ("192.0.2.9", 9999))     # must not raise
        self.assertGreater(svc.sensor.sources["udp"]["errors"], errors)
        svc.sensor.evaluate(time.time())                      # and the pipeline still evaluates

    def test_attacks_only_when_injected_by_default(self):
        # random demo attacks are opt-in (IRONDOME_AUTO_SCENARIOS=on); by default the lab
        # streams benign traffic and attacks run only when injected from the dashboard
        if "IRONDOME_AUTO_SCENARIOS" not in os.environ:
            self.assertFalse(self.svc.AUTO_SCENARIOS)
        hello = self.svc.hello_payload()
        self.assertEqual(hello["ingest"]["auto_scenarios"], self.svc.LAB_ENABLED and self.svc.AUTO_SCENARIOS)
        self.assertTrue(hello["boot_id"])


if __name__ == "__main__":
    unittest.main()
