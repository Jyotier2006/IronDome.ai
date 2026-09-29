"""PS constraint (a): the sensor ingests one-way and has no return path.

    python -m unittest discover -s tests -v

Needs the sensor's dependencies (backend/sensor-service/requirements.txt); skipped otherwise.
"""

from __future__ import annotations

import asyncio
import json
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


if __name__ == "__main__":
    unittest.main()
