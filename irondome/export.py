"""One-way flow export over UDP (the production side of the diode).

`UdpFlowExporter` packs flow records into MTU-sized datagrams of newline-delimited
JSON and fires them at the sensor's receive-only collector. It never reads from the
socket: like traffic crossing a hardware data diode, the export has no return path.
Lab-private keys (starting with "_", e.g. the TLS profile hint used for PCAP
synthesis) are stripped, so no ground truth ever reaches the sensor.
"""

from __future__ import annotations

import json
import socket

MTU_PAYLOAD = 1400   # keep datagrams under a typical 1500-byte MTU (no IP fragmentation)


def public_record(rec: dict) -> dict:
    out = {k: v for k, v in rec.items() if not k.startswith("_")}
    tls = out.get("tls")
    if isinstance(tls, dict) and any(k.startswith("_") for k in tls):
        out["tls"] = {k: v for k, v in tls.items() if not k.startswith("_")}
    return out


class UdpFlowExporter:
    def __init__(self, host: str = "127.0.0.1", port: int = 2055, max_payload: int = MTU_PAYLOAD):
        self.addr = (host, port)
        self.max_payload = max_payload
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        self.buf: list[bytes] = []
        self.size = 0
        self.datagrams = 0
        self.records = 0

    def add(self, rec: dict):
        line = json.dumps(public_record(rec), separators=(",", ":")).encode()
        if self.buf and self.size + len(line) + 1 > self.max_payload:
            self.flush()
        self.buf.append(line)
        self.size += len(line) + 1
        self.records += 1

    def flush(self):
        if not self.buf:
            return
        self.sock.sendto(b"\n".join(self.buf), self.addr)
        self.datagrams += 1
        self.buf, self.size = [], 0

    def close(self):
        self.flush()
        self.sock.close()
