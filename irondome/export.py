"""One-way flow export over UDP (the production side of the diode).

`UdpFlowExporter` packs flow records into MTU-sized datagrams and fires them at the
sensor's receive-only collector, as newline-delimited JSON (default, keeps DNS/TLS
metadata) or as NetFlow v5, NetFlow v9 or IPFIX (flow counters only, like a router or
probe would send). It never reads from the socket: like traffic crossing a hardware
data diode, the export has no return path. Lab-private keys (starting with "_", e.g.
the TLS profile hint used for PCAP synthesis) are stripped, so no ground truth ever
reaches the sensor.
"""

from __future__ import annotations

import json
import socket

from . import ipfix, netflow

MTU_PAYLOAD = 1400   # keep datagrams under a typical 1500-byte MTU (no IP fragmentation)
FORMATS = ("json", "netflow5", "netflow9", "ipfix")
_BATCH = {"netflow5": 30, "netflow9": ipfix.V9_RECORDS_PER_PACKET, "ipfix": ipfix.IPFIX_RECORDS_PER_MESSAGE}


def public_record(rec: dict) -> dict:
    out = {k: v for k, v in rec.items() if not k.startswith("_")}
    tls = out.get("tls")
    if isinstance(tls, dict) and any(k.startswith("_") for k in tls):
        out["tls"] = {k: v for k, v in tls.items() if not k.startswith("_")}
    return out


class UdpFlowExporter:
    def __init__(self, host: str = "127.0.0.1", port: int = 2055, max_payload: int = MTU_PAYLOAD, fmt: str = "json"):
        if fmt not in FORMATS:
            raise ValueError(f"unknown export format {fmt!r}; choose from {FORMATS}")
        self.addr = (host, port)
        self.max_payload = max_payload
        self.fmt = fmt
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        self.buf: list = []
        self.size = 0
        self.datagrams = 0
        self.records = 0
        self.skipped = 0     # IPv6 records the v5/v9 encoders cannot carry
        self.seq = 0

    def add(self, rec: dict):
        if self.fmt == "json":
            line = json.dumps(public_record(rec), separators=(",", ":")).encode()
            if self.buf and self.size + len(line) + 1 > self.max_payload:
                self.flush()
            self.buf.append(line)
            self.size += len(line) + 1
        else:
            if self.fmt in ("netflow5", "netflow9") and ":" in rec["src_ip"]:
                self.skipped += 1
                return
            self.buf.append(rec)
            if len(self.buf) >= _BATCH[self.fmt]:
                self.flush()
        self.records += 1

    def _encode(self, chunk) -> bytes:
        if self.fmt == "netflow5":
            return netflow.encode(chunk, seq=self.seq)
        if self.fmt == "netflow9":
            return ipfix.encode_netflow_v9(chunk, seq=self.seq)
        return ipfix.encode_ipfix(chunk, seq=self.seq)

    def flush(self):
        if not self.buf:
            return
        if self.fmt == "json":
            self.sock.sendto(b"\n".join(self.buf), self.addr)
            self.datagrams += 1
        else:
            n = _BATCH[self.fmt]
            for i in range(0, len(self.buf), n):
                chunk = self.buf[i:i + n]
                self.sock.sendto(self._encode(chunk), self.addr)
                self.datagrams += 1
                self.seq += len(chunk)
        self.buf, self.size = [], 0

    def close(self):
        self.flush()
        self.sock.close()
