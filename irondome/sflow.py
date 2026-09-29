"""sFlow version 5 - sampled packet headers turned into flow records.

An sFlow agent (switch / router) sends 1-in-N sampled packet headers rather than flows.
The collector parses each sampled header (Ethernet, VLAN, IPv4/IPv6, TCP/UDP/ICMP - the
same parser the PCAP path uses), assembles the samples into bidirectional flows, and
scales packet and byte counts by the sampling rate when a flow is exported. Counter
samples and other record types are skipped. Nothing is sent back to the agent.

Sampling has consequences the analyst should know: short flows are often missed
entirely, per-flow counts are statistical estimates, and DNS/TLS metadata is only
available when the sampled packet happens to carry the query or ClientHello within the
agent's header snapshot (typically 128 bytes). Volume-based detectors (DDoS, scans,
exfiltration) degrade gracefully; beaconing and DNS/TLS analysis need unsampled data.
"""

from __future__ import annotations

import socket
import struct

from .pcap import FlowAssembler, parse_frame


def is_sflow_v5(d: bytes) -> bool:
    return len(d) >= 28 and d[:4] == b"\x00\x00\x00\x05" and d[4:8] in (b"\x00\x00\x00\x01", b"\x00\x00\x00\x02")


class _SampledAssembler(FlowAssembler):
    """FlowAssembler whose exported counts are scaled by each flow's sampling rate."""

    def __init__(self, sensor=None):
        super().__init__(sensor=sensor)
        self.rates: dict = {}

    def add_sampled(self, ts, pkt, rate):
        self.add(ts, pkt)
        self.rates[self._key(pkt)] = rate

    def _export(self, key, f, final):
        rate = self.rates.get(key, 1)
        before = len(self.out)
        super()._export(key, f, final)
        for rec in self.out[before:]:
            for k in ("pkts_fwd", "bytes_fwd", "pkts_bwd", "bytes_bwd"):
                rec[k] *= rate
            rec["sampling_rate"] = rate
        if final:
            self.rates.pop(key, None)


class SflowDecoder:
    """Stateful sFlow v5 collector: feed datagrams, collect flows with sweep()."""

    def __init__(self, sensor: str | None = None):
        self.asm = _SampledAssembler(sensor=sensor)
        self.stats = {"datagrams": 0, "flow_samples": 0, "packets": 0, "unparsed": 0, "malformed": 0}

    def decode(self, d: bytes, now: float, exporter: str = "") -> list[dict]:
        """Parse one datagram; returns the flows that became exportable."""
        self.stats["datagrams"] += 1
        try:
            self._datagram(d, now)
        except (struct.error, IndexError, ValueError, OverflowError):
            self.stats["malformed"] += 1
        return self.sweep(now)

    def sweep(self, now: float) -> list[dict]:
        self.asm.sweep(now)
        return self.asm.drain()

    def _datagram(self, d, now):
        addr_type = struct.unpack_from("!I", d, 4)[0]
        off = 8 + (4 if addr_type == 1 else 16)
        _sub_agent, _seq, _uptime, n_samples = struct.unpack_from("!IIII", d, off)
        off += 16
        for _ in range(min(n_samples, 256)):
            fmt, length = struct.unpack_from("!II", d, off)
            body, off = off + 8, off + 8 + length
            enterprise, kind = fmt >> 12, fmt & 0xFFF
            if enterprise != 0 or kind not in (1, 3):
                continue                        # counter samples etc.
            self.stats["flow_samples"] += 1
            if kind == 1:                       # flow sample
                _seq, _src, rate, _pool, _drops, _in, _out, n_rec = struct.unpack_from("!IIIIIIII", d, body)
                p = body + 32
            else:                               # expanded flow sample
                (_seq, _st, _si, rate, _pool, _drops, _if, _iv, _of, _ov, n_rec) = struct.unpack_from("!IIIIIIIIIII", d, body)
                p = body + 44
            for _ in range(min(n_rec, 64)):
                rfmt, rlen = struct.unpack_from("!II", d, p)
                rbody, p = p + 8, p + 8 + rlen
                if rfmt != 1:                   # only raw packet headers
                    continue
                proto, frame_len, _stripped, hlen = struct.unpack_from("!IIII", d, rbody)
                if proto != 1:                  # Ethernet only
                    self.stats["unparsed"] += 1
                    continue
                header = d[rbody + 16: rbody + 16 + hlen]
                pkt = parse_frame(1, header, frame_len)
                if pkt is None:
                    self.stats["unparsed"] += 1
                    continue
                self.stats["packets"] += 1
                self.asm.add_sampled(now, pkt, max(1, rate))


def encode_sflow(samples: list[tuple[bytes, int]], rate: int, agent: str = "192.0.2.10", seq: int = 0,
                 uptime_ms: int = 3_600_000, snaplen: int = 128) -> bytes:
    """One sFlow v5 datagram of flow samples; `samples` = [(ethernet frame, original length)]."""
    out = b""
    for i, (frame, orig_len) in enumerate(samples):
        hdr = frame[:snaplen]
        pad = (-len(hdr)) % 4
        rec = struct.pack("!IIII", 1, orig_len, 4, len(hdr)) + hdr + b"\x00" * pad
        record = struct.pack("!II", 1, len(rec)) + rec
        sample = struct.pack("!IIIIIIII", seq * 1000 + i, 1, rate, rate * (i + 1), 0, 1, 2, 1) + record
        out += struct.pack("!II", 1, len(sample)) + sample
    return (struct.pack("!II", 5, 1) + socket.inet_aton(agent)
            + struct.pack("!IIII", 0, seq, uptime_ms, len(samples)) + out)
