"""NetFlow v5 export datagrams (the format most routers, softflowd and nProbe can emit).

NetFlow v5 records are unidirectional and carry no DNS/TLS metadata, so they feed
the volumetric, scanning, beaconing and exfiltration detectors with reduced fidelity
(the reverse direction arrives as a separate record). The biflow FlowRecord JSON and
PCAP paths give every detector its full feature set.
"""

from __future__ import annotations

import socket
import struct

_HDR = struct.Struct("!HHIIIIBBH")
_REC = struct.Struct("!4s4s4sHHIIIIHHBBBBHHBBH")
_FLAGS = "FSRPAUEC"


def is_netflow_v5(datagram: bytes) -> bool:
    return len(datagram) >= 24 and datagram[0] == 0 and datagram[1] == 5


def decode(datagram: bytes, sensor: str | None = None) -> list[dict]:
    version, count, uptime, secs, nsecs, _seq, _et, _eid, _sampling = _HDR.unpack_from(datagram, 0)
    if version != 5:
        return []
    now = secs + nsecs / 1e9
    out = []
    for i in range(min(count, 30)):
        off = 24 + 48 * i
        if off + 48 > len(datagram):
            break
        (src, dst, _nh, _inp, _outp, pkts, octets, first, last, sport, dport, _p1, flags, proto, _tos,
         _sas, _das, _sm, _dm, _p2) = _REC.unpack_from(datagram, off)
        ts = now - (uptime - first) / 1000.0
        te = now - (uptime - last) / 1000.0
        rec = {
            "ts": ts, "te": max(te, ts),
            "src_ip": socket.inet_ntoa(src), "dst_ip": socket.inet_ntoa(dst),
            "src_port": sport, "dst_port": dport, "proto": proto,
            "pkts_fwd": pkts, "bytes_fwd": octets, "pkts_bwd": 0, "bytes_bwd": 0,
            "flags_fwd": "".join(_FLAGS[b] for b in range(8) if flags & (1 << b)) if proto == 6 else "",
            "flags_bwd": "", "seg": 0,
        }
        if sensor:
            rec["sensor"] = sensor
        out.append(rec)
    return out


def encode(records: list[dict], sys_uptime_ms: int = 3_600_000, now: float | None = None, seq: int = 0) -> bytes:
    """Encode up to 30 records (fwd direction only) into one NetFlow v5 datagram."""
    records = records[:30]
    now = now if now is not None else max((r["te"] for r in records), default=0.0)
    secs, nsecs = int(now), int((now - int(now)) * 1e9)
    body = b""
    for r in records:
        first = max(0, int(sys_uptime_ms - (now - r["ts"]) * 1000))
        last = max(first, int(sys_uptime_ms - (now - r["te"]) * 1000))
        flags = sum(1 << _FLAGS.index(c) for c in r.get("flags_fwd", "") if c in _FLAGS)
        body += _REC.pack(socket.inet_aton(r["src_ip"]), socket.inet_aton(r["dst_ip"]), b"\x00" * 4, 0, 0,
                          r["pkts_fwd"], r["bytes_fwd"], first, last, r["src_port"], r["dst_port"], 0, flags,
                          r["proto"], 0, 0, 0, 0, 0, 0)
    return _HDR.pack(5, len(records), sys_uptime_ms, secs, nsecs, seq, 0, 0, 0) + body
