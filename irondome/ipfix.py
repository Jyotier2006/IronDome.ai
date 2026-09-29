"""IPFIX (RFC 7011) and NetFlow v9 (RFC 3954) flow export, template based.

Both protocols describe their records with templates sent in-band, so the collector
keeps a template cache per (exporter address, observation domain / source id,
template id). Data records that arrive before their template are counted and dropped,
exactly as a standard collector does. The decoder only reads: nothing is ever sent
back to the exporter.

Supported information elements (IANA numbering, shared by v9 for these fields):
    1 octetDeltaCount   2 packetDeltaCount   4 protocolIdentifier   6 tcpControlBits
    7 sourceTransportPort   8 sourceIPv4Address   11 destinationTransportPort
    12 destinationIPv4Address   27/28 source/destinationIPv6Address
    85/86 octet/packetTotalCount   21/22 flowEnd/StartSysUpTime
    150/151 flowStart/EndSeconds   152/153 ...Milliseconds   154/155 ...Microseconds
    161 flowDurationMilliseconds
and the RFC 5103 *reverse* elements (enterprise 29305) for bidirectional flows, which
fill the responder direction of the biflow record. Unknown elements, including
variable-length ones, are skipped.

Standard IPFIX/v9 carry no DNS or TLS fields, so like NetFlow v5 they feed the
volumetric, scanning, beaconing and exfiltration detectors (PS a, b, e, f); the DNS
and encrypted-traffic detectors (c, d) need PCAP or the JSON flow format.
"""

from __future__ import annotations

import socket
import struct
import time

REVERSE_PEN = 29305
_FLAGS = "FSRPAUEC"
_NTP_EPOCH = 2208988800   # seconds between 1900-01-01 and 1970-01-01

FIELDS = {
    (0, 1): "octets", (0, 85): "octets", (0, 2): "packets", (0, 86): "packets",
    (0, 4): "proto", (0, 6): "flags", (0, 7): "sport", (0, 11): "dport",
    (0, 8): "src4", (0, 12): "dst4", (0, 27): "src6", (0, 28): "dst6",
    (0, 21): "last_uptime", (0, 22): "first_uptime",
    (0, 150): "start_s", (0, 151): "end_s", (0, 152): "start_ms", (0, 153): "end_ms",
    (0, 154): "start_us", (0, 155): "end_us", (0, 161): "duration_ms",
    (REVERSE_PEN, 1): "r_octets", (REVERSE_PEN, 85): "r_octets",
    (REVERSE_PEN, 2): "r_packets", (REVERSE_PEN, 86): "r_packets", (REVERSE_PEN, 6): "r_flags",
}


def is_ipfix(d: bytes) -> bool:
    return len(d) >= 16 and d[0] == 0 and d[1] == 10 and struct.unpack_from("!H", d, 2)[0] == len(d)


def is_netflow_v9(d: bytes) -> bool:
    return len(d) >= 20 and d[0] == 0 and d[1] == 9


def _flag_str(v: int) -> str:
    return "".join(_FLAGS[b] for b in range(8) if v & (1 << b))


def _ntp(v: int) -> float:
    return (v >> 32) - _NTP_EPOCH + (v & 0xFFFFFFFF) / 2 ** 32


class TemplateDecoder:
    """Stateful IPFIX / NetFlow v9 decoder (one per collector)."""

    MAX_TEMPLATES = 4096

    def __init__(self):
        self.templates: dict = {}   # (exporter, domain, id) -> ("data"|"options", [(pen, ie, length)])
        self.stats = {"messages": 0, "templates": 0, "records": 0, "unknown_template": 0, "malformed": 0}

    # ------------------------------------------------------------------ public
    def decode(self, data: bytes, exporter: str, sensor: str | None = None) -> list[dict]:
        self.stats["messages"] += 1
        try:
            if is_ipfix(data):
                return self._ipfix(data, exporter, sensor)
            if is_netflow_v9(data):
                return self._v9(data, exporter, sensor)
        except (struct.error, IndexError, ValueError, OverflowError):
            self.stats["malformed"] += 1
        return []

    # ------------------------------------------------------------------ IPFIX
    def _ipfix(self, d, exporter, sensor):
        length, export_time, _seq, domain = struct.unpack_from("!HIII", d, 2)
        ctx = {"export": float(export_time), "uptime": None, "unix": None}
        out, off = [], 16
        while off + 4 <= length:
            set_id, set_len = struct.unpack_from("!HH", d, off)
            if set_len < 4 or off + set_len > length:
                self.stats["malformed"] += 1
                break
            body, end = off + 4, off + set_len
            if set_id == 2:
                self._templates(d, body, end, exporter, domain, ipfix=True, options=False)
            elif set_id == 3:
                self._templates(d, body, end, exporter, domain, ipfix=True, options=True)
            elif set_id >= 256:
                out += self._data(d, body, end, (exporter, domain, set_id), ctx, sensor or f"ipfix:{exporter}")
            off = end
        return out

    # ------------------------------------------------------------------ NetFlow v9
    def _v9(self, d, exporter, sensor):
        _count, uptime, unix_secs, _seq, source_id = struct.unpack_from("!HIIII", d, 2)
        ctx = {"export": float(unix_secs), "uptime": uptime, "unix": float(unix_secs)}
        out, off = [], 20
        while off + 4 <= len(d):
            fs_id, fs_len = struct.unpack_from("!HH", d, off)
            if fs_len < 4 or off + fs_len > len(d):
                if fs_len:
                    self.stats["malformed"] += 1
                break
            body, end = off + 4, off + fs_len
            if fs_id == 0:
                self._templates(d, body, end, exporter, source_id, ipfix=False, options=False)
            elif fs_id == 1:
                self._v9_options(d, body, end, exporter, source_id)
            elif fs_id >= 256:
                out += self._data(d, body, end, (exporter, source_id, fs_id), ctx, sensor or f"netflow9:{exporter}")
            off = end
        return out

    # ------------------------------------------------------------------ templates
    def _store(self, key, kind, fields):
        if len(self.templates) >= self.MAX_TEMPLATES and key not in self.templates:
            self.templates.pop(next(iter(self.templates)))
        self.templates[key] = (kind, fields)
        self.stats["templates"] += 1

    def _templates(self, d, off, end, exporter, domain, ipfix, options):
        while off + 4 <= end:
            tid, count = struct.unpack_from("!HH", d, off)
            off += 4
            if tid < 256:
                break   # padding
            if options:
                off += 2    # scope field count: scope fields are listed with the others
            if count == 0:   # template withdrawal
                self.templates.pop((exporter, domain, tid), None)
                continue
            fields = []
            for _ in range(count):
                ie, flen = struct.unpack_from("!HH", d, off)
                off += 4
                pen = 0
                if ipfix and ie & 0x8000:
                    pen = struct.unpack_from("!I", d, off)[0]
                    off += 4
                    ie &= 0x7FFF
                fields.append((pen, ie, flen))
            if off > end:
                self.stats["malformed"] += 1
                return
            self._store((exporter, domain, tid), "options" if options else "data", fields)

    def _v9_options(self, d, off, end, exporter, source_id):
        while off + 6 <= end:
            tid, scope_len, opt_len = struct.unpack_from("!HHH", d, off)
            off += 6
            if tid < 256:
                break
            n = (scope_len + opt_len) // 4
            fields = []
            for _ in range(n):
                ie, flen = struct.unpack_from("!HH", d, off)
                off += 4
                fields.append((0, ie, flen))
            self._store((exporter, source_id, tid), "options", fields)

    # ------------------------------------------------------------------ data
    def _data(self, d, off, end, key, ctx, sensor):
        tpl = self.templates.get(key)
        if tpl is None:
            self.stats["unknown_template"] += 1
            return []
        kind, fields = tpl
        fixed = sum(f[2] for f in fields if f[2] != 0xFFFF)
        out = []
        while off + max(1, fixed) <= end:
            vals = {}
            for pen, ie, flen in fields:
                if flen == 0xFFFF:                  # variable length (RFC 7011 s7)
                    flen = d[off]
                    off += 1
                    if flen == 255:
                        flen = struct.unpack_from("!H", d, off)[0]
                        off += 2
                if off + flen > end:
                    return out
                name = FIELDS.get((pen, ie))
                if name:
                    raw = d[off:off + flen]
                    if name in ("src4", "dst4"):
                        vals[name] = socket.inet_ntoa(raw) if flen == 4 else None
                    elif name in ("src6", "dst6"):
                        vals[name] = socket.inet_ntop(socket.AF_INET6, raw) if flen == 16 else None
                    else:
                        vals[name] = int.from_bytes(raw, "big")
                off += flen
            if kind == "data":
                rec = self._record(vals, ctx, sensor)
                if rec:
                    out.append(rec)
        return out

    def _record(self, v, ctx, sensor):
        src, dst = v.get("src4") or v.get("src6"), v.get("dst4") or v.get("dst6")
        if not src or not dst:
            return None
        ts = te = None
        if "start_ms" in v:
            ts, te = v["start_ms"] / 1000.0, v.get("end_ms", v["start_ms"]) / 1000.0
        elif "start_s" in v:
            ts, te = float(v["start_s"]), float(v.get("end_s", v["start_s"]))
        elif "start_us" in v:
            ts, te = _ntp(v["start_us"]), _ntp(v.get("end_us", v["start_us"]))
        elif "first_uptime" in v and ctx["uptime"] is not None:
            ts = ctx["unix"] - (ctx["uptime"] - v["first_uptime"]) / 1000.0
            te = ctx["unix"] - (ctx["uptime"] - v.get("last_uptime", v["first_uptime"])) / 1000.0
        if ts is None or not (0 < ts < 4e9 and 0 < te < 4e9):   # missing or impossible timestamps
            te = ctx["export"] or time.time()
            ts = te - min(v.get("duration_ms", 0), 86_400_000) / 1000.0
        proto = v.get("proto", 0)
        self.stats["records"] += 1
        return {
            "ts": ts, "te": max(te, ts), "src_ip": src, "dst_ip": dst,
            "src_port": v.get("sport", 0), "dst_port": v.get("dport", 0), "proto": proto,
            "pkts_fwd": v.get("packets", 0), "bytes_fwd": v.get("octets", 0),
            "pkts_bwd": v.get("r_packets", 0), "bytes_bwd": v.get("r_octets", 0),
            "flags_fwd": _flag_str(v.get("flags", 0)) if proto == 6 else "",
            "flags_bwd": _flag_str(v.get("r_flags", 0)) if proto == 6 else "",
            "seg": 0, "sensor": sensor,
        }


# ---------------------------------------------------------------------------
# Encoding (the lab's exporters and the tests)
# ---------------------------------------------------------------------------
_BIFLOW_V4 = [(0, 8, 4), (0, 12, 4), (0, 7, 2), (0, 11, 2), (0, 4, 1), (0, 6, 2), (0, 152, 8), (0, 153, 8),
              (0, 1, 8), (0, 2, 8), (REVERSE_PEN, 1, 8), (REVERSE_PEN, 2, 8), (REVERSE_PEN, 6, 2)]
_BIFLOW_V6 = [(0, 27, 16), (0, 28, 16)] + _BIFLOW_V4[2:]
_UNI_V9 = [(0, 8, 4), (0, 12, 4), (0, 7, 2), (0, 11, 2), (0, 4, 1), (0, 6, 1), (0, 22, 4), (0, 21, 4),
           (0, 1, 4), (0, 2, 4)]
IPFIX_RECORDS_PER_MESSAGE = 18
V9_RECORDS_PER_PACKET = 30


def _flags_int(s: str) -> int:
    return sum(1 << _FLAGS.index(c) for c in s if c in _FLAGS)


def _ipfix_template_set(tid, fields):
    body = struct.pack("!HH", tid, len(fields))
    for pen, ie, flen in fields:
        body += struct.pack("!HH", ie | (0x8000 if pen else 0), flen) + (struct.pack("!I", pen) if pen else b"")
    return struct.pack("!HH", 2, 4 + len(body)) + body


def _ipfix_record(r, v6):
    addr = (socket.inet_pton(socket.AF_INET6, r["src_ip"]) + socket.inet_pton(socket.AF_INET6, r["dst_ip"])) if v6 \
        else (socket.inet_aton(r["src_ip"]) + socket.inet_aton(r["dst_ip"]))
    return addr + struct.pack("!HHBHQQQQQQH", r["src_port"], r["dst_port"], r["proto"], _flags_int(r.get("flags_fwd", "")),
                              int(r["ts"] * 1000), int(r["te"] * 1000), r["bytes_fwd"], r["pkts_fwd"],
                              r["bytes_bwd"], r["pkts_bwd"], _flags_int(r.get("flags_bwd", "")))


def encode_ipfix(records: list[dict], domain: int = 1, seq: int = 0, export_time: float | None = None,
                 with_templates: bool = True) -> bytes:
    """One IPFIX message of biflow records (template 256 = IPv4, 257 = IPv6)."""
    records = records[:IPFIX_RECORDS_PER_MESSAGE]
    sets = b""
    if with_templates:
        sets += _ipfix_template_set(256, _BIFLOW_V4) + _ipfix_template_set(257, _BIFLOW_V6)
    for tid, v6 in ((256, False), (257, True)):
        rows = b"".join(_ipfix_record(r, v6) for r in records if (":" in r["src_ip"]) == v6)
        if rows:
            sets += struct.pack("!HH", tid, 4 + len(rows)) + rows
    t = int(export_time if export_time is not None else max((r["te"] for r in records), default=time.time()))
    return struct.pack("!HHIII", 10, 16 + len(sets), t, seq, domain) + sets


def encode_netflow_v9(records: list[dict], sys_uptime_ms: int = 3_600_000, now: float | None = None,
                      seq: int = 0, source_id: int = 1, with_template: bool = True) -> bytes:
    """One NetFlow v9 packet (initiator direction only, IPv4, like typical router export)."""
    records = [r for r in records if ":" not in r["src_ip"]][:V9_RECORDS_PER_PACKET]
    now = now if now is not None else max((r["te"] for r in records), default=time.time())
    flowsets = b""
    if with_template:
        tpl = struct.pack("!HH", 256, len(_UNI_V9)) + b"".join(struct.pack("!HH", ie, fl) for _, ie, fl in _UNI_V9)
        flowsets += struct.pack("!HH", 0, 4 + len(tpl)) + tpl
    rows = b""
    for r in records:
        first = max(0, int(sys_uptime_ms - (now - r["ts"]) * 1000))
        last = max(first, int(sys_uptime_ms - (now - r["te"]) * 1000))
        rows += (socket.inet_aton(r["src_ip"]) + socket.inet_aton(r["dst_ip"])
                 + struct.pack("!HHBBIIII", r["src_port"], r["dst_port"], r["proto"],
                               _flags_int(r.get("flags_fwd", "")) & 0xFF, first, last,
                               min(r["bytes_fwd"], 2 ** 32 - 1), min(r["pkts_fwd"], 2 ** 32 - 1)))
    if rows:
        pad = (-len(rows)) % 4
        flowsets += struct.pack("!HH", 256, 4 + len(rows) + pad) + rows + b"\x00" * pad
    count = len(records) + (1 if with_template else 0)
    return struct.pack("!HHIIII", 9, count, sys_uptime_ms, int(now), seq, source_id) + flowsets
