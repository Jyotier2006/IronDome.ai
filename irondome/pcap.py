"""Read-only packet-capture ingest, flow assembly and PCAP synthesis.

Reading (sensor side)
  iter_packets(path)   classic pcap (us / ns) and pcapng, opened read-only ('rb')
  parse_frame()        Ethernet (+802.1Q), Linux SLL/SLL2, raw IP, BSD loopback
                       -> IPv4 / IPv6 -> TCP / UDP / ICMP
  FlowAssembler        packets -> bidirectional FlowRecords with an IPFIX-style
                       exporter: idle timeouts, 10 s active timeout, per-flow SPLT,
                       DNS question/rcode, TLS ClientHello/ServerHello (JA3/JA3S/JA4),
                       QUIC version. Payload beyond handshake headers is never kept.

Writing (traffic lab side)
  write_pcap()         flow records -> packets -> classic pcap that opens in Wireshark;
                       bulk-data packets are snap-length truncated (orig_len preserved)
"""

from __future__ import annotations

import hashlib
import random
import socket
import struct

from . import dnsmsg
from . import tls as tlsmod
from .traffic import ACTIVE_TIMEOUT, HDR_TCP, HDR_UDP, MSS, TLS_PROFILES

LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LOOP = 0, 1, 101, 108
LINKTYPE_SLL, LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_SLL2 = 113, 228, 229, 276
_RAW_TYPES = {12, 14, LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6}
_VLAN = {0x8100, 0x88A8, 0x9100}
_FLAG_BITS = "FSRPAUEC"


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
def iter_packets(path):
    """Yield (ts, linktype, frame_bytes, orig_len) from a pcap or pcapng file."""
    with open(path, "rb") as f:
        head = f.read(4)
        if len(head) < 4:
            return
        if head == b"\x0a\x0d\x0d\x0a":
            yield from _iter_pcapng(f, head)
        else:
            yield from _iter_pcap(f, head)


def _iter_pcap(f, magic):
    m = struct.unpack("<I", magic)[0]
    if m in (0xA1B2C3D4, 0xA1B23C4D):
        endian = "<"
    elif m in (0xD4C3B2A1, 0x4D3CB2A1):
        endian = ">"
    else:
        raise ValueError("not a pcap/pcapng file")
    nano = m in (0xA1B23C4D, 0x4D3CB2A1)
    rest = f.read(20)
    linktype = struct.unpack(endian + "HHiIII", rest)[5] & 0x0FFFFFFF
    div = 1e9 if nano else 1e6
    rec = struct.Struct(endian + "IIII")
    while True:
        hdr = f.read(16)
        if len(hdr) < 16:
            return
        sec, frac, incl, orig = rec.unpack(hdr)
        data = f.read(incl)
        if len(data) < incl:
            return
        yield sec + frac / div, linktype, data, orig


def _iter_pcapng(f, first4):
    endian = "<"
    interfaces = []  # (linktype, ts_divisor)
    buf = first4
    while True:
        if len(buf) < 4:
            buf += f.read(4 - len(buf))
            if len(buf) < 4:
                return
        head = buf + f.read(4)
        buf = b""
        if len(head) < 8:
            return
        btype = struct.unpack(endian + "I", head[:4])[0]
        if btype == 0x0A0D0D0A:  # section header: determine byte order
            bom = f.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", head[4:8])[0]
            f.read(blen - 12)
            interfaces = []
            continue
        blen = struct.unpack(endian + "I", head[4:8])[0]
        if blen < 12:
            return
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            return
        if btype == 1:  # interface description
            linktype = struct.unpack(endian + "H", body[:2])[0]
            div = 1e6
            opt = body[8:-4]
            i = 0
            while i + 4 <= len(opt):
                code, olen = struct.unpack(endian + "HH", opt[i:i + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:  # if_tsresol
                    r = opt[i + 4]
                    div = float(2 ** (r & 0x7F)) if r & 0x80 else float(10 ** r)
                i += 4 + ((olen + 3) & ~3)
            interfaces.append((linktype, div))
        elif btype == 6:  # enhanced packet
            iface, hi, lo, cap, orig = struct.unpack(endian + "IIIII", body[:20])
            lt, div = interfaces[iface] if iface < len(interfaces) else (LINKTYPE_ETHERNET, 1e6)
            yield ((hi << 32) | lo) / div, lt, body[20:20 + cap], orig
        elif btype == 3:  # simple packet
            orig = struct.unpack(endian + "I", body[:4])[0]
            lt = interfaces[0][0] if interfaces else LINKTYPE_ETHERNET
            yield 0.0, lt, body[4:4 + min(orig, len(body) - 8)], orig


def _ip_str(b: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET if len(b) == 4 else socket.AF_INET6, b)


class Packet:
    __slots__ = ("src", "dst", "proto", "sport", "dport", "flags", "ip_len", "payload", "payload_len", "seq", "frag")

    def __init__(self, src, dst, proto, sport, dport, flags, ip_len, payload, payload_len, seq=0, frag=False):
        self.src, self.dst, self.proto, self.sport, self.dport = src, dst, proto, sport, dport
        self.flags, self.ip_len, self.payload, self.payload_len, self.seq, self.frag = flags, ip_len, payload, payload_len, seq, frag


_frag_ports: dict = {}


def parse_frame(linktype: int, data: bytes, orig_len: int) -> Packet | None:
    try:
        if linktype == LINKTYPE_ETHERNET:
            etype = struct.unpack_from("!H", data, 12)[0]
            off = 14
            while etype in _VLAN:
                etype = struct.unpack_from("!H", data, off + 2)[0]
                off += 4
        elif linktype == LINKTYPE_SLL:
            etype, off = struct.unpack_from("!H", data, 14)[0], 16
        elif linktype == LINKTYPE_SLL2:
            etype, off = struct.unpack_from("!H", data, 0)[0], 20
        elif linktype in _RAW_TYPES:
            etype, off = (0x86DD if data[0] >> 4 == 6 else 0x0800), 0
        elif linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
            fam = struct.unpack_from("<I" if linktype == LINKTYPE_NULL else "!I", data, 0)[0]
            etype, off = (0x0800 if fam == 2 else 0x86DD), 4
        else:
            return None
        if etype == 0x0800:
            return _parse_ipv4(data, off, orig_len)
        if etype == 0x86DD:
            return _parse_ipv6(data, off, orig_len)
    except (struct.error, IndexError, ValueError, OSError):
        return None
    return None


def _parse_ipv4(data, off, orig_len):
    vihl = data[off]
    ihl = (vihl & 0x0F) * 4
    total = struct.unpack_from("!H", data, off + 2)[0] or (orig_len - off)
    ident, frag = struct.unpack_from("!HH", data, off + 4)
    proto = data[off + 9]
    src, dst = _ip_str(data[off + 12:off + 16]), _ip_str(data[off + 16:off + 20])
    frag_off = frag & 0x1FFF
    more = bool(frag & 0x2000)
    if frag_off:  # non-first fragment: no transport header; reuse ports of the first fragment
        sport, dport = _frag_ports.get((src, dst, proto, ident), (0, 0))
        return Packet(src, dst, proto, sport, dport, 0, total, b"", total - ihl, frag=True)
    pkt = _parse_l4(data, off + ihl, proto, src, dst, total, total - ihl)
    if pkt and more:
        if len(_frag_ports) > 50_000:
            _frag_ports.clear()
        _frag_ports[(src, dst, proto, ident)] = (pkt.sport, pkt.dport)
    return pkt


def _parse_ipv6(data, off, orig_len):
    plen = struct.unpack_from("!H", data, off + 4)[0]
    nh = data[off + 6]
    src, dst = _ip_str(data[off + 8:off + 24]), _ip_str(data[off + 24:off + 40])
    total = 40 + plen if plen else orig_len - off
    p = off + 40
    for _ in range(6):
        if nh in (0, 43, 60):
            nh, hlen = data[p], (data[p + 1] + 1) * 8
            p += hlen
        elif nh == 44:
            if struct.unpack_from("!H", data, p + 2)[0] & 0xFFF8:
                return Packet(src, dst, data[p], 0, 0, 0, total, b"", 0, frag=True)
            nh = data[p]
            p += 8
        else:
            break
    return _parse_l4(data, p, nh, src, dst, total, total - (p - off))


def _parse_l4(data, p, proto, src, dst, ip_len, l4_len):
    end = min(len(data), p + l4_len) if l4_len > 0 else len(data)
    if proto == 6:
        sport, dport, seq = struct.unpack_from("!HHI", data, p)
        doff = (data[p + 12] >> 4) * 4
        flags = data[p + 13]
        return Packet(src, dst, 6, sport, dport, flags, ip_len, data[p + doff:end], max(0, l4_len - doff), seq)
    if proto == 17:
        sport, dport, ulen = struct.unpack_from("!HHH", data, p)
        return Packet(src, dst, 17, sport, dport, 0, ip_len, data[p + 8:end], max(0, (ulen or l4_len) - 8))
    if proto in (1, 58):
        typ, code = data[p], data[p + 1]
        return Packet(src, dst, proto, 0, (typ << 8) | code, 0, ip_len, b"", max(0, l4_len - 8))
    return Packet(src, dst, proto, 0, 0, 0, ip_len, b"", l4_len)


# ---------------------------------------------------------------------------
# Flow assembly
# ---------------------------------------------------------------------------
def _flag_str(bits: int) -> str:
    return "".join(_FLAG_BITS[i] for i in range(8) if bits & (1 << i))


class _Flow:
    __slots__ = ("src", "sport", "dst", "dport", "proto", "ts", "te", "seg_start", "seg", "pf", "bf", "pb", "bb",
                 "ff", "fb", "splt_len", "splt_iat", "last_data", "dns", "dns_done", "tls_ch", "tls_sh", "quic",
                 "buf_f", "buf_b", "next_seq_f", "next_seq_b", "data_pkts_f", "data_pkts_b", "fin_f", "fin_b", "rst",
                 "closed_at")

    def __init__(self, pkt, ts, reverse):
        if reverse:
            self.src, self.sport, self.dst, self.dport = pkt.dst, pkt.dport, pkt.src, pkt.sport
        else:
            self.src, self.sport, self.dst, self.dport = pkt.src, pkt.sport, pkt.dst, pkt.dport
        self.proto = pkt.proto
        self.ts = self.te = self.seg_start = ts
        self.seg = 0
        self.pf = self.bf = self.pb = self.bb = self.ff = self.fb = 0
        self.splt_len, self.splt_iat = [], []
        self.last_data = None
        self.dns = None
        self.dns_done = False
        self.tls_ch = self.tls_sh = None
        self.quic = None
        self.buf_f, self.buf_b = bytearray(), bytearray()
        self.next_seq_f = self.next_seq_b = None
        self.data_pkts_f = self.data_pkts_b = 0
        self.fin_f = self.fin_b = self.rst = False
        self.closed_at = None


class FlowAssembler:
    """Turns packets into FlowRecords like an IPFIX metering process."""

    TCP_IDLE = 15.0
    TCP_HALF_OPEN_IDLE = 2.0
    UDP_IDLE = 5.0
    ICMP_IDLE = 5.0
    SPLT_MAX = 20
    HELLO_BUF = 16384

    def __init__(self, active_timeout: float = ACTIVE_TIMEOUT, sensor: str | None = None):
        self.active = active_timeout
        self.sensor = sensor
        self.flows: dict = {}
        self.out: list = []
        self.last_sweep = None
        self.packets = 0

    def _key(self, p):
        a, b = (p.src, p.sport), (p.dst, p.dport)
        return (p.proto, a, b) if a <= b else (p.proto, b, a)

    def add(self, ts: float, p: Packet):
        self.packets += 1
        key = self._key(p)
        f = self.flows.get(key)
        if f is not None and f.closed_at is not None and p.proto == 6 and (p.flags & 0x12) == 0x02:
            self._export(key, f, final=True)     # port reuse: a new connection on a closed 5-tuple
            f = None
        if f is None:
            reverse = p.proto == 6 and (p.flags & 0x12) == 0x12   # first packet seen is a SYN-ACK
            f = self.flows[key] = _Flow(p, ts, reverse)
        fwd = p.src == f.src and p.sport == f.sport
        if fwd:
            f.pf += 1
            f.bf += p.ip_len
            f.ff |= p.flags
        else:
            f.pb += 1
            f.bb += p.ip_len
            f.fb |= p.flags
        f.te = max(f.te, ts)
        if p.payload_len > 0 and len(f.splt_len) < self.SPLT_MAX and not p.frag:
            iat = 0.0 if f.last_data is None else (ts - f.last_data) * 1000.0
            f.splt_len.append(p.ip_len if fwd else -p.ip_len)
            f.splt_iat.append(round(iat, 3))
            f.last_data = ts
        if p.proto == 17:
            self._udp_meta(f, p, fwd)
        elif p.proto == 6:
            if p.flags & 0x04:
                f.rst = True
            if p.flags & 0x01:
                if fwd:
                    f.fin_f = True
                else:
                    f.fin_b = True
            if p.payload:
                self._tls_meta(f, p, fwd)
        # export completed DNS transactions promptly; closed TCP connections linger 1 s
        # so the trailing ACK is not mistaken for a new flow (as IPFIX exporters do)
        if f.proto == 6 and f.closed_at is None and (f.rst or (f.fin_f and f.fin_b)):
            f.closed_at = ts
        if f.dns_done and f.pb:
            self._export(key, f, final=True)
        elif ts - f.seg_start >= self.active and f.closed_at is None:
            self._export(key, f, final=False)
        if self.last_sweep is None:
            self.last_sweep = ts
        elif ts - self.last_sweep >= 1.0:
            self.sweep(ts)

    def _udp_meta(self, f, p, fwd):
        if (p.sport == 53 or p.dport == 53) and not f.dns_done and p.payload:
            m = dnsmsg.parse(p.payload)
            if m:
                if not m["qr"] and f.dns is None:
                    f.dns = {"qname": m["qname"], "qtype": m["qtype"], "rcode": "NORESPONSE", "answers": 0}
                elif m["qr"]:
                    f.dns = f.dns or {"qname": m["qname"], "qtype": m["qtype"]}
                    f.dns["rcode"] = m["rcode"]
                    f.dns["answers"] = m["answers"]
                    f.dns_done = True
        elif (p.dport == 443 or p.sport == 443) and f.quic is None and fwd and p.payload and p.payload[0] & 0x80 \
                and len(p.payload) >= 5:
            version = struct.unpack_from("!I", p.payload, 1)[0]
            f.quic = {"version": "1" if version == 1 else ("2" if version == 0x6B3343CF else hex(version))}

    def _tls_meta(self, f, p, fwd):
        if fwd:
            if f.tls_ch is not None or f.data_pkts_f > 8 or len(f.buf_f) >= self.HELLO_BUF:
                return
            f.data_pkts_f += 1
            if not f.buf_f and p.payload[0] != 0x16:
                f.data_pkts_f = 99  # not TLS
                return
            if f.next_seq_f is not None and p.seq != f.next_seq_f:
                return  # retransmission / out of order: skip
            f.buf_f += p.payload[: self.HELLO_BUF - len(f.buf_f)]
            f.next_seq_f = (p.seq + p.payload_len) & 0xFFFFFFFF
            ch = tlsmod.parse_client_hello(bytes(f.buf_f))
            if ch:
                f.tls_ch = ch
                f.buf_f = bytearray()
        else:
            if f.tls_sh is not None or f.data_pkts_b > 8 or len(f.buf_b) >= self.HELLO_BUF:
                return
            f.data_pkts_b += 1
            if not f.buf_b and p.payload[0] != 0x16:
                f.data_pkts_b = 99
                return
            if f.next_seq_b is not None and p.seq != f.next_seq_b:
                return
            f.buf_b += p.payload[: self.HELLO_BUF - len(f.buf_b)]
            f.next_seq_b = (p.seq + p.payload_len) & 0xFFFFFFFF
            sh = tlsmod.parse_server_hello(bytes(f.buf_b))
            if sh:
                f.tls_sh = sh
                f.buf_b = bytearray()

    def _record(self, f):
        rec = {"ts": f.seg_start, "te": f.te, "src_ip": f.src, "src_port": f.sport, "dst_ip": f.dst,
               "dst_port": f.dport, "proto": f.proto, "pkts_fwd": f.pf, "bytes_fwd": f.bf, "pkts_bwd": f.pb,
               "bytes_bwd": f.bb, "flags_fwd": _flag_str(f.ff) if f.proto == 6 else "",
               "flags_bwd": _flag_str(f.fb) if f.proto == 6 else "", "seg": f.seg}
        if f.seg == 0:
            if f.dns:
                rec["dns"] = {"qname": f.dns["qname"], "qtype": f.dns["qtype"],
                              "rcode": f.dns.get("rcode", "NORESPONSE"), "answers": f.dns.get("answers", 0)}
            if f.tls_ch or f.tls_sh:
                rec["tls"] = tlsmod.tls_metadata(f.tls_ch, f.tls_sh)
            if f.quic:
                rec["quic"] = f.quic
            if f.splt_len:
                rec["splt"] = {"len": list(f.splt_len), "iat": list(f.splt_iat)}
        if self.sensor:
            rec["sensor"] = self.sensor
        return rec

    def _export(self, key, f, final):
        if f.pf or f.pb:
            self.out.append(self._record(f))
        if final:
            self.flows.pop(key, None)
        else:   # active timeout: start a continuation segment
            f.seg += 1
            f.seg_start = f.te
            f.pf = f.bf = f.pb = f.bb = f.ff = f.fb = 0

    def sweep(self, now: float):
        self.last_sweep = now
        for key, f in list(self.flows.items()):
            idle = now - f.te
            if f.closed_at is not None:
                if now - f.closed_at >= 1.0:
                    self._export(key, f, final=True)
                continue
            if f.proto == 6:
                limit = self.TCP_HALF_OPEN_IDLE if not (f.ff & 0x10 and f.pb) else self.TCP_IDLE
            elif f.proto == 17:
                limit = self.UDP_IDLE
            else:
                limit = self.ICMP_IDLE
            if idle >= limit:
                self._export(key, f, final=True)
            elif now - f.seg_start >= self.active:
                self._export(key, f, final=False)

    def flush(self):
        for key, f in list(self.flows.items()):
            self._export(key, f, final=True)

    def drain(self) -> list[dict]:
        out, self.out = self.out, []
        return out


def read_flows(path, sensor: str | None = None, batch: int = 2000):
    """Generator of FlowRecord batches from a capture file (read-only)."""
    asm = FlowAssembler(sensor=sensor)
    n = 0
    for ts, lt, data, orig in iter_packets(path):
        p = parse_frame(lt, data, orig)
        if p is None:
            continue
        asm.add(ts, p)
        n += 1
        if len(asm.out) >= batch:
            yield asm.drain()
    asm.flush()
    rest = asm.drain()
    if rest:
        yield rest


# ---------------------------------------------------------------------------
# Synthesis (traffic lab): flow records -> packets -> pcap
# ---------------------------------------------------------------------------
def _csum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _mac(ip: str) -> bytes:
    return b"\x02" + hashlib.md5(ip.encode()).digest()[:5]


class _Synth:
    def __init__(self, seed=7):
        self.rng = random.Random(seed)
        self.ip_id = 0

    def frame(self, src, dst, proto, l4: bytes, ip_len: int) -> bytes:
        self.ip_id = (self.ip_id + 1) & 0xFFFF
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, self.ip_id, 0x4000, 64, proto, 0,
                          socket.inet_aton(src), socket.inet_aton(dst))
        hdr = hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:]
        return _mac(dst) + _mac(src) + b"\x08\x00" + hdr + l4

    def tcp(self, src, sp, dst, dp, seq, ack, flags, payload: bytes, ip_len: int) -> bytes:
        seg = struct.pack("!HHIIBBHHH", sp, dp, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 64240, 0, 0)
        return self.frame(src, dst, 6, seg + payload, ip_len)

    def udp(self, src, sp, dst, dp, payload: bytes, ip_len: int) -> bytes:
        return self.frame(src, dst, 17, struct.pack("!HHHH", sp, dp, ip_len - 20, 0) + payload, ip_len)

    def icmp(self, src, dst, typ, code, payload: bytes, ip_len: int) -> bytes:
        body = struct.pack("!BBHHH", typ, code, 0, 1, 1) + payload
        body = body[:2] + struct.pack("!H", _csum(body)) + body[4:]
        return self.frame(src, dst, 1, body, ip_len)


def _fill(n: int) -> bytes:
    return b"\x00" * max(0, n)


def _data_sizes(total_pkts, total_bytes, fixed_sizes, ctrl):
    """IP lengths of the non-control packets of one direction (SPLT sizes first)."""
    rest_pkts = max(0, total_pkts - ctrl - len(fixed_sizes))
    rest_bytes = total_bytes - HDR_TCP * ctrl - sum(fixed_sizes)
    payload = max(0, rest_bytes - HDR_TCP * rest_pkts)
    sizes = list(fixed_sizes)
    for _ in range(rest_pkts):
        chunk = min(MSS, payload)
        sizes.append(HDR_TCP + chunk)
        payload -= chunk
    if payload > 0 and sizes:     # inconsistent record: put the remainder in the last packet
        sizes[-1] += payload
    return sizes


def _tcp_packets(sy: _Synth, r: dict, rng: random.Random):
    """Realise a TCP flow record as (ts, frame, orig_len, keep_full) tuples."""
    out = []
    src, sp, dst, dp = r["src_ip"], r["src_port"], r["dst_ip"], r["dst_port"]
    ff, fb = r.get("flags_fwd", ""), r.get("flags_bwd", "")
    ts, te = r["ts"], max(r["te"], r["ts"])
    seg0 = r.get("seg", 0) == 0
    seq_f, seq_b = rng.getrandbits(32), rng.getrandbits(32)
    ctrl_f, ctrl_b = [], []
    if seg0 and "S" in ff:
        ctrl_f.append(("S", 0x02))
    if seg0 and "S" in fb:
        ctrl_b.append(("SA", 0x12))
    elif seg0 and "R" in fb and "S" in ff:
        ctrl_b.append(("RA", 0x14))
    if seg0 and "S" in ff and "S" in fb and "A" in ff:
        ctrl_f.append(("A", 0x10))
    tail_f = [("F", 0x11)] if "F" in ff else ([("R", 0x04)] if "R" in ff else [])
    tail_b = [("F", 0x11)] if "F" in fb else ([("R", 0x14)] if ("R" in fb and not ctrl_b) else [])
    splt = (r.get("splt") or {}) if seg0 else {}
    lens = splt.get("len", [])
    iats = splt.get("iat", [])
    f_fixed = [x for x in lens if x > 0]
    b_fixed = [-x for x in lens if x < 0]
    n_ctrl_f, n_ctrl_b = len(ctrl_f) + len(tail_f), len(ctrl_b) + len(tail_b)
    f_sizes = _data_sizes(r["pkts_fwd"], r["bytes_fwd"], f_fixed, n_ctrl_f) if r["pkts_fwd"] >= n_ctrl_f else []
    b_sizes = _data_sizes(r["pkts_bwd"], r["bytes_bwd"], b_fixed, n_ctrl_b) if r["pkts_bwd"] >= n_ctrl_b else []
    tls = r.get("tls") or {}
    profile = tls.get("_profile")
    hello_f = hello_b = None
    if profile and profile in TLS_PROFILES and f_fixed:
        hello_f = tlsmod.build_client_hello(TLS_PROFILES[profile], tls.get("sni") or None, rng.randbytes(32))
        tls13 = 0x0304 in TLS_PROFILES[profile].get("versions", [])
        hello_b = tlsmod.build_server_hello(0x0303, 0x1301 if tls13 else 0xC02F,
                                            [43, 51] if tls13 else [65281, 11, 23], 0x0304 if tls13 else None,
                                            rng.randbytes(32))
    # timeline: handshake, SPLT-ordered data, the remaining data spread evenly, closing
    rtt = min(0.05, (te - ts) / 10 if te > ts else 0.001)
    t = ts
    events = []
    for name, fl in ctrl_f[:1]:
        events.append((t, True, fl, 0))
    for name, fl in ctrl_b:
        events.append((t + rtt / 2, False, fl, 0))
    for name, fl in ctrl_f[1:]:
        events.append((t + rtt, True, fl, 0))
    t = t + rtt
    fi = bi = 0
    for k, x in enumerate(lens):
        t += (iats[k] if k < len(iats) else 1.0) / 1000.0
        if x > 0 and fi < len(f_sizes):
            events.append((t, True, 0x18, f_sizes[fi]))
            fi += 1
        elif x < 0 and bi < len(b_sizes):
            events.append((t, False, 0x18, b_sizes[bi]))
            bi += 1
    rest = [(True, s) for s in f_sizes[fi:]] + [(False, s) for s in b_sizes[bi:]]
    rng.shuffle(rest)
    end = te - rtt / 2 if te - rtt / 2 > t else t
    for k, (d, s) in enumerate(rest):
        tk = t + (end - t) * (k + 1) / (len(rest) + 1)
        events.append((tk, d, 0x18 if s > HDR_TCP else 0x10, s))
    for name, fl in tail_f:
        events.append((te, True, fl, 0))
    for name, fl in tail_b:
        events.append((te, False, fl, 0))
    events.sort(key=lambda e: e[0])
    first_f = first_b = True
    for tk, is_f, fl, size in events:
        ip_len = size if size else HDR_TCP
        pay_len = ip_len - HDR_TCP
        payload = b""
        keep = False
        if pay_len > 0:
            if is_f and first_f and hello_f is not None:
                payload = hello_f + _fill(pay_len - len(hello_f))
                keep = True
            elif not is_f and first_b and hello_b is not None:
                payload = hello_b + _fill(pay_len - len(hello_b))
                keep = True
            else:
                payload = _fill(pay_len)
            if is_f:
                first_f = False
            else:
                first_b = False
            ip_len = HDR_TCP + len(payload)
        if is_f:
            frame = sy.tcp(src, sp, dst, dp, seq_f, seq_b, fl, payload, ip_len)
            seq_f += len(payload) + (1 if fl & 0x03 else 0)
        else:
            frame = sy.tcp(dst, dp, src, sp, seq_b, seq_f, fl, payload, ip_len)
            seq_b += len(payload) + (1 if fl & 0x03 else 0)
        out.append((tk, frame, len(frame), keep))
    return out


def _udp_packets(sy: _Synth, r: dict, rng: random.Random):
    out = []
    src, sp, dst, dp = r["src_ip"], r["src_port"], r["dst_ip"], r["dst_port"]
    ts, te = r["ts"], max(r["te"], r["ts"])
    dns = r.get("dns")
    if dns and r.get("seg", 0) == 0:
        txid = rng.getrandbits(16)
        q = dnsmsg.build_query(txid, dns["qname"], dns["qtype"])
        out.append((ts, sy.udp(src, sp, dst, dp, q, HDR_UDP + len(q)), None, True))
        if r["pkts_bwd"]:
            resp = dnsmsg.build_response(txid, dns["qname"], dns["qtype"], dns["rcode"], dns.get("answers", 1),
                                         total_len=r["bytes_bwd"] - HDR_UDP)
            out.append((te, sy.udp(dst, dp, src, sp, resp, HDR_UDP + len(resp)), None, True))
        return [(t, fr, len(fr), k) for t, fr, _, k in out]
    splt = (r.get("splt") or {}) if r.get("seg", 0) == 0 else {}
    lens, iats = splt.get("len", []), splt.get("iat", [])
    quic = r.get("quic")
    events = []
    t = ts
    for k, x in enumerate(lens):
        t += (iats[k] if k < len(iats) else 1.0) / 1000.0
        events.append((t, x > 0, abs(x)))
    nf = r["pkts_fwd"] - sum(1 for _, d, _ in events if d)
    nb = r["pkts_bwd"] - sum(1 for _, d, _ in events if not d)
    bf = r["bytes_fwd"] - sum(s for _, d, s in events if d)
    bb = r["bytes_bwd"] - sum(s for _, d, s in events if not d)
    for is_f, n, b in ((True, nf, bf), (False, nb, bb)):
        for k in range(max(0, n)):
            size = max(HDR_UDP, b // max(1, n) + (1 if k < b % max(1, n) else 0))
            events.append((t + (te - t) * (k + 1) / (n + 1), is_f, size))
    events.sort(key=lambda e: e[0])
    first = True
    for tk, is_f, size in events:
        pay = max(0, size - HDR_UDP)
        payload = _fill(pay)
        keep = False
        if quic and is_f and first and pay >= 5:
            payload = bytes([0xC3]) + struct.pack("!I", 1) + _fill(pay - 5)
            first = False
            keep = True
        a, ap, b, bp = (src, sp, dst, dp) if is_f else (dst, dp, src, sp)
        fr = sy.udp(a, ap, b, bp, payload, HDR_UDP + len(payload))
        out.append((tk, fr, len(fr), keep))
    return out


def _icmp_packets(sy: _Synth, r: dict, rng: random.Random):
    out = []
    ts, te = r["ts"], max(r["te"], r["ts"])
    typ = r.get("dst_port", 0x0800) >> 8
    for is_f, n, b in ((True, r["pkts_fwd"], r["bytes_fwd"]), (False, r["pkts_bwd"], r["bytes_bwd"])):
        for k in range(n):
            size = max(28, b // max(1, n))
            tk = ts + (te - ts) * (k + 0.5) / max(1, n)
            a, bb = (r["src_ip"], r["dst_ip"]) if is_f else (r["dst_ip"], r["src_ip"])
            fr = sy.icmp(a, bb, typ if is_f else 0, 0, _fill(size - 28), size)
            out.append((tk, fr, len(fr), False))
    return out


def write_pcap(path, records, snaplen: int = 128, seed: int = 7, max_packets_per_record: int = 5000) -> dict:
    """Synthesise packets for flow records and write a classic (microsecond) pcap.

    Bulk-data packets are truncated to `snaplen` bytes (orig_len keeps the wire size),
    which is how production taps keep captures small; handshakes and DNS stay whole."""
    sy = _Synth(seed)
    rng = random.Random(seed)
    pkts = []
    for r in records:
        if r["pkts_fwd"] + r["pkts_bwd"] > max_packets_per_record:
            continue
        if r["proto"] == 6:
            pkts += _tcp_packets(sy, r, rng)
        elif r["proto"] == 17:
            pkts += _udp_packets(sy, r, rng)
        elif r["proto"] == 1:
            pkts += _icmp_packets(sy, r, rng)
    pkts.sort(key=lambda p: p[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for ts, frame, orig, keep in pkts:
            data = frame if keep or len(frame) <= snaplen else frame[:snaplen]
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            if usec >= 1_000_000:
                sec, usec = sec + 1, usec - 1_000_000
            f.write(struct.pack("<IIII", sec, usec, len(data), orig) + data)
    return {"packets": len(pkts), "records": len(records)}
