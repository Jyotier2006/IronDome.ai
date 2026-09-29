"""Minimal DNS wire format: parse queries/responses (sensor) and build them (traffic lab)."""

from __future__ import annotations

import struct

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "NULL": 10, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28,
          "SRV": 33, "KEY": 25, "OPT": 41, "SVCB": 64, "HTTPS": 65, "ANY": 255}
QTYPE_NAMES = {v: k for k, v in QTYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
RCODE_NUMS = {v: k for k, v in RCODES.items()}

_OPT_MIN = 11          # root name + type + class + ttl + rdlen
_OPT_PAD_HDR = 4       # EDNS padding option code + length


def encode_name(qname: str) -> bytes:
    out = b""
    for label in qname.strip(".").split("."):
        if label:
            raw = label.encode("ascii", "replace")[:63]
            out += bytes([len(raw)]) + raw
    return out + b"\x00"


def query_len(qname: str) -> int:
    return 12 + len(encode_name(qname)) + 4


def _answer_rr(qtype: int, rdata: bytes) -> bytes:
    # name = pointer to the question name at offset 12
    return b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 300, len(rdata)) + rdata


def _rdata(qtype_name: str, i: int) -> bytes:
    if qtype_name == "AAAA":
        return bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [i + 1])
    if qtype_name in ("A", "ANY"):
        return bytes([198, 51, 100, (i % 250) + 1])
    if qtype_name == "TXT":
        return b"\x08v=spf1 ~"
    if qtype_name in ("CNAME", "NS", "PTR"):
        return encode_name(f"host{i}.example.net")
    if qtype_name == "MX":
        return struct.pack("!H", 10) + encode_name(f"mx{i}.example.net")
    return b"\x00" * 4


def min_response_len(qname: str, qtype: str, rcode: str, answers: int) -> int:
    n = query_len(qname)
    if rcode == "NOERROR":
        n += sum(12 + len(_rdata(qtype, i)) for i in range(answers))
    return n


def build_query(txid: int, qname: str, qtype: str) -> bytes:
    return (struct.pack("!HHHHHH", txid & 0xFFFF, 0x0100, 1, 0, 0, 0)
            + encode_name(qname) + struct.pack("!HH", QTYPES.get(qtype, 1), 1))


def build_response(txid: int, qname: str, qtype: str, rcode: str, answers: int, total_len: int | None = None) -> bytes:
    """Build a response; if total_len is larger than the natural size, the remainder is
    carried in an EDNS(0) padding option (RFC 7830) so sizes match flow records exactly."""
    qt = QTYPES.get(qtype, 1)
    rc = RCODE_NUMS.get(rcode, 0)
    answers = answers if rc == 0 else 0
    rdatas = [_rdata(qtype, i) for i in range(answers)]
    question = encode_name(qname) + struct.pack("!HH", qt, 1)
    natural = 12 + len(question) + sum(12 + len(rd) for rd in rdatas)
    remaining = (total_len - natural) if total_len is not None else 0
    opt = b""
    arcount = 0
    if remaining >= _OPT_MIN + _OPT_PAD_HDR:
        pad = remaining - _OPT_MIN - _OPT_PAD_HDR
        opt_rdata = struct.pack("!HH", 12, pad) + b"\x00" * pad
        opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, len(opt_rdata)) + opt_rdata
        arcount = 1
    elif remaining > 0 and rdatas:
        rdatas[-1] += b"\x00" * remaining     # small remainder: grow the last answer's rdata
    body = question + b"".join(_answer_rr(qt, rd) for rd in rdatas) + opt
    flags = 0x8180 | rc
    return struct.pack("!HHHHHH", txid & 0xFFFF, flags, 1, answers, 0, arcount) + body


def _read_name(buf: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    jumped_end = None
    while off < len(buf):
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(buf) or depth > 8:
                raise ValueError("bad pointer")
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            name, _ = _read_name(buf, ptr, depth + 1)
            labels.append(name)
            jumped_end = off + 2
            break
        labels.append(buf[off + 1 : off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    name = ".".join(lab for lab in labels if lab)
    return name, (jumped_end if jumped_end is not None else off)


def parse(payload: bytes) -> dict | None:
    """Parse the header and first question of a DNS message."""
    if len(payload) < 17:
        return None
    try:
        txid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", payload, 0)
        if qd < 1 or qd > 4:
            return None
        qname, off = _read_name(payload, 12)
        qtype, _qclass = struct.unpack_from("!HH", payload, off)
    except (struct.error, ValueError, IndexError):
        return None
    return {
        "id": txid,
        "qr": bool(flags & 0x8000),
        "qname": qname.lower(),
        "qtype": QTYPE_NAMES.get(qtype, str(qtype)),
        "rcode": RCODES.get(flags & 0x000F, str(flags & 0x000F)),
        "answers": an,
    }
