"""TLS handshake metadata: ClientHello / ServerHello parsing and fingerprints.

Only the cleartext handshake is read (record type 22). Application data is never
touched and nothing is decrypted (PS constraint b). Fingerprints implemented:

  JA3   md5("SSLVersion,Ciphers,Extensions,EllipticCurves,EcPointFormats")
  JA3S  md5("SSLVersion,Cipher,Extensions")                       (ServerHello)
  JA4   FoxIO JA4 client fingerprint  e.g. t13d1516h2_8daaf6152771_e5627efa2ab1

GREASE values (RFC 8701) are ignored everywhere, as the fingerprint specs require.
"""

from __future__ import annotations

import hashlib
import struct

GREASE = frozenset(0x0A0A + 0x1010 * i for i in range(16))

EXT_SNI = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B

_VERSION_NAMES = {0x0304: "TLS1.3", 0x0303: "TLS1.2", 0x0302: "TLS1.1", 0x0301: "TLS1.0", 0x0300: "SSL3.0"}
_JA4_VERSION = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
                0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3"}


def _u16_list(data: bytes) -> list[int]:
    return [struct.unpack_from("!H", data, i)[0] for i in range(0, len(data) - 1, 2)]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def _parse_extensions(buf: bytes, off: int, end: int) -> list[tuple[int, bytes]]:
    exts = []
    if off + 2 > end:
        return exts
    (total,) = struct.unpack_from("!H", buf, off)
    off += 2
    stop = min(end, off + total)
    while off + 4 <= stop:
        etype, elen = struct.unpack_from("!HH", buf, off)
        off += 4
        exts.append((etype, buf[off : off + elen]))
        off += elen
    return exts


def _handshake(payload: bytes, want_type: int) -> tuple[bytes, int, int] | None:
    """Locate a handshake message inside a TLS record stream (first record only)."""
    if len(payload) < 9 or payload[0] != 0x16:
        return None
    hs_type = payload[5]
    if hs_type != want_type:
        return None
    hs_len = int.from_bytes(payload[6:9], "big")
    start = 9
    end = start + hs_len
    # Require the complete message: a fingerprint of a truncated hello would be wrong.
    if hs_len < 38 or end > len(payload):
        return None
    return payload, start, end


def parse_client_hello(payload: bytes) -> dict | None:
    """Parse a TLS ClientHello record. Returns None if payload is not a complete ClientHello."""
    found = _handshake(payload, 0x01)
    if not found:
        return None
    buf, off, end = found
    try:
        (legacy_version,) = struct.unpack_from("!H", buf, off)
        off += 2 + 32
        sid_len = buf[off]
        off += 1 + sid_len
        (cs_len,) = struct.unpack_from("!H", buf, off)
        off += 2
        ciphers = _u16_list(buf[off : off + cs_len])
        off += cs_len
        comp_len = buf[off]
        off += 1 + comp_len
        exts = _parse_extensions(buf, off, end)
    except (struct.error, IndexError):
        return None

    info = {
        "legacy_version": legacy_version,
        "ciphers": ciphers,
        "extensions": [t for t, _ in exts],
        "groups": [],
        "point_formats": [],
        "sig_algs": [],
        "alpn": [],
        "supported_versions": [],
        "sni": None,
    }
    for etype, data in exts:
        try:
            if etype == EXT_SNI and len(data) >= 5:
                name_len = struct.unpack_from("!H", data, 3)[0]
                info["sni"] = data[5 : 5 + name_len].decode("ascii", "replace")
            elif etype == EXT_SUPPORTED_GROUPS and len(data) >= 2:
                (n,) = struct.unpack_from("!H", data, 0)
                info["groups"] = _u16_list(data[2 : 2 + n])
            elif etype == EXT_EC_POINT_FORMATS and data:
                info["point_formats"] = list(data[1 : 1 + data[0]])
            elif etype == EXT_SIGNATURE_ALGORITHMS and len(data) >= 2:
                (n,) = struct.unpack_from("!H", data, 0)
                info["sig_algs"] = _u16_list(data[2 : 2 + n])
            elif etype == EXT_ALPN and len(data) >= 2:
                i, stop = 2, 2 + struct.unpack_from("!H", data, 0)[0]
                while i < min(stop, len(data)):
                    ln = data[i]
                    info["alpn"].append(data[i + 1 : i + 1 + ln].decode("ascii", "replace"))
                    i += 1 + ln
            elif etype == EXT_SUPPORTED_VERSIONS and data:
                info["supported_versions"] = _u16_list(data[1 : 1 + data[0]])
        except (struct.error, IndexError):
            continue
    return info


def parse_server_hello(payload: bytes) -> dict | None:
    found = _handshake(payload, 0x02)
    if not found:
        return None
    buf, off, end = found
    try:
        (legacy_version,) = struct.unpack_from("!H", buf, off)
        off += 2 + 32
        sid_len = buf[off]
        off += 1 + sid_len
        (cipher,) = struct.unpack_from("!H", buf, off)
        off += 2 + 1  # cipher + compression method
        exts = _parse_extensions(buf, off, end)
    except (struct.error, IndexError):
        return None
    selected = None
    for etype, data in exts:
        if etype == EXT_SUPPORTED_VERSIONS and len(data) >= 2:
            (selected,) = struct.unpack_from("!H", data, 0)
    return {"legacy_version": legacy_version, "cipher": cipher, "extensions": [t for t, _ in exts],
            "selected_version": selected}


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------
def _no_grease(xs):
    return [x for x in xs if x not in GREASE]


def ja3_string(ch: dict) -> str:
    return ",".join([
        str(ch["legacy_version"]),
        "-".join(str(c) for c in _no_grease(ch["ciphers"])),
        "-".join(str(e) for e in _no_grease(ch["extensions"])),
        "-".join(str(g) for g in _no_grease(ch["groups"])),
        "-".join(str(p) for p in ch["point_formats"]),
    ])


def ja3(ch: dict) -> str:
    return hashlib.md5(ja3_string(ch).encode()).hexdigest()


def ja3s(sh: dict) -> str:
    s = ",".join([
        str(sh["legacy_version"]),
        str(sh["cipher"]),
        "-".join(str(e) for e in _no_grease(sh["extensions"])),
    ])
    return hashlib.md5(s.encode()).hexdigest()


def _sha12(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12] if s else "000000000000"


def ja4(ch: dict, quic: bool = False) -> str:
    versions = _no_grease(ch.get("supported_versions") or [])
    version = max(versions) if versions else ch["legacy_version"]
    ciphers = _no_grease(ch["ciphers"])
    exts = _no_grease(ch["extensions"])
    alpn = ch["alpn"][0] if ch.get("alpn") else ""
    alpn2 = (alpn[0] + alpn[-1]) if alpn else "00"
    part_a = "{}{}{}{:02d}{:02d}{}".format(
        "q" if quic else "t",
        _JA4_VERSION.get(version, "00"),
        "d" if ch.get("sni") else "i",
        min(len(ciphers), 99),
        min(len(exts), 99),
        alpn2,
    )
    part_b = _sha12(",".join(sorted(f"{c:04x}" for c in ciphers)))
    ext_str = ",".join(sorted(f"{e:04x}" for e in exts if e not in (EXT_SNI, EXT_ALPN)))
    sig = ",".join(f"{s:04x}" for s in ch.get("sig_algs") or [])
    part_c = _sha12(ext_str + ("_" + sig if sig else ""))
    return f"{part_a}_{part_b}_{part_c}"


def version_name(ch: dict | None = None, sh: dict | None = None) -> str:
    if sh and sh.get("selected_version"):
        return _VERSION_NAMES.get(sh["selected_version"], hex(sh["selected_version"]))
    if ch:
        versions = _no_grease(ch.get("supported_versions") or [])
        v = max(versions) if versions else ch["legacy_version"]
        return _VERSION_NAMES.get(v, hex(v))
    return "unknown"


def tls_metadata(ch: dict | None, sh: dict | None = None, quic: bool = False) -> dict:
    """The FlowRecord `tls` block built from parsed hellos."""
    meta: dict = {"version": version_name(ch, sh)}
    if ch:
        meta.update({
            "sni": ch.get("sni") or "",
            "alpn": (ch.get("alpn") or [""])[0],
            "ja3": ja3(ch),
            "ja4": ja4(ch, quic=quic),
            "ciphers": len(_no_grease(ch["ciphers"])),
            "exts": len(_no_grease(ch["extensions"])),
        })
    if sh:
        meta["ja3s"] = ja3s(sh)
    return meta


# ---------------------------------------------------------------------------
# Building hellos (used by the traffic lab to synthesise realistic PCAPs)
# ---------------------------------------------------------------------------
def _ext(etype: int, body: bytes) -> bytes:
    return struct.pack("!HH", etype, len(body)) + body


def build_client_hello(profile: dict, sni: str | None, rng_bytes: bytes = b"\x00" * 32) -> bytes:
    """Serialise a ClientHello from a profile dict with keys:
    version, ciphers, extensions (ordered ids), groups, point_formats, sig_algs, alpn, versions."""
    body_exts = []
    for etype in profile["extensions"]:
        if etype == EXT_SNI:
            if not sni:
                continue
            name = sni.encode()
            entry = b"\x00" + struct.pack("!H", len(name)) + name
            body_exts.append(_ext(etype, struct.pack("!H", len(entry)) + entry))
        elif etype == EXT_SUPPORTED_GROUPS:
            g = b"".join(struct.pack("!H", x) for x in profile.get("groups", []))
            body_exts.append(_ext(etype, struct.pack("!H", len(g)) + g))
        elif etype == EXT_EC_POINT_FORMATS:
            p = bytes(profile.get("point_formats", [0]))
            body_exts.append(_ext(etype, bytes([len(p)]) + p))
        elif etype == EXT_SIGNATURE_ALGORITHMS:
            s = b"".join(struct.pack("!H", x) for x in profile.get("sig_algs", []))
            body_exts.append(_ext(etype, struct.pack("!H", len(s)) + s))
        elif etype == EXT_ALPN:
            protos = profile.get("alpn") or []
            if not protos:
                continue
            lst = b"".join(bytes([len(p)]) + p.encode() for p in protos)
            body_exts.append(_ext(etype, struct.pack("!H", len(lst)) + lst))
        elif etype == EXT_SUPPORTED_VERSIONS:
            v = b"".join(struct.pack("!H", x) for x in profile.get("versions", []))
            body_exts.append(_ext(etype, bytes([len(v)]) + v))
        elif etype == 0x0033:  # key_share: one X25519 share (32 bytes)
            share = struct.pack("!HH", 0x001D, 32) + rng_bytes[:32]
            body_exts.append(_ext(etype, struct.pack("!H", len(share)) + share))
        elif etype == 0x0015:  # padding
            body_exts.append(_ext(etype, b"\x00" * 16))
        else:  # renegotiation_info carries one zero byte; everything else is sent empty
            body_exts.append(_ext(etype, b"\x00" if etype == 0xFF01 else b""))
    exts = b"".join(body_exts)
    ciphers = b"".join(struct.pack("!H", c) for c in profile["ciphers"])
    body = (
        struct.pack("!H", profile.get("version", 0x0303))
        + rng_bytes[:32].ljust(32, b"\x00")
        + b"\x20" + rng_bytes[:32].ljust(32, b"\x11")          # 32-byte session id
        + struct.pack("!H", len(ciphers)) + ciphers
        + b"\x01\x00"                                          # compression: null
        + struct.pack("!H", len(exts)) + exts
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def build_server_hello(version: int, cipher: int, extensions: list[int], selected_version: int | None,
                       rng_bytes: bytes = b"\x00" * 32) -> bytes:
    body_exts = []
    for etype in extensions:
        if etype == EXT_SUPPORTED_VERSIONS and selected_version:
            body_exts.append(_ext(etype, struct.pack("!H", selected_version)))
        elif etype == 0x0033:
            share = struct.pack("!HH", 0x001D, 32) + rng_bytes[:32]
            body_exts.append(_ext(etype, share))
        else:
            body_exts.append(_ext(etype, b"" if etype != 0xFF01 else b"\x00"))
    exts = b"".join(body_exts)
    body = (
        struct.pack("!H", version)
        + rng_bytes[:32].ljust(32, b"\x00")
        + b"\x20" + rng_bytes[:32].ljust(32, b"\x22")
        + struct.pack("!H", cipher) + b"\x00"
        + struct.pack("!H", len(exts)) + exts
    )
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def profile_hello(profile: dict, sni: str | None) -> dict:
    """The parsed-ClientHello view of a profile, as parse_client_hello() would return it
    for build_client_hello(profile, sni). Lets the traffic lab compute JA3/JA4 without
    serialising bytes."""
    exts = [e for e in profile["extensions"]
            if not (e == EXT_SNI and not sni) and not (e == EXT_ALPN and not profile.get("alpn"))]
    ch = {
        "legacy_version": profile.get("version", 0x0303),
        "ciphers": profile["ciphers"],
        "extensions": exts,
        "groups": profile.get("groups", []) if EXT_SUPPORTED_GROUPS in exts else [],
        "point_formats": profile.get("point_formats", [0]) if EXT_EC_POINT_FORMATS in exts else [],
        "sig_algs": profile.get("sig_algs", []) if EXT_SIGNATURE_ALGORITHMS in exts else [],
        "alpn": list(profile.get("alpn") or []),
        "supported_versions": profile.get("versions", []) if EXT_SUPPORTED_VERSIONS in exts else [],
        "sni": sni,
    }
    return ch
