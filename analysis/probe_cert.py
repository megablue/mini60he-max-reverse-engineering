"""Parse the Authenticode overlay's PKCS#7 blob as data (never executes the exe).

The overlay (analysis/out/cert_pkcs7.bin) is the PE security directory. This
script walks it with a minimal DER reader -- no crypto library -- and prints
every certificate with SHA-1 thumbprint, subject/issuer, validity, serial and
the EV policy OIDs it carries. Regenerable: python analysis/probe_cert.py
Writes analysis/out/cert_info.txt.
"""
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
BLOB = ROOT / "out" / "cert_pkcs7.bin"
OUT = ROOT / "out" / "cert_info.txt"

OIDS = {
    "2.5.4.3": "CN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
}

STRING_TAGS = {0x0C, 0x13, 0x14, 0x16, 0x1E}


def tlv(b, off):
    """Return (tag, value_start, end) for the DER element at off."""
    if off + 2 > len(b):
        raise ValueError("truncated tag")
    tag = b[off]
    l = b[off + 1]
    off += 2
    if l & 0x80:
        n = l & 0x7F
        if n == 0 or off + n > len(b):
            raise ValueError("bad length")
        l = int.from_bytes(b[off:off + n], "big")
        off += n
    end = off + l
    if end > len(b):
        raise ValueError("length past end")
    return tag, off, end


def children(b, start, end):
    out = []
    off = start
    while off < end:
        tag, vs, ve = tlv(b, off)
        out.append((tag, off, vs, ve))
        off = ve
    return out


def decode_oid(b, start, end):
    if start >= end:
        return "?"
    first = b[start]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for byte in b[start + 1:end]:
        val = (val << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def decode_name(b, start, end):
    """Name ::= SEQUENCE OF SET OF SEQUENCE { type OID, value ANY }."""
    fields = []
    for _tag, _o, s, e in children(b, start, end):
        for _t2, _o2, s2, e2 in children(b, s, e):
            oid_tag, oid_s, oid_e = tlv(b, s2)
            if oid_tag != 0x06:
                continue
            oid = decode_oid(b, oid_s, oid_e)
            vtag, vs, ve = tlv(b, oid_e)
            if vtag in STRING_TAGS:
                text = b[vs:ve].decode("utf-16-be" if vtag == 0x1E else "utf-8", "replace")
            else:
                text = b[vs:ve].hex()
            fields.append((OIDS.get(oid, oid), text))
    return fields


def collect_oids(b, off, end, depth=0, out=None):
    """Every OID string under a node, descending constructed tags and OCTET STRINGs."""
    if out is None:
        out = []
    if depth > 14:
        return out
    try:
        kids = children(b, off, end)
    except ValueError:
        return out
    for tag, _start, vs, ve in kids:
        if tag == 0x06:
            out.append(decode_oid(b, vs, ve))
        elif tag in (0x30, 0x31, 0x04) or 0xA0 <= tag <= 0xA3:
            collect_oids(b, vs, ve, depth + 1, out)
    return out


def scan_certificates(b):
    """Every offset where a node is shaped like X.509 Certificate.

    A byte scan is used instead of a container walk because Timestamp Tokens
    travel as an OCTET STRING whose payload may carry padding, and because a
    certificate is recognisable on its own: SEQ { tbs SEQ, alg SEQ, sig BIT
    STRING } that parses exactly and ends at its own length.
    """
    out = []
    i = 0
    while i < len(b) - 4:
        if b[i] == 0x30:
            try:
                _tag, vs, ve = tlv(b, i)
                kids = children(b, vs, ve)
            except ValueError:
                i += 1
                continue
            if len(kids) == 3 and kids[0][0] == 0x30 and kids[1][0] == 0x30 and kids[2][0] == 0x03:
                out.append((kids[0][1], ve))
                i = ve
                continue
        i += 1
    return out


def describe(b, tbs_start, cert_end):
    cert = b[tbs_start:cert_end]
    tbs = children(b, tbs_start, cert_end)[0]
    f = children(b, tbs[2], tbs[3])
    i = 0
    if f and f[0][0] == 0xA0:  # [0] EXPLICIT version
        i = 1
    serial = b[f[i][2]:f[i][3]].hex()
    i += 2  # skip serial + signature algorithm
    issuer = decode_name(b, f[i][2], f[i][3])
    i += 1
    validity = children(b, f[i][2], f[i][3])
    i += 1
    subject = decode_name(b, f[i][2], f[i][3])
    policies = [
        oid for oid in collect_oids(b, tbs_start, cert_end)
        if oid.startswith("2.23.140") or oid.startswith("1.3.6.1.4.1.311.60.2.1.3")
    ]
    return {
        "thumb_sha1": hashlib.sha1(cert).hexdigest().upper(),
        "serial": serial,
        "issuer": issuer,
        "subject": subject,
        "not_before": b[validity[0][2]:validity[0][3]].decode("ascii", "replace"),
        "not_after": b[validity[1][2]:validity[1][3]].decode("ascii", "replace"),
        "policies": policies,
        "sha256": hashlib.sha256(cert).hexdigest().upper(),
    }


def pkcs7_offset(b):
    """The overlay carries a WIN_CERTIFICATE header before the PKCS#7 SEQUENCE.

    dwLength(4) wRevision(2) wCertificateType(2) then DER. Prefer the offset at
    which a top-level SEQUENCE covers the rest of the blob.
    """
    for off in (0, 8):
        try:
            tag, _vs, end = tlv(b, off)
        except ValueError:
            continue
        if tag == 0x30 and 0 < end <= len(b) and end >= len(b) - 16:
            return off
    raise ValueError("no PKCS#7 SEQUENCE found")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    b = BLOB.read_bytes()
    start = pkcs7_offset(b)
    _tag, body_start, body_end = tlv(b, start)
    lines = [
        f"blob: {BLOB.relative_to(ROOT.parent)} size={len(b)} bytes "
        f"sha256={hashlib.sha256(b).hexdigest().upper()}",
        f"pkcs7 DER starts at overlay offset {start:#x} (WIN_CERTIFICATE header {start} bytes)",
    ]
    seen = set()
    for tbs_start, cert_end in scan_certificates(b):
        key = (tbs_start, cert_end)
        if key in seen:
            continue
        seen.add(key)
        info = describe(b, tbs_start, cert_end)
        lines.append("")
        lines.append(f"cert @ {tbs_start:#x}..{cert_end:#x}")
        lines.append(f"  thumbprint sha1 : {info['thumb_sha1']}")
        lines.append(f"  sha256          : {info['sha256']}")
        lines.append(f"  serial          : {info['serial']}")
        lines.append(f"  notBefore       : {info['not_before']}")
        lines.append(f"  notAfter        : {info['not_after']}")
        lines.append(f"  policies        : {', '.join(info['policies']) or '(none in the 2.23.140 / jurisdiction arcs)'}")
        for label, name in (("subject", info["subject"]), ("issuer", info["issuer"])):
            lines.append(f"  {label}:")
            for k, v in name:
                lines.append(f"    {k} = {v}")
    stamps = generalized_times(b)
    if stamps:
        lines.append("")
        lines.append("DER GeneralizedTime values (RFC 3161 genTime candidates):")
        for off, stamp in stamps:
            lines.append(f"  {off:#x}: {stamp}")
    text = "\n".join(lines) + "\n"
    OUT.write_text(text, encoding="utf-8")
    sys.stdout.write(text)


def generalized_times(b):
    """Every DER GeneralizedTime (tag 0x18) with a 15-digit UTC stamp, e.g. RFC 3161 genTime."""
    out = []
    i = 0
    while True:
        j = b.find(b"\x18\x0f", i)
        if j < 0:
            return out
        stamp = b[j + 2:j + 17]
        if stamp.endswith(b"Z") and stamp[:14].isdigit():
            out.append((j, stamp.decode("ascii")))
        i = j + 1


if __name__ == "__main__":
    main()
