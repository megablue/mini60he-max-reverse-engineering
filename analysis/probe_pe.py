#!/usr/bin/env python3
"""probe_pe.py - static census probe of the pinned Mini60 HE Max updater binary.

Read-only by design: the exe is opened as bytes (hash / PE header / resource
tree / strings) and never executed. Nothing here enumerates or touches HID.

    python analysis/probe_pe.py

Writes reproducible artifacts to analysis/out/ (overwrites, deterministic
except for nothing - no timestamps inside the artifacts) and prints a census
summary (also saved as out/census.txt).

Evidence discipline: the pinned SHA-256 is enforced. If bin/ no longer holds
the pinned file the script exits 1 without writing anything.

Strings counting thresholds: ASCII >= 4 printable chars, UTF-16LE >= 4 chars.
"""
from __future__ import annotations

import hashlib
import io
import math
import re
import zipfile
from collections import Counter
from pathlib import Path

import pefile

ROOT = Path(__file__).resolve().parents[1]
EXE_PATH = ROOT / "bin" / "MINI 60 HE MAX_V1.52.exe"
OUT_DIR = ROOT / "analysis" / "out"

SHA256_PIN = ("958A39951D2F908A7FE925E0FA598C321924CB235239BF37484AE7C8213512D6")

KEYWORD_RE = re.compile(
    r"sonix|isp|\bsn8|sn34|\bhid\b|hid[du]|bootloader|check.?sum|encrypt|"
    r"\bvid\b|\bpid\b|feature.?report|\bversion\b|password|firmware|"
    r"123456|user\.hex|\bhex\b|\bbin\b",
    re.IGNORECASE,
)

RT_STRING, RT_RCDATA, RT_VERSION = 6, 10, 16


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def ascii_strings(data: bytes, min_len: int = 4):
    out, cur = [], []
    for byte in data:
        if 0x20 <= byte < 0x7F:
            cur.append(chr(byte))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


def utf16_strings(data: bytes, min_len: int = 4):
    out, cur = [], []
    for i in range(0, len(data) - 1, 2):
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 0x20 <= lo < 0x7F:
            cur.append(chr(lo))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


def hexdump(data: bytes, width: int = 16, limit: int | None = None):
    lines = []
    shown = data if limit is None else data[:limit]
    for off in range(0, len(shown), width):
        chunk = shown[off : off + width]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"  {off:06X}  {hexpart:<{width * 3 - 1}}  {text}")
    if limit is not None and len(data) > limit:
        lines.append(f"  ... ({len(data) - limit} more bytes, total {len(data):#x})")
    return lines


def printable_text(data: bytes) -> str | None:
    def ok(text: str) -> str | None:
        if text and all(0x20 <= ord(c) < 0x7F or c in "\r\n\t" for c in text):
            return text
        return None

    # bare ASCII first (bytes like b'1234' would not decode as utf-16)
    try:
        head = ok(data.rstrip(b"\x00").decode("ascii"))
        if head:
            return head
    except UnicodeDecodeError:
        pass
    # else UTF-16LE, with or without a terminator
    try:
        cand = data if len(data) % 2 == 0 else data[:-1]
        return ok(cand.decode("utf-16-le").rstrip("\x00"))
    except UnicodeDecodeError:
        return None


def main() -> int:
    print(f"probe target: {EXE_PATH}")

    if not EXE_PATH.is_file():
        print(f"ERROR: expected evidence binary not found: {EXE_PATH}")
        return 1

    raw = EXE_PATH.read_bytes()
    sha = hashlib.sha256(raw).hexdigest().upper()
    print(f"size    : {len(raw)} bytes")
    print(f"sha256  : {sha}")
    if sha != SHA256_PIN:
        print("ERROR: hash does not match the evidence pin - writing nothing.")
        print(f"       pin : {SHA256_PIN}")
        return 1
    print("pin     : matches\n")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    pe = pefile.PE(data=raw)

    # --- version metadata -------------------------------------------------
    lines = []
    ffi = pe.VS_FIXEDFILEINFO[0] if getattr(pe, "VS_FIXEDFILEINFO", None) else None
    if ffi:
        ver = (
            (ffi.FileVersionMS >> 16) & 0xFFFF,
            ffi.FileVersionMS & 0xFFFF,
            (ffi.FileVersionLS >> 16) & 0xFFFF,
            ffi.FileVersionLS & 0xFFFF,
        )
        lines.append(f"VS_FIXEDFILEINFO FileVersion : {'.'.join(map(str, ver))}")
    strinfo = {}
    for fi in getattr(pe, "FileInfo", []) or []:
        for table in fi:
            for st in getattr(table, "StringTable", []):
                for k, v in st.entries.items():
                    strinfo[k.decode(errors="replace")] = v.decode(errors="replace")
    for k, v in sorted(strinfo.items()):
        lines.append(f"StringFileInfo {k:<32}: {v!r}")
    (OUT_DIR / "fileinfo.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("version metadata:")
    for line in lines:
        print(f"  {line}")

    # --- section table ----------------------------------------------------
    sec_lines = ["name      raw_off  raw_sz     vaddr     vsize       entropy"]
    for s in pe.sections:
        end = s.PointerToRawData + s.Misc_VirtualSize  # indicative only
        sec_lines.append(
            f"{s.Name.decode(errors='replace').strip('<>\\x00 '): <9}"
            f" {s.PointerToRawData:#09x} {s.SizeOfRawData:#09x}"
            f" {s.VirtualAddress:#011x} {s.Misc_VirtualSize:#011x}"
            f" {entropy(s.get_data()):.3f}"
        )
    (OUT_DIR / "sections.txt").write_text("\n".join(sec_lines) + "\n", encoding="utf-8")

    # --- imports ----------------------------------------------------------
    imp_lines = []
    ndll = 0
    nfun = 0
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        ndll += 1
        imp_lines.append(entry.dll.decode(errors="replace"))
        for imp in entry.imports:
            nfun += 1
            name = imp.name.decode(errors="replace") if imp.name else f"ord#{imp.ordinal}"
            imp_lines.append(f"    {name}")
    (OUT_DIR / "imports.txt").write_text("\n".join(imp_lines) + "\n", encoding="utf-8")

    # --- walk the resource tree ------------------------------------------
    rsrc = []  # (type_id, rid, lang_id, data)
    type_names = {RT_STRING: "RT_STRING", RT_RCDATA: "RT_RCDATA", RT_VERSION: "RT_VERSION"}
    for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for rid_entry in rtype.directory.entries:
            for lang_entry in rid_entry.directory.entries:
                d = lang_entry.data.struct
                rsrc.append(
                    (rtype.id, rid_entry.id, lang_entry.id, pe.get_data(d.OffsetToData, d.Size))
                )
    counts = Counter(type_id for type_id, *_ in rsrc)
    print("\nresource type counts:")
    for t, c in sorted(counts.items(), reverse=True):
        print(f"  {type_names.get(t, 'id ' + str(t))}: {c}")

    # --- RT_RCDATA --------------------------------------------------------
    rc = sorted((r for r in rsrc if r[0] == RT_RCDATA), key=lambda r: r[1] or 0)
    census_rc = []
    for _t, rid, _lang, data in rc:
        if rid == 4000:
            (OUT_DIR / "rcdata_4000.bin").write_bytes(data)
            head = [
                int.from_bytes(data[i : i + 4], "little") for i in range(0, 32, 4)
            ]
            census_rc.append(
                f"id {rid}: {len(data)} bytes (0x{len(data):x}) "
                f"entropy {entropy(data):.3f}  -> rcdata_4000.bin"
            )
            census_rc.append(f"  head dwords: " + " ".join(f"{w:08x}" for w in head))
            census_rc.append(
                f"  tail bytes : " + data[-16:].hex(" ")
            )
        elif rid == 4011:
            (OUT_DIR / "rcdata_4011.zip").write_bytes(data)
            zf = zipfile.ZipFile(io.BytesIO(data))
            census_rc.append(
                f"id {rid}: {len(data)} bytes (0x{len(data):x})  -> rcdata_4011.zip "
                f"(zip, testzip={'OK' if zf.testzip() is None else 'FAILED'})"
            )
            for info in zf.infolist():
                census_rc.append(
                    f"    {info.filename!r} size {info.file_size} crc {info.CRC:08x}"
                )
        else:
            (OUT_DIR / f"rcdata_{rid}.bin").write_bytes(data)
            text = printable_text(data)
            desc = f" {text!r}" if text is not None else ""
            census_rc.append(
                f"id {rid}: {len(data)} bytes (0x{len(data):x}){desc}"
                f"  -> rcdata_{rid}.bin"
            )
    total = sum(len(r[3]) for r in rc)
    census_rc.append(f"RT_RCDATA total: {len(rc)} entries, {total} bytes")
    print("\nRT_RCDATA:")
    for line in census_rc:
        print("  " + line)

    # --- RT_STRING --------------------------------------------------------
    ts = sorted((r for r in rsrc if r[0] == RT_STRING), key=lambda r: r[1] or 0)
    tstr = []
    unique_all = set()
    for _t, rid, _lang, data in ts:
        text = data.decode("utf-16-le", errors="replace")
        parts = [p for p in text.split("\x00") if p]
        unique_all.update(parts)
        tstr.append(f"table {rid}: {len(parts)} strings")
        for i, p in enumerate(parts):
            tstr.append(f"  [{(rid - 1) * 16 + i}] {p!r}")
    print(f"\nRT_STRING: {len(ts)} tables, {len(unique_all)} unique strings")
    (OUT_DIR / "rt_string.txt").write_text("\n".join(tstr) + "\n", encoding="utf-8")

    # --- RT_VERSION -------------------------------------------------------
    vt = [r for r in rsrc if r[0] == RT_VERSION]
    (OUT_DIR / "rt_version.txt").write_text(
        "\n".join(
            f"table {rid}: {len(data)} bytes{'' if not printable_text(data) else ' ' + printable_text(data)!r}"
            for _t, rid, _lang, data in vt
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"RT_VERSION: {len(vt)} entries")
    print(f"imports   : {ndll} DLLs, {nfun} functions")

    # --- strings ----------------------------------------------------------
    a_str = ascii_strings(raw)
    u_str = utf16_strings(raw)
    (OUT_DIR / "strings_ascii.txt").write_text("\n".join(a_str) + "\n", encoding="utf-8")
    (OUT_DIR / "strings_utf16.txt").write_text("\n".join(u_str) + "\n", encoding="utf-8")
    all_by_text = {}
    for s in set(a_str) | set(u_str):
        all_by_text[s] = 0
    for s in a_str:
        all_by_text[s] += 1
    for s in u_str:
        all_by_text[s] += 1
    hits = sorted(s for s in all_by_text if KEYWORD_RE.search(s))
    (OUT_DIR / "strings_sonix_isp.txt").write_text("\n".join(hits) + "\n", encoding="utf-8")
    print(f"strings   : {len(a_str)} ascii, {len(u_str)} utf16, {len(hits)} keyword hits")

    # --- security directory / overlay ------------------------------------
    sd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
    cert_note = []
    if sd.VirtualAddress and sd.Size:
        cert = raw[sd.VirtualAddress : sd.VirtualAddress + sd.Size]
        (OUT_DIR / "cert_pkcs7.bin").write_bytes(cert)
        cert_note.append(
            f"security dir: offset {sd.VirtualAddress:#x} size {sd.Size:#x}"
            f"  -> cert_pkcs7.bin"
        )
    end_raw = max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections)
    overlay = raw[end_raw:]
    cert_note.append(f"overlay    : start {end_raw:#x} size {len(overlay):#x}")
    if end_raw == sd.VirtualAddress and len(overlay) == sd.Size:
        cert_note.append("  -> overlay == security directory (Authenticode)")
    if end_raw + len(overlay) == len(raw):
        cert_note.append("  -> overlay ends the file exactly")
    print("\noverlay/certificate:")
    for line in cert_note:
        print("  " + line)

    # ------------------------------------------------------------------
    census = [
        f"target  : {EXE_PATH.name}",
        f"size    : {len(raw)} bytes",
        f"sha256  : {sha}  (pin match: {sha == SHA256_PIN})",
        "",
        "version metadata:",
        *[f"  {l}" for l in lines],
        "",
        "sections:",
        *sec_lines,
        "",
        f"imports : {ndll} DLLs, {nfun} functions -> imports.txt",
        f"RT_RCDATA: {len(rc)} entries, {total} bytes",
        *[f"  {l}" for l in census_rc],
        f"RT_STRING: {len(ts)} tables -> rt_string.txt",
        f"RT_VERSION: {len(vt)} entries -> rt_version.txt",
        f"strings : {len(a_str)} ascii, {len(u_str)} utf16,",
        f"          {len(hits)} keyword hits -> strings_sonix_isp.txt",
        "",
        "overlay/certificate:",
        *cert_note,
        "",
        "artifacts in analysis/out/:",
        *[f"  {p.name}" for p in sorted(OUT_DIR.glob('*'))],
    ]
    (OUT_DIR / "census.txt").write_text("\n".join(census) + "\n", encoding="utf-8")
    print("\nartifacts written to", OUT_DIR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
