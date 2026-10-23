#!/usr/bin/env python3
"""isp_pw6.py - password semantics, probe 6: device-side + long-frame + wider sweep.

  V1  DEVICE-SIDE cross-check: search the embedded firmware image
      (analysis/out/rcdata_4000.bin) for the candidate pw constants:
      0x34333231 ('1234' ascii LE), 0x00320031 (utf16 '12' LE), 0x00BC614E
      (dec 12345678), 0x12345678 (hex), 0xFAFAFAFA, and the byte runs
      b'1234', r'1\\x002\\x00' -- the device's ISP-password verify constant
      is one of these, and matching it settles the wire payload semantics.
  V2  fn 0x40BAC0 (long 64-byte pw form) head+body 0x40BAC0..0x40BBC0:
      which frame indexes carry password bytes.
  V3  aligned re-sweep: every 4-aligned .text dword in 0x5B1C00..0x5B2200,
      with instruction classification and containing fn, to find any writer
      or base-pointer of the 0x5B1D6C neighborhood.

Read-only: pinned exe + extracted firmware image opened as bytes. Never
executed; no HID device touched.

    python analysis/isp_pw6.py           # full report -> out/isp_pw6.txt

Artifact: analysis/out/isp_pw6.txt
"""
from __future__ import annotations

import hashlib
import re
import struct
from pathlib import Path

import capstone
import pefile

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "bin" / "MINI 60 HE MAX_V1.52.exe"
FW = ROOT / "analysis" / "out" / "rcdata_4000.bin"
OUT = ROOT / "analysis" / "out"
REPORT = OUT / "isp_pw6.txt"

SHA256_PIN = "958A39951D2F908A7FE925E0FA598C321924CB235239BF37484AE7C8213512D6"

lines: list[str] = []


def out(*a):
    lines.append(" ".join(str(x) for x in a))


def hx(v: int) -> str:
    return f"0x{v:X}"


raw = EXE.read_bytes()
sha = hashlib.sha256(raw).hexdigest()
if sha.upper() != SHA256_PIN:
    raise SystemExit(f"pin mismatch: {sha}; refusing to analyze")
pe = pefile.PE(data=raw)
base = pe.OPTIONAL_HEADER.ImageBase

ranges = []
for sec in pe.sections:
    name = sec.Name.rstrip(b"\x00").decode("latin-1")
    ranges.append((sec.PointerToRawData, sec.PointerToRawData + sec.SizeOfRawData,
                   base + sec.VirtualAddress,
                   base + sec.VirtualAddress + sec.SizeOfRawData, name))

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = False
md.skipdata = True

TEXT_SEC = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
text = raw[TEXT_SEC.PointerToRawData:TEXT_SEC.PointerToRawData + TEXT_SEC.SizeOfRawData]
text_va0 = base + TEXT_SEC.VirtualAddress

fn_starts = sorted({text_va0 + i for pat in (b"\x8b\xff\x55\x8b\xec", b"\x55\x8b\xec")
                    for i in range(len(text) - len(pat)) if text[i:i + len(pat)] == pat})
run = 0
for i, b in enumerate(text):
    if b == 0xCC:
        run += 1
    else:
        if run >= 4 and i < len(text):
            fn_starts.append(text_va0 + i)
        run = 0
fn_starts = sorted(set(fn_starts))


def containing_fn(site: int):
    lo, hi = 0, len(fn_starts) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if fn_starts[mid] <= site:
            best = fn_starts[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return best


def va_bytes(va):
    for off0, off1, va0, va1, name in ranges:
        if va0 <= va < va1:
            return raw[off0:off1], va - va0, name
    return None, None, None


def dump(start: int, stop: int, title: str):
    out(f"--- range {hx(start)}..{hx(stop)}  {title} ---")
    blob, sect_off, secn = va_bytes(start)
    va0 = None
    for off0, off1, va_a, va_b, name in ranges:
        if name == secn:
            va0 = va_a
    r = sect_off
    stop_rel = sect_off + (stop - start)
    while r < stop_rel:
        n0 = r
        try:
            for insn in md.disasm(blob[r:stop_rel], va0 + r):
                b = insn.bytes.hex()
                out(f"{insn.address:08X}  {b:<22s} {insn.mnemonic:8s} {insn.op_str}")
                r = (insn.address - va0) + insn.size
                break
        except Exception as e:  # noqa: BLE001
            out(f"disasm error at {hx(va0 + r)}: {e}")
            break
        if r <= n0:
            r = n0 + 1
    out("--- end range ---")


# =============================================================== V1 device side
out("")
out("================================================================ V1")
out("= V1 firmware-image cross-check of password constants")
out("================================================================")
fw = FW.read_bytes()
out(f"firmware image: {len(fw)} bytes")

cases = {
    "dword 0x34333231 (ascii '1234' LE)": struct.pack("<I", 0x34333231),
    "dword 0x31323334 (ascii '1234' BE)": struct.pack("<I", 0x31323334),
    "dword 0x00320031 (utf16 '12' LE)":   struct.pack("<I", 0x00320031),
    "dword 0x00BC614E (dec 12345678)":    struct.pack("<I", 12345678),
    "dword 0x12345678 (hex 12345678)":    struct.pack("<I", 0x12345678),
    "dword 0xFAFAFAFA (tool's init)":     b"\xfa\xfa\xfa\xfa",
    "bytes b'1234'":                      b"1234",
    "utf16 b'1\\x002\\x003\\x00'":         "12345678".encode("utf-16-le")[:6],
}
for label, pat in cases.items():
    hits = []
    start = 0
    while True:
        j = fw.find(pat, start)
        if j < 0:
            break
        hits.append(j)
        start = j + 1
    out(f"{label}: {len(hits)} hits "
        + (", ".join(f"@fw 0x{j:X}" for j in hits[:20]) if hits else "(none)"))

# =============================================================== V2 long frame
out("")
out("================================================================ V2")
out("= V2 fn 0x40BAC0 (long 64B pw form) 0x40BAC0..0x40BBC0")
out("================================================================")
dump(0x40BAC0, 0x40BBC0, "long pw form body")

# =============================================================== V3 wide sweep
out("")
out("================================================================ V3")
out("= V3 aligned .text dwords in 0x5B1C00..0x5B2200 (all, classified)")
out("================================================================")
LO, HI = 0x5B1C00, 0x5B2200
found = {}
for i in range(0, len(text) - 4):
    va = text_va0 + i
    if va % 4:
        continue
    v = int.from_bytes(text[i:i + 4], "little")
    if LO <= v < HI:
        found.setdefault(v, []).append(va)
out(f"{sum(len(v) for v in found.values())} aligned sites, {len(found)} distinct addrs")
for v in sorted(found):
    for site in found[v]:
        fn = containing_fn(site)
        win0 = site - 8
        blob, sect_off, secn = va_bytes(win0)
        va0 = None
        for off0, off1, va_a, va_b, name in ranges:
            if name == secn:
                va0 = va_a
        txts = []
        r = sect_off
        stop_rel = sect_off + 40
        chosen = None
        while r < stop_rel:
            n0 = r
            try:
                for insn in md.disasm(blob[r:stop_rel], va0 + r):
                    lo_i = va0 + r
                    txts.append((lo_i, f"{insn.mnemonic} {insn.op_str}",
                                 lo_i <= site < lo_i + insn.size))
                    if chosen is None or txts[-1][2]:
                        if txts[-1][2]:
                            chosen = len(txts) - 1
                    r = sect_off + (lo_i - va0) + insn.size
                    break
            except Exception:  # noqa: BLE001
                r += 1
            if r <= n0:
                r = n0 + 1
            if chosen is not None and len(txts) > 3:
                break
        sel = " | ".join((">> " if c else "   ") + t for _, t, c in txts[:4])
        out(f"{hx(site)} ({hx(fn)}): {sel}")

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"report: {len(lines)} lines -> {REPORT.name}")
