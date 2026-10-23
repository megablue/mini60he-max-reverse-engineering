#!/usr/bin/env python3
"""isp_pw3.py - password-payload semantics, probe 3: the app-dialog post-processor.

  S1  fn 0x426250 whole (called at 0x4273ED with ecx=esi, right after the
      small RCDATA resources were assigned into the dialog object)
  S2  fn 0x420230 whole (the LoadRCDATA-as-CString helper used at 0x42735B)
  S3  who writes dialog member +0x1c-style pw pointers: scan .text for
      'mov [reg+0x1c], ' stores inside fns that reference 0x5b1d6c-readers'
      caller set (0x4024D0..0x4039C0 flow family heads)
  S4  callers of fn 0x426250 and fn 0x427120 (who drives the dialog loader)

Read-only: the pinned exe is opened as bytes (SHA-256 enforced). Never
executed; no HID device touched -- static bytes only.

    python analysis/isp_pw3.py           # full report -> out/isp_pw3.txt

Artifact: analysis/out/isp_pw3.txt
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
OUT = ROOT / "analysis" / "out"
REPORT = OUT / "isp_pw3.txt"

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

str_by_va: dict[int, str] = {}


def harvest_str(blob: bytes, off0: int, va0: int, wide: bool):
    step = 2 if wide else 1
    i = 0
    n = len(blob)
    while i + step <= n:
        b = blob[i:i + step][0]
        if 0x20 <= b < 0x7F:
            j, chars = i, []
            while j + step <= n:
                b2 = blob[j:j + step][0]
                if not (0x20 <= b2 < 0x7F):
                    break
                chars.append(chr(b2))
                j += step
            s = "".join(chars)
            if len(s) >= 4:
                str_by_va[va0 + i] = s
            i = j + step
        else:
            i += step


for off0, off1, va0, va1, name in ranges:
    blob = raw[off0:off1]
    harvest_str(blob, off0, va0, wide=True)
    harvest_str(blob, off0, va0, wide=False)

iat_by_va: dict[int, str] = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode("latin-1")
    for imp in entry.imports:
        if imp.address and imp.name:
            iat_by_va[imp.address] = f"{dll}!{imp.name.decode('latin-1')}"

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


def next_fn_start(site: int) -> int:
    """Start of the function beginning at or after the byte offset `site - text_va0`."""
    i0 = site - text_va0
    for va in fn_starts:
        if va >= site:
            return va
    return site + 0x100


def fn_end(fn: int) -> int:
    return next_fn_start(fn + 1)


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
                notes = []
                for tok in re.findall(r"0x[0-9a-fA-F]+", insn.op_str):
                    v = int(tok, 16)
                    if v in str_by_va:
                        notes.append(f"STR:{str_by_va[v]!r}")
                    if v in iat_by_va:
                        notes.append(f"IMP:{iat_by_va[v]}")
                b = insn.bytes.hex()
                out(f"{insn.address:08X}  {b:<22s} {insn.mnemonic:8s} "
                    f"{insn.op_str}{'   ; ' + ' '.join(notes) if notes else ''}")
                r = (insn.address - va0) + insn.size
                break
        except Exception as e:  # noqa: BLE001
            out(f"disasm error at {hx(va0 + r)}: {e}")
            break
        if r <= n0:
            r = n0 + 1
    out("--- end range ---")


def call_sites(target: int) -> list[int]:
    found = []
    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            rel = int.from_bytes(text[i + 1:i + 5], "little", signed=True)
            va = text_va0 + i
            if va + 5 + rel == target:
                found.append(va)
    return sorted(found)


# ================================================================== S1 0x426250
out("")
out("================================================================ S1")
out("= S1 fn 0x426250 whole (dialog post-processor)")
out("================================================================")
dump(0x426250, fn_end(0x426250), "fn 0x426250 whole")

# ================================================================== S2 0x420230
out("")
out("================================================================ S2")
out("= S2 fn 0x420230 whole (LoadRCDATA-as-CString helper)")
out("================================================================")
dump(0x420230, fn_end(0x420230), "fn 0x420230 whole")

# ===================================================== S3 pw-pointer provenance
out("")
out("================================================================ S3")
out("= S3 who fills the flow objects' pw field (+0x1c)?")
out("================================================================")
out("callers of 0x4024D0 (the flow wrapper that reads [ecx+0x1c]):")
for s in call_sites(0x4024D0):
    out(f"  {hx(s)} in fn {hx(containing_fn(s))}")
out("callers of 0x4039C0 (the upload flow):")
for s in call_sites(0x4039C0):
    out(f"  {hx(s)} in fn {hx(containing_fn(s))}")
out("callers of 0x40B740 (short pw frame):")
for s in call_sites(0x40B740):
    out(f"  {hx(s)} in fn {hx(containing_fn(s))}")
out("callers of 0x427120 (dialog resource loader):")
for s in call_sites(0x427120):
    out(f"  {hx(s)} in fn {hx(containing_fn(s))}")
out("callers of 0x426250:")
for s in call_sites(0x426250):
    out(f"  {hx(s)} in fn {hx(containing_fn(s))}")
out("callers of 0x407CA0 (codeoption erase, long-pw path):")
for s in call_sites(0x407CA0):
    out(f"  {hx(s)} in fn {hx(containing_fn(s))}")

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"report: {len(lines)} lines -> {REPORT.name}")
