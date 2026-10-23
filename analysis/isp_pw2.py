#!/usr/bin/env python3
"""isp_pw2.py - password-payload semantics, probe 2.

  P1  fn 0x427120 (the one RCDATA-4007 consumer) in full
  P2  every call site of SHLWAPI!StrToInt64ExW / StrToIntExW with context
      (wide-string -> integer conversion of the pw resource?)
  P3  pointer hunt across .rdata/.data for the 0x5B1D50..0x5B1D90 zone
      (object whose member 0x5B1D6C is written via a register base)
  P4  raw .rdata window 0x588910 (static pointer .data 0x5B1D70 -> 0x588910)
      and .data window at 0x5B23BF
  P5  fn 0x40B740 gate tail in full (0x40B7F0..0x40B940), untruncated
  P6  FAFAFAFA census in the file

Read-only: the pinned exe is opened as bytes (SHA-256 enforced). Never
executed; no HID device touched -- static bytes only.

    python analysis/isp_pw2.py           # full report -> out/isp_pw2.txt

Artifact: analysis/out/isp_pw2.txt
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
REPORT = OUT / "isp_pw2.txt"

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

TEXT_SEC = next(s for s in pe.sections
                if s.Name.rstrip(b"\x00") == b".text")
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
            r = n0 + 1  # no progress without an exception -> force move
    out("--- end range ---")


def call_iat_sites(iat_va: int) -> list[int]:
    pat = b"\xff\x15" + struct.pack("<I", iat_va)
    found = []
    for i in range(len(text) - 6):
        if text[i:i + 6] == pat:
            found.append(text_va0 + i)
    return sorted(found)


# ============================================================ P1 fn 0x427120
out("")
out("================================================================ P1")
out("= P1 fn 0x427120 whole (RCDATA 4007 site at 0x427350)")
out("================================================================")
dump(0x427120, 0x4274A0, "fn 0x427120 whole")

# ================================================ P2 StrToInt conversion sites
out("")
out("================================================================ P2")
out("= P2 SHLWAPI StrToInt* call sites with wide context")
out("================================================================")
for va, nm in sorted(iat_by_va.items(), key=lambda kv: kv[1]):
    if "StrToInt" in nm:
        out(f"IAT {hx(va)} = {nm}")
for va, nm in sorted(iat_by_va.items(), key=lambda kv: kv[1]):
    if "StrToInt" in nm:
        for s in call_iat_sites(va):
            out(f"call site {hx(s)} of {nm} in fn {hx(containing_fn(s))}")
            dump(max(text_va0, s - 0xB0), s + 0x30, f"context of {nm} @ {hx(s)}")

# LoadResource/LockResource chains near proven conversions? Print all call sites.
out("-- LoadResource / LockResource / SizeofResource call sites --")
for va, nm in sorted(iat_by_va.items(), key=lambda kv: kv[1]):
    if any(k in nm for k in ("LoadResource", "LockResource", "SizeofResource")):
        for s in call_iat_sites(va):
            out(f"{nm} @ {hx(s)} in fn {hx(containing_fn(s))}")

# ======================================== P3 pointer hunt across non-.text secs
out("")
out("================================================================ P3")
out("= P3 pointer/data references of zone 0x5B1D50..0x5B1D90 outside .text")
out("================================================================")
LO, HI = 0x5B1D50, 0x5B1D90
for off0, off1, va0, va1, name in ranges:
    if name == ".text":
        continue
    blob = raw[off0:off1]
    for i in range(len(blob) - 4):
        v = int.from_bytes(blob[i:i + 4], "little")
        if LO <= v < HI and v % 4 == 0:
            site = va0 + i
            out(f"value {hx(v)} at {hx(site)} ({name}); context:")
            ctx = blob[max(0, i - 0x20):i + 0x24]
            s0 = va0 + max(0, i - 0x20)
            for k in range(0, len(ctx), 16):
                row = ctx[k:k + 16]
                hexs = " ".join(f"{b:02x}" for b in row)
                asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row)
                out(f"  {s0 + k:08X}  {hexs:<48s} |{asc}|")

# ============================================== P4 pointer targets' own windows
out("")
out("================================================================ P4")
out("= P4 .rdata window at 0x588910 and .data window at 0x5B23BF")
out("================================================================")
for va, span, tag in ((0x588910, 0x60, ".rdata ptr target"), (0x5B23BF, 0x30, ".data ref site")):
    for off0, off1, va0, va1, name in ranges:
        if va0 <= va < va1:
            rel = va - va0
            chunk = raw[off0 + rel - 0x10:off0 + rel + span]
            for k in range(0, len(chunk), 16):
                row = chunk[k:k + 16]
                hexs = " ".join(f"{b:02x}" for b in row)
                asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row)
                out(f"{va - 0x10 + k:08X}  {hexs:<48s} |{asc}|  ({tag}/{name})")

# ============================================== P5 pw-frame gate tail, uncut
out("")
out("================================================================ P5")
out("= P5 fn 0x40B740 gate tail (0x40B7F0..0x40B940) and fn 0x40B860 zone")
out("================================================================")
dump(0x40B7F0, 0x40B940, "pw short-frame gate tail uncut")

# ============================================================ P6 FAFAFAFA
out("")
out("================================================================ P6")
out("= P6 0xFAFAFAFA census")
out("================================================================")
pat = b"\xfa\xfa\xfa\xfa"
count = 0
for off0, off1, va0, va1, name in ranges:
    blob = raw[off0:off1]
    start = 0
    while True:
        j = blob.find(pat, start)
        if j < 0:
            break
        count += 1
        if name == ".data":
            out(f"0xFAFAFAFA at {hx(va0 + j)} ({name})")
        start = j + 1
out(f"total: {count} occurrences (only .data listed)")

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"report: {len(lines)} lines -> {REPORT.name}")
