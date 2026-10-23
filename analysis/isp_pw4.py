#!/usr/bin/env python3
"""isp_pw4.py - password-payload semantics, probe 4: the flow top-level.

  T1  fn 0x401100 whole (calls 0x4039C0 twice)
  T2  fn 0x401600 whole (calls 0x4024D0 twice + 0x4039C0 once)
  T3  fn 0x401FE0 whole (calls 0x4024D0)
  T4  fn 0x404420 whole (calls 0x4039C0)

Read-only: the pinned exe is opened as bytes (SHA-256 enforced). Never
executed; no HID device touched -- static bytes only.

    python analysis/isp_pw4.py           # full report -> out/isp_pw4.txt

Artifact: analysis/out/isp_pw4.txt
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import capstone
import pefile

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "bin" / "MINI 60 HE MAX_V1.52.exe"
OUT = ROOT / "analysis" / "out"
REPORT = OUT / "isp_pw4.txt"

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


def next_fn_start(site: int) -> int:
    for va in fn_starts:
        if va >= site:
            return va
    return site + 0x100


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


for fn, tag in ((0x401100, "upload dispatcher"),
                (0x401600, "erase/other dispatcher"),
                (0x401FE0, "fn 0x401FE0"),
                (0x404420, "fn 0x404420")):
    out(f"")
    out(f"{'=' * 64}")
    out(f"= {hx(fn)} whole ({tag}); ends {hx(next_fn_start(fn + 1))}")
    out(f"{'=' * 64}")
    dump(fn, next_fn_start(fn + 1), f"{hx(fn)} whole ({tag})")

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"report: {len(lines)} lines -> {REPORT.name}")
