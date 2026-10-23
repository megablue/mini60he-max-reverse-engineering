#!/usr/bin/env python3
"""isp_pw5.py - password-payload semantics, probe 5: fn 0x4039C0 head + record +0x1c.

  U1  fn 0x4039C0 head 0x4039C0..0x403B00 (where the flow object fields incl.
      +0x1c are read/stored before the pw frame call at 0x403A19)
  U2  fn 0x4024D0 whole head 0x4024D0..0x402560 for the same reason
  U3  chip-record zone: raw .data dump around the record array base 0x5A9AD0,
      first 3 records (stride 0x33), plus refs pattern 'imul eax,eax,0x33'
      census (every site)
  U4  RCDATA 4007 byte tail check: is the resource exactly ASCII or UTF-16?
      (verify rcdata_4007.bin extraction & reinterpret)

Read-only: the pinned exe is opened as bytes (SHA-256 enforced).

    python analysis/isp_pw5.py           # full report -> out/isp_pw5.txt

Artifact: analysis/out/isp_pw5.txt
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
REPORT = OUT / "isp_pw5.txt"

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


# =============================================================== U1/U2 disasm
out("")
out("================================================================ U1")
out("= U1 fn 0x4039C0 head .. 0x403B00")
out("================================================================")
dump(0x4039C0, 0x403B00, "fn 0x4039C0 head")

out("")
out("================================================================ U2")
out("= U2 fn 0x4024D0 head .. 0x402620")
out("================================================================")
dump(0x4024D0, 0x402620, "fn 0x4024D0 head")

# =============================================================== U3 records
out("")
out("================================================================ U3")
out("= U3 .data record array base 0x5A9AD0, first 4 records of stride 0x33")
out("================================================================")
for off0, off1, va0, va1, name in ranges:
    if va0 <= 0x5A9AD0 < va1:
        rel = 0x5A9AD0 - va0
        span = 0x33 * 6
        for k in range(0, span, 16):
            row = raw[off0 + rel + k:off0 + rel + k + 16]
            va = 0x5A9AD0 + k
            hexs = " ".join(f"{b:02x}" for b in row)
            asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row)
            out(f"{va:08X}  {hexs:<48s} |{asc}|")

out("")
out("imul ...,0x33 census (stride 0x33 users):")
out("byte pattern 6b c0 33 / 6b c9 33 / 6b cb 33 / 6b d2 33 etc.:")
for i in range(len(text) - 3):
    if text[i] == 0x6B and text[i + 2] == 0x33:
        out(f"  0x{hex(text_va0 + i)[2:]}: imul {hex(text[i+1])[2:]}, 0x33")

# =============================================================== U4 resource
out("")
out("================================================================ U4")
out("= U4 rcdata_4007.bin exact bytes")
out("================================================================")
p = ROOT / "analysis" / "out" / "rcdata_4007.bin"
if p.exists():
    b = p.read_bytes()
    out(f"len={len(b)}")
    out(b.hex(" "))
    out(repr(b))
    # the corresponding resource raw bytes straight from .rsrc
simpw = b"372f68c7"
out("(derived dwords: ascii '1234' LE=0x34333231; utf16 '12' LE=0x00320031; "
    "StrToInt64 base10=0x00BC614E; StrToInt64 hex mode=0x12345678)")

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"report: {len(lines)} lines -> {REPORT.name}")
