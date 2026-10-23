#!/usr/bin/env python3
"""isp_pw7.py - password semantics, probe 7: dialog init wiring.

  Z1  fn 0x427660 whole (sole caller of 0x427120): look for the store of the
      pw pointer into the controller object member +0x1c, and for any
      StrToInt conversion of the pw CString.
  Z2  .text-wide X-hunt: all capstone instructions whose memory operand has
      displacement == 0xEC on a base register (references of the pw CString
      at dialog+0xEC) and displacement == 0x1C stores near [+0x14] stores
      (controller ctor pattern), to find the writer of controller+0x1c.

Read-only: the pinned exe is opened as bytes (SHA-256 enforced). Never
executed; no HID device touched.

    python analysis/isp_pw7.py           # full report -> out/isp_pw7.txt

Artifact: analysis/out/isp_pw7.txt
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
REPORT = OUT / "isp_pw7.txt"

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

import capstone

md64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md64.detail = True  # we need operands

ranges = []
for sec in pe.sections:
    name = sec.Name.rstrip(b"\x00").decode("latin-1")
    ranges.append((sec.PointerToRawData, sec.PointerToRawData + sec.SizeOfRawData,
                   base + sec.VirtualAddress,
                   base + sec.VirtualAddress + sec.SizeOfRawData, name))

TEXT_SEC = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
text = raw[TEXT_SEC.PointerToRawData:TEXT_SEC.PointerToRawData + TEXT_SEC.SizeOfRawData]
text_va0 = base + TEXT_SEC.VirtualAddress

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
            for insn in md64.disasm(blob[r:stop_rel], va0 + r):
                notes = []
                for tok in re.findall(r"0x[0-9a-fA-F]+", insn.op_str):
                    v = int(tok, 16)
                    if v in str_by_va:
                        notes.append(f"STR:{str_by_va[v]!r}")
                    if v in iat_by_va:
                        notes.append(f"IMP:{iat_by_va[v]}")
                out(f"{insn.address:08X}  {insn.bytes.hex():<22s} {insn.mnemonic:8s} "
                    f"{insn.op_str}{'   ; ' + ' '.join(notes) if notes else ''}")
                r = (insn.address - va0) + insn.size
                break
        except Exception as e:  # noqa: BLE001
            out(f"disasm error at {hx(va0 + r)}: {e}")
            break
        if r <= n0:
            r = n0 + 1
    out("--- end range ---")


# ================================================================== Z1 0x427660
out("")
out("================================================================ Z1")
out("= Z1 fn 0x427660 whole (dialog init / resource-loader driver)")
out("================================================================")
end = next_fn_start(0x427660 + 1)
out(f"fn end: {hx(end)}")
dump(0x427660, end, "fn 0x427660 whole")

# ============================================== Z2 X-hunt displacements 0xEC/1c
out("")
out("================================================================ Z2")
out("= Z2 .text-wide memory-operand X-hunt: disp 0xEC loads/stores; "
    "+0x1c stores adjacent to +0x14 stores")
out("================================================================")
out("-- sites with base-register disp 0xEC (pw CString reads) --")
blob = text
r = 0
count = 0
while r < len(blob) - 16:
    try:
        for insn in md64.disasm(blob[r:r + 16], text_va0 + r):
            if insn.mnemonic in ("mov", "lea", "cmp", "add", "sub", "test",
                                 "movzx", "push", "xchg", "inc", "dec"):
                for op in insn.operands:
                    if op.type == capstone.x86.X86_OP_MEM and \
                            op.mem.disp == 0xEC and op.mem.base != 0 and \
                            (op.mem.index == 0 or op.mem.scale == 0):
                        count += 1
                        out(f"{hx(insn.address)} ({hx(fn_starts and 0) or ''}"
                            f"): {insn.mnemonic} {insn.op_str}")
            r += insn.size
            break
    except Exception:  # noqa: BLE001
        r += 1
out(f"disp0xEC total: {count}")

out("")
out("-- 'mov [reg+0x1c], reg' stores whose containing fn also touches [reg+0x14] --")
onec = []
ri = 0
while ri < len(blob) - 16:
    try:
        for insn in md64.disasm(blob[ri:ri + 16], text_va0 + ri):
            if insn.mnemonic == "mov" and len(insn.operands) == 2:
                d, s = insn.operands
                if d.type == capstone.x86.X86_OP_MEM and d.mem.disp == 0x1C and \
                        d.mem.base != 0 and s.type == capstone.x86.X86_OP_REG and \
                        d.mem.index == 0:
                    fn = containing_fn(insn.address)
                    onec.append((insn.address, fn, insn.op_str))
            ri += insn.size
            break
    except Exception:  # noqa: BLE001
        ri += 1
out(f"'+0x1c' store count: {len(onec)}")
for va, fn, s in onec:
    out(f"  {hx(va)} fn {hx(fn)}: mov {s}")

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"report: {len(lines)} lines -> {REPORT.name}")
