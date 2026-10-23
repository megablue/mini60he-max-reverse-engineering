#!/usr/bin/env python3
"""isp_gate.py - phase-6 precondition probe: which chip record does the tool
select, and does the stock 0x7E000 image pass the RCDATA size gate?

  G1  the 12 chip records at 0x5A9AD0 (stride 0x33): field0 dword, +0x1F
      pointer, +0x27/+0x2B/+0x2F words, +4 dword
  G2  the size gate inside fn 0x427120 (0x4272AA..0x427320) annotated, and
      the verdict for a 0x7E000-byte RCDATA 4000
  G3  the other two readers of record field0 (0x41F4AE, 0x4268FE) + contexts,
      to name what field0 actually means
  G4  every instruction in .text whose displacement is exactly 0x5A9AD0
      (read or write), and every store into [reg+0x3E8] (the dialog's record
      index member)
  G5  the 12-name chip table at 0x588F7C and the five protocol-variant
      installer sites

Read-only: the pinned exe is opened as bytes (SHA-256 enforced). Never
executed; no HID device touched -- static bytes only.

    python analysis/isp_gate.py       # report -> out/isp_gate.txt

Artifact: analysis/out/isp_gate.txt
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
REPORT = OUT / "isp_gate.txt"

SHA256_PIN = "958A39951D2F908A7FE925E0FA598C321924CB235239BF37484AE7C8213512D6"

REC_BASE = 0x5A9AD0
REC_STRIDE = 0x33
REC_COUNT = 12
DIALOG_IDX = 0x3E8          # [dialog+0x3E8] = chip-record index
SIZE_CAP = 0x8400
STOCK_SIZE = 0x7E000
NAME_TABLE = 0x588F7C
INSTALLERS = (0x556285, 0x556735, 0x556CD0, 0x557D70, 0x558E50)

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

secs = []
for sec in pe.sections:
    name = sec.Name.rstrip(b"\x00").decode("latin-1")
    secs.append((name, sec.PointerToRawData, sec.SizeOfRawData,
                 base + sec.VirtualAddress, base + sec.VirtualAddress + sec.SizeOfRawData))

TEXT_SEC = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
text = raw[TEXT_SEC.PointerToRawData:TEXT_SEC.PointerToRawData + TEXT_SEC.SizeOfRawData]
text_va0 = base + TEXT_SEC.VirtualAddress


def va_off(va: int) -> int | None:
    """VA -> file offset (raw sections only)."""
    for name, off, size, v0, v1 in secs:
        if v0 <= va < v1:
            d = va - v0
            if d < size:
                return off + d
    return None


def rd32(va: int) -> int:
    o = va_off(va)
    if o is None:
        return 0xDEADBEEF
    return int.from_bytes(raw[o:o + 4], "little")


def rd16(va: int) -> int:
    o = va_off(va)
    if o is None:
        return 0xBEEF
    return int.from_bytes(raw[o:o + 2], "little")


def rd8(va: int) -> int:
    o = va_off(va)
    return 0xFF if o is None else raw[o]


def cstr(va: int, limit: int = 64) -> str:
    o = va_off(va)
    if o is None:
        return "<no section>"
    e = raw.find(b"\x00", o, o + limit)
    if e < 0:
        e = o + limit
    return raw[o:e].decode("latin-1")


md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

insns = list(md.disasm(text, text_va0))
insn_at = {i.address: i for i in insns}

# ============================================================ G1 records
out("=" * 72)
out("= G1  chip records at 0x5A9AD0, stride 0x33, count 12")
out("=" * 72)
out(" idx  va         f00(+0x00)  d(+0x04)  p1F(+0x1F)  w27   w2B   w2F   cap?  name?")
for i in range(REC_COUNT):
    r = REC_BASE + i * REC_STRIDE
    f00 = rd32(r)
    d04 = rd32(r + 4)
    p1f = rd32(r + 0x1F)
    w27 = rd16(r + 0x27)
    w2b = rd16(r + 0x2B)
    w2f = rd16(r + 0x2F)
    cap = "0x8400" if f00 == 0 else "none"
    out(f" {i:2d}  {hx(r):<10s} {f00:#010x}  {d04:#010x}  {hx(p1f):<10s} "
        f"{w27:#06x} {w2b:#06x} {w2f:#06x} {cap:<5s}")

out("")
out("records with field0 == 0 (capped at 0x8400): " +
    ", ".join(str(i) for i in range(REC_COUNT) if rd32(REC_BASE + i * REC_STRIDE) == 0))
out("records with field0 != 0 (no size check):  " +
    ", ".join(str(i) for i in range(REC_COUNT) if rd32(REC_BASE + i * REC_STRIDE) != 0))

out("")
out("distinct field0 values:")
seen: dict[int, list[int]] = {}
for i in range(REC_COUNT):
    seen.setdefault(rd32(REC_BASE + i * REC_STRIDE), []).append(i)
for v, ids in sorted(seen.items()):
    out(f"   {v:#010x}  idx {ids}")

# ============================================================ G2 size gate
out("")
out("=" * 72)
out("= G2  size gate in fn 0x427120 (RCDATA 4000 -> dialog buffer)")
out("=" * 72)
for a in range(0x4272A0, 0x427320):
    i = insn_at.get(a)
    if not i:
        continue
    note = ""
    if i.mnemonic.startswith("cmp") and i.op_str.endswith(hx(SIZE_CAP)):
        note = f"  <-- cap: size {hx(STOCK_SIZE)} {'EXCEEDS' if STOCK_SIZE > SIZE_CAP else 'fits'}"
    if i.mnemonic == "xor" and i.op_str == "al, al":
        note = "  <-- bail: returns 0, firmware NOT loaded"
    if i.mnemonic == "imul" and i.op_str.endswith("0x33"):
        note = "  <-- record stride"
    out(f"{i.address:08X}  {i.bytes.hex():<22s} {i.mnemonic:8s} {i.op_str}{note}")

out("")
gate_ok_capped = STOCK_SIZE <= SIZE_CAP
out(f"verdict, field0 == 0 record : stock image {hx(STOCK_SIZE)} vs cap "
    f"{hx(SIZE_CAP)} -> {'PASSES' if gate_ok_capped else 'REJECTED (xor al,al)'}")
out("verdict, field0 != 0 record : size check skipped entirely -> PASSES")

# ============================================================ G3 field0 readers
out("")
out("=" * 72)
out("= G3  other readers of record field0 (what the dword means)")
out("=" * 72)
for site, tag in ((0x41F4AE, "fn around 0x41F4AE"), (0x4268FE, "fn around 0x4268FE")):
    out("")
    out(f"-- {tag}: +/-0x30 around {hx(site)}")
    for a in range(site - 0x30, site + 0x34):
        i = insn_at.get(a)
        if not i:
            continue
        mark = "  <-- record field0" if a == site else ""
        out(f"{i.address:08X}  {i.bytes.hex():<22s} {i.mnemonic:8s} {i.op_str}{mark}")

# ============================================================ G4 displacement sweep
out("")
out("=" * 72)
out("= G4  split-vs-sweep: every insn whose *displacement* is 0x5A9AD0")
out("=" * 72)
hits = 0
def operands(ins) -> list:
    """Operands, or [] for a SKIPDATA pseudo-insn (id 0 / CS_ERR_SKIPDATA)."""
    if ins.id == 0:
        return []
    try:
        return list(ins.operands)
    except capstone.CsError:
        return []


for i in insns:
    ops = operands(i)
    if not ops:
        continue
    for op in ops:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.disp == REC_BASE:
            kind = "WRITE" if any(o.type == capstone.x86.X86_OP_MEM and o.access == capstone.CS_AC_WRITE for o in ops) else "read/lea"
            out(f"{i.address:08X}  {i.bytes.hex():<22s} {i.mnemonic:8s} {i.op_str}   [{kind}]")
            hits += 1
out(f"total displacement hits: {hits}")

out("")
out("-- stores into [reg+0x3E8] (dialog chip-record index member)")
w3e8 = 0
for i in insns:
    if i.mnemonic not in ("mov", "or", "and", "add", "inc", "xchg"):
        continue
    ops = operands(i)
    if len(ops) < 1:
        continue
    dst = ops[0]
    if dst.type != capstone.x86.X86_OP_MEM or dst.mem.disp != DIALOG_IDX:
        continue
    if dst.access != capstone.CS_AC_WRITE:
        continue
    out(f"{i.address:08X}  {i.bytes.hex():<22s} {i.mnemonic:8s} {i.op_str}")
    w3e8 += 1
out(f"total writers: {w3e8}")

out("")
out("-- reads of [reg+0x3E8]")
r3e8 = 0
for i in insns:
    ops = operands(i)
    if not ops:
        continue
    for op in ops:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.disp == DIALOG_IDX and op.access == capstone.CS_AC_READ:
            out(f"{i.address:08X}  {i.bytes.hex():<22s} {i.mnemonic:8s} {i.op_str}")
            r3e8 += 1
            break
out(f"total readers: {r3e8}")

# ============================================================ G5 names + installers
out("")
out("=" * 72)
out("= G5  chip-name table 0x588F7C and protocol-variant installers")
out("=" * 72)
out("name table (C strings in order):")
p = NAME_TABLE
for k in range(14):
    s = cstr(p)
    out(f"  [{k:2d}] {hx(p)}  {s!r}")
    if not s or s == "<no section>":
        break
    p += len(s) + 1

out("")
for site in INSTALLERS:
    out(f"")
    out(f"-- installer {hx(site)} +/-0x50")
    for a in range(site - 0x50, site + 0x54):
        i = insn_at.get(a)
        if not i:
            continue
        mark = "  <-- installer head" if a == site else ""
        out(f"{i.address:08X}  {i.bytes.hex():<22s} {i.mnemonic:8s} {i.op_str}{mark}")

OUT.mkdir(parents=True, exist_ok=True)
REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"report: {len(lines)} lines -> {REPORT.name}")
