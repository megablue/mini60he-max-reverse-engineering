#!/usr/bin/env python3
"""decode_fw.py - phase-2 decode of the RCDATA-4000 image (candidate SN34F280 firmware).

Input : analysis/out/rcdata_4000.bin (written by probe_pe.py from the pinned exe)
Output: analysis/out/fw_decode.txt + console summary

Read-only, static: capstone disassembly and byte statistics only. No device.

Checks (plan phase 2):
1. Cortex-M vector-table hypothesis at image start (SP 0x200076F8, handlers).
2. Thumb (not ARM) validation: every vector address's bit0 + alignment.
3. Flash-region map: nonzero runs, zero and 0xFF runs, page heat.
4. Strings inside the image (ASCII + UTF-16).
5. Checksum/version field hunt: magic dwords, checksum candidates vs image.
"""
from __future__ import annotations

import binascii
import math
import struct
from collections import Counter
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[1]
IMG = ROOT / "analysis" / "out" / "rcdata_4000.bin"
OUT = ROOT / "analysis" / "out"
REPORT = OUT / "fw_decode.txt"

exlines: list[str] = []


def out(*a):
    line = " ".join(str(x) for x in a)
    exlines.append(line)
    print(line)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


data = IMG.read_bytes()
assert len(data) == 0x7E000, f"unexpected image size {len(data):#x}"
out(f"image: {IMG.name}  size {len(data):#x} ({len(data)} bytes)")
out("")

# ---------------------------------------------------------------- head dwords
out("== head dwords (offset 0x0..0xFF) ==")
head = struct.unpack_from("<64I", data, 0)
base_notes = {
    0: "SP initial value",
    1: "Reset handler",
    2: "NMI handler",
    3: "HardFault handler",
    4: "MemManage",
    5: "BusFault",
    6: "UsageFault",
    7: "reserved",
    11: "SVCall",
    12: "DebugMon",
    14: "PendSV",
    15: "SysTick",
}
for i, w in enumerate(head):
    note = base_notes.get(i, "IRQ handler" if i >= 16 else "")
    text = f"[{i:2d}] 0x{w:08x}"
    if i >= 1 and 1 <= w <= len(data) and (w & 1):
        text += f"  (thumb addr 0x{w-1:x})" + ("" if not note else f"  {note}")
    out(text)

# --------------------------------------------------------------- vector table
out("")
out("== vector table sanity ==")
entries = sum(1 for i, w in enumerate(head) if i >= 1 and w)
vt = []
for i, w in enumerate(head):
    if i >= 1 and 1 <= w <= len(data) and (w & 1):
        vt.append((i, w))
amb = [w for _i, w in vt if not (w & 1)]
out(f"entries with thumb-bit0 set : {len(vt)} of {entries} nonzero handler slots")
out(f"max handler address         : {max(w for _i, w in vt):#x} < image end {len(data):#x}")
out("interpretation: Cortex-M0 style vector table, all entries Thumb (ARM would need 4-aligned, bit0=0)")
out("")

# ------------------------------------------------------- disassembly validation
out("== disassembly validation ==")
md_t = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
md_a = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)


def disasm_run(md, data, off, length=0x80):
    return sum(1 for _ in md.disasm(data[off : off + length], off))


for label, off in [
    ("Reset   0x204", 0x205 - 1),
    ("NMI     0x21A", 0x21B - 1),
    ("HardFlt 0x518C", 0x518D - 1),
    ("stub    0x21E", 0x21F - 1),
]:
    r_t = disasm_run(md_t, data, off)
    r_a = disasm_run(md_a, data, off)
    out(f"{label}: {r_t:3d} thumb instrs before first invalid | {r_a:3d} arm instrs before first invalid")

out("")
out("-- Reset handler, first 40 thumb instructions at 0x204 --")
n = 0
for i in md_t.disasm(data[0x204 : 0x204 + 0x300], 0x204):
    out(f"  {i.address:08x}  {i.mnemonic:8}{i.op_str}")
    n += 1
    if n >= 40:
        break

out("")
out("-- HardFault handler region 0x518C, first 24 instructions --")
n = 0
for i in md_t.disasm(data[0x518C : 0x518C + 0x100], 0x518C):
    out(f"  {i.address:08x}  {i.mnemonic:8}{i.op_str}")
    n += 1
    if n >= 24:
        break

out("")
out("-- every handler entry, 4 instructions each --")
for sect, w in vt:
    off = w - 1
    snippet = []
    for i in md_t.disasm(data[off : off + 8], off):
        snippet.append(f"{i.mnemonic} {i.op_str}")
    out(f"  v[{sect:2d}] 0x{w - 1:06x}: " + " | ".join(snippet))

# ----------------------------------------------------------------- region map
out("")
out("== region map (nonzero, non-FF runs; gap >= 0x400 splits) ==")
GAP = 0x400
RUNS = 0x40
runs = []
start = None
last_off = 0
i = 0
n_data = len(data)
while i < n_data:
    w = struct.unpack_from("<I", data, i)[0]
    interesting = w not in (0, 0xFFFFFFFF)
    if interesting:
        if start is None:
            start = i
        last_off = i + 4
    elif start is not None and i + 4 - last_off >= GAP and start is not None:
        runs.append((start, last_off))
        start = None
    i += 4
if start is not None:
    runs.append((start, last_off))
merged = []
for s, e in runs:
    if merged and s < merged[-1][1] + GAP:
        merged[-1][1] = e
    else:
        merged.append([s, e])

out(f"{'start':>9} {'end':>9} {'size':>9} {'align':>5}  entropy  mean-1k-entropy")
for s, e in merged:
    size = e - s
    align = f"{s % 0x1000 == 0 and s % 0x100 == 0 and 'yes' or ('/' if s % 4 == 0 else 'odd'):>5}"
    chunk_ent = [entropy(data[c : c + 0x400]) for c in range(s, min(e, s + 0x4000), 0x400)]
    out(f"{s:9x} {e:9x} {size:9x} {align:>5}  {entropy(data[s:e]):.3f}  {sum(chunk_ent) / len(chunk_ent):.3f}")
out("")
byte_hist = Counter(data)
out(f"byte composition: 0x00 {byte_hist[0] * 100 // n_data}%  0xFF {byte_hist[0xFF] * 100 // n_data}%  other {100 - byte_hist[0] * 100 // n_data - byte_hist[0xFF] * 100 // n_data}%")

# full-region FF detection (erase-state pages, >= 0x1000 aligned)
out("")
out("== fully-0xFF 4k pages and fully-0x00 4k pages ==")
ffpages, zpages = [], []
for p in range(0, n_data, 0x1000):
    page = data[p : p + 0x1000]
    if page.count(0xFF) == 0x1000:
        ffpages.append(p)
    if page.count(0) == 0x1000:
        zpages.append(p)


def ranges(pages):
    outl = []
    for p in pages:
        if outl and p == outl[-1][1] + 0x1000:
            outl[-1][1] = p + 0x1000
        else:
            outl.append([p, p + 0x1000])
    return [f"{a:x}-{b - 1:x}" for a, b in outl]


out(f"0xFF pages (erase state): {', '.join(ranges(ffpages)) if ffpages else 'none'}")
out(f"0x00 pages              : {', '.join(ranges(zpages)) if zpages else 'none'}")

# -------------------------------------------------------------------- strings
out("")
out("== strings inside the image (ASCII, min 4) ==")
strs = []
cur, from_off = [], 0
for idx, byte in enumerate(data):
    if 0x20 <= byte < 0x7F:
        if not cur:
            from_off = idx
        cur.append(chr(byte))
    else:
        if len(cur) >= 4:
            strs.append((from_off, "".join(cur)))
        cur = []
if len(cur) >= 4:
    strs.append((from_off, "".join(cur)))
per_str = [f"  0x{off:06x}  {s!r}" for off, s in strs[:60]]
out("\n".join(per_str))
out(f"(total {len(strs)}; written to fw_strings.txt)")
(OUT / "fw_strings.txt").write_text("\n".join(f"0x{off:06x}  {s}" for off, s in strs) + "\n", encoding="utf-8")

# ----------------------------------------------------------------- checksums
out("")
out("== checksum / magic hunt ==")
out(f"tail 16 bytes @0x{len(data) - 16:x}: {data[-16:].hex(' ')}")
tail_dwords = struct.unpack_from("<1024I", data, len(data) - 0x1000)
uniq_tail = {w: len(data) - 0x1000 + j * 4 for j, w in enumerate(tail_dwords) if w}
out(f"distinct nonzero dwords in last 4k: {[f'{w:08x}@0x{off:x}' for w, off in sorted(uniq_tail.items(), key=lambda kv: kv[1])]}")

body = data[: len(data) - 4]
wsum = sum(struct.unpack(f"<{len(body) // 2}H", body)) & 0xFFFF
ones = (~wsum + 1) & 0xFFFF
wsum32 = sum(struct.unpack(f"<{len(body) // 4}I", body[: len(body) & ~3])) & 0xFFFFFFFF
crc_all = binascii.crc32(data) & 0xFFFFFFFF
crc_body = binascii.crc32(body) & 0xFFFFFFFF
out(f"sum-16 of words over whole minus tail4 : {wsum:04x}  (2's compl {ones:04x})")
out(f"sum-32 of words over whole minus tail4 : {wsum32:08x}")
out(f"crc32 whole image                      : {crc_all:08x}")
out(f"crc32 body minus tail4                 : {crc_body:08x}")

magic = sorted(w for w in uniq_tail if w in (crc_all, crc_body, wsum, ones, wsum32))
for w in magic:
    out(f"tail dword matches candidate: {w:08x} at 0x{uniq_tail[w]:x}")

# '5555aaaa' dword offsets anywhere
needle_a = struct.pack("<I", 0xAAAA5555)
needle_b = struct.pack("<I", 0x5555AAAA)
for needle in (needle_a, needle_b):
    hits = []
    at = data.find(needle)
    while at != -1:
        hits.append(at)
        at = data.find(needle, at + 1)
    out(f"pattern bytes {needle.hex(' ')}: {len(hits)} hit(s): {[f'0x{h:x}' for h in hits[:8]]}")

# boot-loader-ish ascii anchors
for anchor in (b"SN34", b"F280", b"FINDER", b"FIND", b"USB", b"HID", b"KEYB", b"V1.", b"SN32", b"SN8"):
    at = data.find(anchor)
    hits = []
    while at != -1 and len(hits) < 6:
        hits.append(at)
        at = data.find(anchor, at + 1)
    out(f"anchor {anchor!r}: {[f'0x{h:x}' for h in hits] if hits else 'none'}")

# ----------------------------------------------------- UTF-16 strings in image
out("")
out("== strings inside the image (UTF-16BE UTF-16LE, min 3 chars) ==")
u = []
cur, start = [], 0
for i in range(0, len(data) - 1, 2):
    nice = data[i + 1] == 0 and 0x20 <= data[i] < 0x7F
    if nice:
        if not cur:
            start = i
        cur.append(chr(data[i]))
    else:
        if len(cur) >= 3:
            u.append((start, "".join(cur)))
        cur = []
if len(cur) >= 3:
    u.append((start, "".join(cur)))
out("\n".join(f"  0x{a:06x}  {s!r}" for a, s in u[:40]) if u else "  none")
out(f"(total {len(u)})")

# --------------------------------------------- checksum candidates at any dword
out("")
out("== checksum scan: candidate checksums searched at every 4-aligned offset ==")
windows = {
    "full": data,
    "minus-tail4": data[: len(data) - 4],
    "used 0..0x18600": data[:0x18600],
    "code 0..0x9810": data[:0x9810],
    "code 0..0xb000": data[:0xB000],
}
cands = {}
for name, blob in windows.items():
    half = blob[: len(blob) & ~1]
    cands[f"sum16 {name}"] = sum(struct.unpack(f"<{len(half)//2}H", half)) & 0xFFFF
    words4 = blob[: len(blob) & ~3]
    cands[f"sum32 {name}"] = sum(struct.unpack(f"<{len(words4)//4}I", words4)) & 0xFFFFFFFF
    cands[f"crc32 {name}"] = binascii.crc32(blob) & 0xFFFFFFFF
    cands[f"negsum16 {name}"] = (-(sum(struct.unpack(f"<{len(half)//2}H", half)))) & 0xFFFF
for k, v in sorted(cands.items()):
    v4 = v & 0xFFFFFFFF
    hits = []
    for off in range(0, len(data) - 3, 4):
        if struct.unpack_from("<I", data, off)[0] == v4:
            hits.append(off)
    if hits:
        out(f"  {k:<24} = {v:08x}  FOUND at {[f'0x{h:x}' for h in hits]}")

# ----------------------------------------------- MINI60HE MAX / HID descriptors
out("")
out("== product-string contexts ==")
for anchor in (b"MINI60HE", b"HIDAD", b"HID Interface"):
    at = data.find(anchor)
    while at != -1:
        lo, hi = max(0, at - 16), min(len(data), at + 48)
        out(f"  {anchor!s}: 0x{at:x}  {data[lo:hi].hex(' ')}")
        out(f"      text-ish: {data[lo:hi]!r}")
        at = data.find(anchor, at + 1)

REPORT.write_text("\n".join(exlines) + "\n", encoding="utf-8")
out("")
out(f"report written: {REPORT}")
