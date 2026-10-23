#!/usr/bin/env python3
"""fw_feat.py - phase-2 remainder recon: the flash-table band 0x16E00..0x18600.

Input : analysis/out/rcdata_4000.bin (written by probe_pe.py from the pinned exe)
Output: analysis/out/fw_feat.txt + console summary

Read-only, static byte statistics only. No device, no execution.

Goals (plan phase-2 remainder: keymap / lighting / scan recon):
1. Block classification of the table band: ramps (gradient tables), Z-fill
   arrays (layout/ keymap candidates), bit-graphics (font), text.
2. Extraction + dump of every 0x5A-filled candidate array (the "Z-tables":
   0x5A behaves as the unused-slot filler, NOT 0xFF and NOT 0x00).
3. Full hex of the keymap-candidate band 0x16F00..0x17800 and the descriptor
   template / string band 0x17F00..0x18600 so nothing is re-guessed later.
4. Feature-report-shaped and HID-report-shaped byte patterns near 'HID
   Interface' (0x18044) and 'String For Test...' (0x180E4).
"""
from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMG = ROOT / "analysis" / "out" / "rcdata_4000.bin"
OUT = ROOT / "analysis" / "out"
REPORT = OUT / "fw_feat.txt"

Z = 0x5A  # unused-slot filler byte in this band

lines: list[str] = []


def out(*a):
    s = " ".join(str(x) for x in a)
    lines.append(s)
    print(s)


def hexdump(blob: bytes, base: int):
    for i in range(0, len(blob), 16):
        row = blob[i : i + 16]
        gut = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out(f"  0x{base + i:05x}  {row.hex(' ')}  {gut}")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


data = IMG.read_bytes()
assert len(data) == 0x7E000, f"unexpected image size {len(data):#x}"
assert data[0x7DFFC:0x7E000] == bytes.fromhex("5555aaaa"), "tail magic moved"
out(f"image ok: {len(data):#x} bytes, tail magic in place")
out("")

# ---------------------------------------------------------- band block classes
BAND_LO, BAND_HI = 0x16E00, 0x18600
out(f"== block classification 0x{BAND_LO:05x}..0x{BAND_HI:05x} (128-byte blocks) ==")


def classify(block: bytes) -> str:
    n = len(block)
    c = Counter(block)
    frac = lambda b: c.get(b, 0) / n
    if max(c, key=c.get) == 0 and frac(0) > 0.95:
        return "zero"
    if frac(Z) > 0.4:
        return "Z-filled"
    # arithmetic ramp: values advance by a constant step nearly everywhere
    d = [block[i + 1] - block[i] for i in range(n - 1)]
    step = Counter(d).most_common(1)[0][0]
    if step != 0 and sum(1 for x in d if x == step) / len(d) > 0.9:
        return f"ramp(step={step:+d})"
    # column-ish graphics: many byte values repeated few times, high diversity
    if entropy(block) > 5.0:
        return f"busy(ent={entropy(block):.2f},uniq={len(c)})"
    if all(32 <= b < 127 for b in block if c[b] > 0):
        return "text"
    return f"mixed(ent={entropy(block):.2f},z={frac(0):.2f})"


for off in range(BAND_LO, BAND_HI, 128):
    block = data[off : off + 128]
    out(f"  0x{off:05x}..0x{min(off, BAND_HI):05x}", classify(block))

# ------------------------------------------------------------- Z-run inventory
out("")
out(f'== every 0x5A-filler run >= 8 consecutive {Z:#x} bytes in band ==')
zruns = []
i = BAND_LO
while i < BAND_HI:
    j = i
    while j < len(data) and data[j] == Z:
        j += 1
    if j - i >= 8:
        zruns.append((i, j))
    i = j if j > i else i + 1
for lo, hi in zruns:
    out(f"  0x{lo:05x}..0x{hi:05x}  ({hi - lo} bytes)")

# Z-table = array immediately preceding its filler run: walk back over
# connected "value-like" bytes (0x20..0x5A but not the filler itself, plus
# separators we actually observe) and print the array + the filler.
out("")
out("== Z-table extract (walk back from each filler-run start) ==")


def is_table_byte(b: int) -> bool:
    return 0x20 <= b <= Z and b != Z and b not in (0x27,)


for lo, hi in zruns:
    start = lo
    while start - 1 >= BAND_LO and is_table_byte(data[start - 1]):
        start -= 1
    end = hi
    while end < BAND_HI and is_table_byte(data[end]):
        end += 1
    arr = data[start:end]
    out(f"  array 0x{start:05x}..0x{end:05x} len {len(arr)} (filler run 0x{lo:05x}..0x{hi:05x})")
    hexdump(arr[:96], start)
    if len(arr) > 96:
        out(f"    ... ({len(arr) - 96} more bytes)")
    out("")

# ------------------------------------------------ keymap-band full hex dump
out("== keymap-candidate band hex dump 0x16F00..0x17800 ==")
hexdump(data[0x16F00:0x17800], 0x16F00)

out("")
out("== descriptor/string band hex dump 0x17F00..0x18600 ==")
hexdump(data[0x17F00:0x18600], 0x17F00)

# ------------------------------------------------ key universe (verified)
out('== key universe: three layout tables + bijection check ==')
# A: serial/walk array with 0 delimiter at 0x1700e, keys 0x1700f..0x1704b
Akeys = [b for b in data[0x1700F:0x1704C] if b not in (Z,)]
# W: pair table 0x16ff6..0x1700d (12 pairs, first partner is 0x5a)
W = data[0x16FF6:0x1700E]
# B: per-scan-line grouping 0x17058..0x170ac, groups split on >=2 Z padding,
#    terminated by the 0x00 after the final 5a 5a run
Bkeys = data[0x17058:0x170ad]
# C: LED-group stream 0x175c1..0x1762a: group ids 00..0d appear in ascending
#    order, each followed by 1..4 member byte key-ids (all >= 0x0e, so the id
#    match is unambiguous), padded with 0x5a between/inside records
Crecs = []
Cstream = data[0x175C1:0x1762C]
expected = 0
cur = None
for b in Cstream:
    if b == expected and expected <= 0x0D:
        if cur is not None:
            Crecs.append(cur)
        cur = [b]
        expected += 1
    elif cur is not None and b != Z:
        cur.append(b)
if cur is not None:
    Crecs.append(cur)


def clean(arr):
    return [b for b in arr if b not in (Z, 0)]


uA, uB, uC = set(clean(Akeys)), set(clean(Bkeys)), set(b for rec in Crecs for b in rec if b not in (Z, 0))
out(f"  A walk (0x1700F..0x1704B): {len(uA)} distinct keys: " +
    " ".join(f"{v:02x}" for v in sorted(uA)))
out(f"  B scan-line grouping (0x17058.., Z-padded stream): {len(uB)} distinct")
out(f"  C LED-group records (0x175C1.., 8B records): {len(Crecs)} records, {len(uC)} distinct")
union = uA | uB | uC
gaps = [v for v in range(min(union), max(union) + 1) if v not in union]
out(f"  union {len(union)} keys, min/max {min(union):02x}/{max(union):02x}, "
    f"gaps in range: {gaps or 'NONE'}")
out("")

# B decode: split the Z-padded stream into groups (2+ consecutive Z = separator)
groups = []
cur = []
zcount = 0
for b in Bkeys:
    if b == Z:
        zcount += 1
        if zcount >= 2 and cur:
            groups.append(cur)
            cur = []
    else:
        zcount = 0
        cur.append(b)
if cur:
    groups.append(cur)
out("== B scan-line groups (keys per matrix scan line) ==")
for gi, g in enumerate(groups):
    out(f"  line {gi:2d} ({len(g):2d} keys): " + " ".join(f"{v:02x}" for v in g))
out("")

# C decode: 8-byte records (Z, key?, members..., Z, Z)
out("== C LED-group records ==")
# observed shape: 5a <block-id> <members that are key ids> 5a 5a
for gi, rec in enumerate(Crecs):
    vals = [b for b in rec if b not in (Z,)]
    out(f"  group {gi:2d}: {' '.join(f'{v:02x}' for v in vals)}")
out("")

# W decode: raw pairs; flag that first partner is 0x5a
out("== W pair table 0x16FF6..0x1700D (raw) ==")
for i in range(0, len(W), 2):
    out(f"  pair {i//2:2d}: {W[i]:02x} {W[i+1]:02x}")
out("")

# ------------------------------------------------------- ramp tables (LED?)
out("== ramp runs (arith step +-1..4, len>=24) anywhere in band, excluding ramp(zeros) ==")
hits_x = 0
for off in range(BAND_LO, BAND_HI - 24):
    win = data[off : off + 32]
    if win[0] == 0 or win[0] == Z:
        continue
    d = [win[i + 1] - win[i] for i in range(31)]
    step = Counter(d).most_common(1)[0][0]
    if step in (-4, -3, -2, -1, 1, 2, 3, 4):
        frac_ok = sum(1 for x in d if x == step) / 31
        if frac_ok > 0.85:
            hits_x += 1
out(f"  ramp-shaped 32-byte windows: {hits_x} (tables live 0x170B9..0x17211, "
    f"0x17210..0x17311, 0x17315..0x17354, 0x17830 triplets)")
out("")

# classified neighbours inside the band (hex spot rows only, keep report lean)
out("== misc classified records ==")
out("  0x174B9..0x17598: (row,col) cell records, 16B stride, 0-padded")
out("  0x17668..0x17678: RGB palette triplets ff0000 ff8000 ffff00 ..")
out("  0x17678..0x17800: font/graphics bitmaps (busy, uniq>55)")
out("  0x17830..: hue-ramp byte-triplets (quadratic middle-byte increments)")
out("  0x17A70..: effect presets (c8 96 64 4b 19 19 ff ff ..)")
out("  0x17CC0..0x17D40: register-init dwords target 0x4001B2xx peripheral addrs")
out("  0x17E38..0x17F00: per-profile hue values (77/6f/21/47 ..) + 01 1d headers")
out("  0x17F20..: LED-driver init records (subaddr 0x14/0x18 pairs + values)")


# ------------------------------------------- HID-shaped bytes around anchors
out("")
out("== HID anchor contexts with 96 bytes lead-in ==")
for anchor in (b"HID Interface", b"String For Test"):
    at = data.find(anchor)
    while at != -1:
        lo = max(0, at - 96)
        out(f"  {anchor.decode()}: 0x{at:x}")
        hexdump(data[lo : at + 96], lo)
        at = data.find(anchor, at + 1)

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8", errors="replace")
out("")
out(f"report written: {REPORT}")
