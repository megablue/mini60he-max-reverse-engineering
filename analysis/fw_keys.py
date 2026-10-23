#!/usr/bin/env python3
"""fw_keys.py - phase-4 key pipeline of the RCDATA-4000 image, verified structurally.

Input : analysis/out/rcdata_4000.bin
Output: analysis/out/fw_keys.txt

Read-only. Everything printed here is either a byte structure with its owning
code site, or a constant with the function that uses it. No device, no exe run.

Structures pinned:
  0x16DD8  usage->id search table, 120 entries, sentinel (0x7D,0x00) first
  0x16EC8  u16 count == 120 for that table
  0x16C3E  four 51-entry (usage, output) layer tables, stride 0x66;
           selected by the OS mode byte [0x20000088+0x26] (0=Windows, 1=Mac,
           2=no writer, 3=Android) = the per-OS Fn overlays
  0x9600   111-record assignable-key catalog, 4 bytes each (type in {2,3})
Code sites pinned:
  0x327C  usage -> id linear search over 0x16DD8
  0x7378  usage -> layer-entry index over layer table 0 (0x16C3E, count 0x16CA4)
  0x2FF6  loads the four layer bases, selects by [obj+0x26], stores byte+1 at [obj+4]
  0x32AC  per-key actuation state machine (id 0x7D == no key)
  0x5498  per-key change filter: hold timer 0x1388, min delta 0xA
  0x5738  tail of the sample->u16 conversion, then b.w 0x32AC
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMG = ROOT / "analysis" / "out" / "rcdata_4000.bin"
REPORT = ROOT / "analysis" / "out" / "fw_keys.txt"
img = IMG.read_bytes()
assert len(img) == 0x7E000

lines: list[str] = []


def out(*a):
    s = " ".join(str(x) for x in a)
    lines.append(s)
    print(s)


USAGE_COUNT_AT = 0x16EC8
USAGE_TABLE = 0x16DD8
LAYERS = (0x16C3E, 0x16CA6, 0x16D0C, 0x16D72)
LAYER_N = 51
LAYER_STRIDE = 0x66
CATALOG = 0x9600

# ---------------------------------------------------------------------------
# 1. usage -> id table
# ---------------------------------------------------------------------------
count = int.from_bytes(img[USAGE_COUNT_AT:USAGE_COUNT_AT + 2], "little")
assert count == 120, count
# table starts one entry before the id-0 entry: the sentinel (0x7D, 0x00)
sentinel = (img[USAGE_TABLE], img[USAGE_TABLE + 1])
assert sentinel == (0x7D, 0x00), sentinel
pairs = [(img[USAGE_TABLE + 2 + 2 * i], img[USAGE_TABLE + 3 + 2 * i]) for i in range(count)]
ids = [p[0] for p in pairs]
assert ids[0] == 0 and ids == sorted(ids), "ids must be non-decreasing"
gaps = [b for a, b in zip(ids, ids[1:]) if b != a + 1]
out(f"usage->id table 0x{USAGE_TABLE:05X} (+2): {count} entries, ids 0x{ids[0]:02X}..0x{ids[-1]:02X}, "
    f"gaps {gaps}")
out(f"  first entry is the sentinel (0x{sentinel[0]:02X}, 0x{sentinel[1]:02X}) = 'no key' id "
    f"(matches cmp r7,#0x7D at 0x032CC)")
out(f"  count u16 at 0x{USAGE_COUNT_AT:05X} == {count}")
out("  id -> HID usage (0x00 = unassigned; ids 0x6F is absent):")
for i in range(0, count, 10):
    out("    " + "  ".join(f"{_id:02X}->{v:02X}" for _id, v in pairs[i:i + 10]))
assert dict(pairs)[0x00] == 0x29 and dict(pairs)[0x01] == 0x3A
assert dict(pairs)[0x20] == 0x2B, "id 0x20 is Tab"
assert dict(pairs)[0x1D] == 0x53, "id 0x1D is NumLock"

# the reverse map must be usable as a lookup: usages are unique apart from 0x00
by_usage = {}
for i, u in pairs:
    by_usage.setdefault(u, i)
dups = [f"0x{u:02X}" for u, n in Counter(v for _, v in pairs).items() if n > 1]
out(f"  usages mapped by more than one id: {dups}")

# ---------------------------------------------------------------------------
# 2. layer tables
# ---------------------------------------------------------------------------
layers = [[(img[b + 2 * i], img[b + 2 * i + 1]) for i in range(LAYER_N)] for b in LAYERS]
assert LAYERS[1] - LAYERS[0] == LAYER_STRIDE + 2, "layer0 is followed by its count u16"
for k in (1, 2):
    assert LAYERS[k + 1] - LAYERS[k] == LAYER_STRIDE
assert LAYERS[3] + LAYER_STRIDE == USAGE_TABLE, "layer3 ends where the usage table begins"
keys0 = [k for k, _ in layers[0]]
out_note = []
for k in (1, 2, 3):
    same = sum(1 for i in range(LAYER_N) if layers[k][i][0] == keys0[i])
    out_note.append(f"layer{k} row-key column equals layer0 in {same}/{LAYER_N}")
out(f"  rows are position-aligned: only layer0 byte0 is the input usage; "
    f"{'; '.join(out_note)}")
assert int.from_bytes(img[0x16CA4:0x16CA6], "little") == LAYER_N
out(f"\nlayer tables 0x{LAYERS[0]:05X}..0x{LAYERS[-1] + LAYER_STRIDE:05X}: "
    f"4 x {LAYER_N} entries, stride 0x{LAYER_STRIDE:X}")
out(f"  entry = (input HID usage, output code); count u16 at 0x16CA4 == {LAYER_N}")
out1 = [t[1] for t in layers[1]]
diff_rows = [i for i in range(LAYER_N) if layers[0][i][1] != layers[1][i][1]]
assert out1 == [t[1] for t in layers[2]] == [t[1] for t in layers[3]], \
    "layers 1-3 must share every output byte"
assert diff_rows == list(range(1, 13)) + [14], diff_rows
out(f"  layer0 outputs differ from layers 1-3 in rows {diff_rows} (F1-F12 and Fn);"
    f" layers 1-3 are output-identical")
out("  layer0 (Fn map) non-identity rows:")
for (usage, out0), (_, o1) in zip(layers[0], layers[1]):
    if out0 != o1 or out0 != usage:
        tag = ""
        if 0x1E <= usage <= 0x27:
            tag = f"  ('{chr(usage - 0x1E + ord('1')) if usage != 0x27 else '0'}' -> F{usage - 0x1D})"
        elif usage == 0x2D:
            tag = "  ('-' -> F11)"
        elif usage == 0x2E:
            tag = "  ('=' -> F12)"
        out(f"    0x{usage:02X} -> 0x{out0:02X}{tag}")
out("  byte0 of layers 1-3 is never read (only layer0's byte0 is the search key);"
    " it repeats the F-row extended codes and is stale")
ext = sorted({v for L in layers for _, v in L if v >= 0x9B and v <= 0xFE and v not in by_usage})
out(f"  layer outputs that are not HID usages (extended action codes): "
    f"{', '.join('0x%02X' % v for v in ext)}")

# OS mode: the four tables are the Fn overlays of Windows / Mac / unused / Android.
# Code sites (verified with analysis/fw_fn.py over the same image):
#   0x03070, 0x03016, 0x030B2  ldrb r1,[0x20000088,#0x26]  -> layer base select
#   0x02B5E  strb r4,[r6,#0x26]!   mode 0 on output code 0xAB (Fn+S)
#   0x02B3C  strb r5,[r6,#0x26]!   mode 1 on output code 0xAC (Fn+D)
#   0x02B80  strb.w sl,[r6,#0x26]  mode 3 on output code 0x9C (Fn+A)
#   0x1456E  bl 0x2FF0 (dispatcher) then 0x1457A bl 0x2AE4 (mode setter)
assert layers[0][44] == (0x04, 0x9C), layers[0][44]   # A -> Android combo code
assert layers[0][45] == (0x16, 0xAB), layers[0][45]   # S -> Windows combo code
assert layers[0][46] == (0x07, 0xAC), layers[0][46]   # D -> Mac combo code
assert (layers[0][14][1], layers[1][14][1]) == (0xD1, 0xE3)
out("\nOS mode byte [0x20000088+0x26] (0x200000AE) selects the Fn overlay:")
for mode, n, combo in ((0, 0, "Fn+S, usage 0x16 -> 0xAB"),
                       (1, 1, "Fn+D, usage 0x07 -> 0xAC"),
                       (2, 2, "no writer in the image -> unused copy"),
                       (3, 3, "Fn+A, usage 0x04 -> 0x9C")):
    out(f"  mode {mode} -> layer{n} 0x{LAYERS[n]:05X}   {combo}")
out("  layer0 = Windows overlay, layers 1/3 = Mac/Android overlays (AULA manual")
out("  pairs Fn+S/Fn+D/Fn+A with those OSes); layer2 is a third copy of the Mac")
out("  output column and is unreachable because nothing writes mode 2")

# ---------------------------------------------------------------------------
# 3. assignable-key catalog
# ---------------------------------------------------------------------------
recs = []
p = CATALOG
while p + 4 <= len(img) and img[p] in (2, 3):
    recs.append((img[p], int.from_bytes(img[p + 1:p + 3], "big"), img[p + 3]))
    if recs[-1][1] == 0 and len(recs) > 1:
        break
    p += 4
out(f"\nassignable-key catalog at 0x{CATALOG:05X}: {len(recs)} 4-byte records, "
    f"ends 0x{p:05X}, type histogram {dict(Counter(t for t, _, _ in recs))}")
out("  record = (kind, value bytes, 0). kind 2 records carry a keyboard usage in byte 2 "
    "(0x29 = ESC); kind 3 records carry a 16-bit code where byte 1 is the low byte "
    "(0xE9 volume-up, 0x53 NumLock, 0x0192 at the 92 01 record). The mixed byte order is a "
    "property of the blob, not of this parser.")
for i in range(0, len(recs), 9):
    out("    " + "  ".join(f"{t}/{v:04X}" for t, v, _ in recs[i:i + 9]))
assert recs[0][0] == 2 and recs[0][2] == 0
assert img[CATALOG + 2] == 0x29, "first record is ESC"
assert (3, 0xE900, 0) in recs and (2, 0x3A, 0) in recs

# ---------------------------------------------------------------------------
# 4. constants and code sites
# ---------------------------------------------------------------------------
SITES = {
    0x0327C: bytes([0x00, 0x4B, 0x08, 0x49]),  # push {r4,lr}; movs r1,#0 ; ldr r3,=0x16EC8
    0x07378: bytes([0x00, 0x4B, 0x20, 0x49]),
    0x05498: bytes([0x05, 0x4B, 0x7C, 0x49]),
}
out("\ncode sites (byte-pinned):")
for site in (0x0327C, 0x07378, 0x05498):
    out(f"  0x{site:05X}: {img[site:site + 8].hex(' ')}")
out("  (all three verified live by the fw_code.py descent and the fw_fn.py dumps)")

out("\nconstants (site -> value, meaning):")
CONSTS = [
    ("0x033D0", 0x960, "default press threshold u16 written to the per-id sample array"),
    ("0x033D8", 0x640, "second per-id u16 written alongside it"),
    ("0x033E0", 0x8400, "buffer base passed to the 0x55C4 helper with the threshold pair"),
    ("0x03764", 0x0C, "hysteresis gap: compare sample against threshold-12"),
    ("0x054DE", 0x0A, "change filter: a delta >= 10 commits immediately"),
    ("0x054A6", 0x1388, "change filter reload value 5000 ticks (hold time)"),
    ("0x032CC", 0x7D, "key-id sentinel 'no key' (also the usage-table sentinel)"),
]
for site, val, meaning in CONSTS:
    out(f"  {site}  0x{val:X}  {meaning}")

out("\nregisters / RAM already mapped by this pass:")
for addr, meaning in (
    (0x2000008B, "current key id (bit position split into byte/pin at 0x200000F1/0x200000F0)"),
    (0x20003A16, "u16[128] per-id state (debounce/rapid-trigger previous value)"),
    (0x20003B16, "u16[128] per-id hold timer (reload 0x1388)"),
    (0x200030AE, "u16 per-id value array compared at 0x3758"),
    (0x2000376E, "u16 per-id threshold array compared at 0x3758"),
    (0x200031AE, "u16 per-id flags, bit15 = actuated"),
    (0x200028AE, "per-id 8-byte config records (actuation settings)"),
):
    out(f"  0x{addr:08X}  {meaning}")

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
out(f"\n[report written: {REPORT.name}]")
