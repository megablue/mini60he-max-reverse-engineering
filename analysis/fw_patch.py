#!/usr/bin/env python3
"""fw_patch.py - phase-5 modification surface of the RCDATA-4000 image.

Input : analysis/out/rcdata_4000.bin (pinned SHA-256)
Output: analysis/out/fw_patch.txt

Answers one question, read-only: *where exactly would a patch go, and what does
that byte mean?* Nothing here builds or writes an image -- it inventories the
addresses so phase 6 can be a mechanical edit.

  P1  data regions: key remap, scan grid, actuation defaults, LED tables
  P2  code constants: threshold / hysteresis / debounce immediates, per-OS
      output codes, with the exact instruction bytes on disk
  P3  image-side gates a patch must respect (version word, length)
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[1]
IMG = ROOT / "analysis" / "out" / "rcdata_4000.bin"
REPORT = ROOT / "analysis" / "out" / "fw_patch.txt"
IMG_SHA256 = "06A1A47432A6CA7EC060103378E2D984A46F9AFA98F19FCCD99219EAEA4A88E0"

img = IMG.read_bytes()
assert hashlib.sha256(img).hexdigest().upper() == IMG_SHA256, "image is not the pinned one"
assert len(img) == 0x7E000

lines: list[str] = []


def out(*a):
    s = " ".join(str(x) for x in a)
    lines.append(s)


def hx(v: int) -> str:
    return f"0x{v:X}"


def win(off: int, n: int) -> str:
    return img[off:off + n].hex(" ")


def u16(o: int) -> int:
    return int.from_bytes(img[o:o + 2], "little")


def u8(o: int) -> int:
    return img[o]


md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
md.detail = True


def disasm(off: int, stop: int, marks: dict[int, str] | None = None) -> None:
    """Annotated window; `marks` maps image offset -> comment."""
    marks = marks or {}
    for ins in md.disasm(img[off:stop], off):
        note = marks.get(ins.address, "")
        out(f"  {ins.address:05X}  {ins.bytes.hex():<16s} {ins.mnemonic:8s} "
            f"{ins.op_str}{'   ; ' + note if note else ''}")


# ===========================================================================
# P1  data regions
# ===========================================================================
out("=" * 78)
out("= P1  DATA REGIONS (image offsets; unit = bytes per addressable key/entry)")
out("=" * 78)

USAGE_TABLE = 0x16DD8
USAGE_N_AT = 0x16EC8
usage_n = u16(USAGE_N_AT)
assert usage_n == 120, usage_n
out("")
out("[1] key remap - usage<->id table, the primary 'change what a key sends' hook")
out(f"    table  {hx(USAGE_TABLE)} .. {hx(USAGE_TABLE + 2 + 2 * usage_n)}  "
    f"{usage_n} x 2 B (id, HID usage), sentinel (0x7D,0x00) first")
out(f"    count  u16 at {hx(USAGE_N_AT)} == {usage_n}")
out("    edit   2 bytes per key: byte1 = HID usage sent, byte0 = the key id the")
out("           scan map produced. Leave byte0 alone; changing it re-targets an id.")
out(f"    first 8 pairs: {win(USAGE_TABLE, 18)}")
out("    ownership: fn 0x327C (usage->id search), callers 0x7630/0x763C/0x10988/0x128B6")
out("    trap   duplicate usages are not rejected by firmware; two keys then report")
out("           the same usage and the host sees a double press.")

LAYERS = (0x16C3E, 0x16CA6, 0x16D0C, 0x16D72)
LAYER_STRIDE = 0x66
LAYER_N = 51
out("")
out("[2] per-OS Fn overlays - 4 tables, 51 rows x 2 B each")
for idx, base in enumerate(LAYERS):
    os_name = ("Windows", "Mac", "unused (no writer for mode 2)", "Android")[idx]
    out(f"    layer{idx} {hx(base)} .. {hx(base + LAYER_STRIDE)}  {os_name}, "
        f"{LAYER_N} rows, first row {win(base, 2)}")
out("    edit   byte1 of a row (offset +1) = the output code that layer produces")
out("           for layer key byte0. Layers 1-3 never read byte0 (stale extended-")
out("           code column, identical across the three); only layer0 searches it.")
out("    trap   the mode byte is 0x200000AE (0/1/3 reachable via Fn+S/D/A); layer 2")
out("           has no writer, so editing it changes nothing at runtime.")
out("    ownership: loader 0x2FF0 (4 bases, select by [obj+0x26]), output -> [obj+4]")
out("               search 0x7378 over layer0, consumer 0x2AE4 (re-reads [obj+4])")

SCAN_MAP = 0x16A96
out("")
out("[3] scan grid - physical position -> logical key id")
out(f"    table  {hx(SCAN_MAP)} .. {hx(SCAN_MAP + 128)}  128 B, index = row + 8*col")
out("    edit   1 byte per physical cell: the key id that cell reports")
out(f"           0x7D = no key. first 32: {win(SCAN_MAP, 32)}")
out("    trap   a wrong id here points at a nonexistent key; ids must exist in the")
out("           usage table above and in the per-key RAM arrays (128 entries).")

out("")
out("[4] actuation / debounce defaults")
t8400 = [u16(0x8400 + 2 * i) for i in range(112)]
t8500 = [u16(0x8500 + 2 * i) for i in range(112)]
out(f"    per-key table 0x8400  {len(set(t8400))} distinct over 112 entries, "
    f"first {[hex(v) for v in t8400[:6]]}")
out(f"                 0x8500  {len(set(t8500))} distinct over 112 entries, "
    f"first {[hex(v) for v in t8500[:6]]}")
out("    code seeds   0x960 (2400) and 0x640 (1600) are the per-key initial")
out("                 values used when 0xB000/0xB600 are blank (0x33D0/0x33D8);")
out("                 0x8400 at 0x33E0 is a table *base*, not a value")
out(f"    per-key catalog      0x9600, 112 x 4 B (kind 2 = usage, kind 3 = special)")
out(f"                         0x9600: {win(0x9600, 16)}")
kinds = {}
for i in range(112):
    k = u8(0x9600 + 4 * i)
    kinds[k] = kinds.get(k, 0) + 1
out(f"    kind census          {kinds}")
k3 = next(i for i in range(112) if u8(0x9600 + 4 * i) == 3)
out(f"    first kind-3 record  #{k3}: {win(0x9600 + 4 * k3, 4)}")
out("    settings page        0xB000 + id*4 and 0xB600 + id*8 - erased/blank in the")
out("                         factory image, so defaults are synthesized in code")
out("    ownership: loader 0x58FE-0x5990 copies 0x8400/0x8500/0x9600/0xB000/0xB600")
out("    trap   editing 0xB000 is a *default* NVM page: a later settings save from")
out("           the companion app overwrites it; 0x9600 is read-only input.")

LED = [
    (0x16FF6, 12, "W pair table (12 pairs)"),
    (0x170B9, 0x17354 - 0x170B9, "ramp/fade tables (arithmetic byte ramps)"),
    (0x174B9, 16, "cell records, 16 B stride (semantics open)"),
    (0x17668, 12, "palette triplets: ff0000 ff8000 ffff00"),
    (0x17837, 0x17A60 - 0x17837, "RGB hue ramp: ff0000, ff0100, ff0200 ... ffff00"),
    (0x17A83, 14, "preset run x2: c8 96 64 4b 19 19 / c8 96 64 4b 28 28"),
    (0x17E38, 0x17F00 - 0x17E38, "per-profile hues + 01 1d headers"),
]
out("")
out("[5] lighting - data tables the LED engine reads")
for off, n, note in LED:
    out(f"    {hx(off)}  {n:>5d} B  {note}")
    out(f"              {win(off, min(n, 16))}")
out("    trap   0x170B9..0x17354 is *mixed* data+literals; a wrong edit breaks the")
out("           ramp engine rather than just recoloring. The palette, the RGB hue")
out("           ramp and the preset run are pure values -- safest first targets.")

out("")
out("[6] the catalog's two record kinds, byte-exact")
out("    kind 2 carries a HID usage in bytes 2-3; kind 3 carries a firmware")
out("    function in bytes 1-2. Editing a kind-3 record re-targets a special key")
out("    (volume, backlight, OS switch) instead of a typed character.")

# ===========================================================================
# P2  code constants
# ===========================================================================
out("")
out("=" * 78)
out("= P2  CODE CONSTANTS (Thumb-2; these are instructions, not table entries)")
out("=" * 78)

out("")
out("[A] actuation state machine 0x32AC - initialization + tracked value")
disasm(0x33C0, 0x33F0, {
    0x33D0: "seed 0x960 (2400) into [sb+id*2] (per-key rest/peak array)",
    0x33D8: "seed 0x640 (1600) into [r8+id*2]",
    0x33E0: "flash table base 0x8400 (per-key u16 defaults), not a value",
    0x3348: "flag bit15 of u16 @0x200031AE = actuated",
})

out("")
out("[B] value/threshold compare with hysteresis")
disasm(0x3750, 0x3774, {0x3764: "hysteresis 0xC (12 counts)"})

out("")
out("[C] per-key change filter 0x5498 - hold timer and commit delta")
disasm(0x54A0, 0x54F0, {0x54A8: "reload 0x1388 (5000) on no change", 0x54AE: "commit at |delta| >= 0xA"})

out("")
out("[D] per-OS Fn trigger codes and the mode-byte writers 0x2AE4")
disasm(0x2B20, 0x2B90, {
    0x2B26: "trigger compare 0xAC = D (Mac)",
    0x2B2A: "trigger compare 0xAB = S (Windows)",
    0x2B2E: "trigger compare 0x9C = A (Android)",
    0x2B3C: "writes mode byte [obj+0x26] = 1 (Mac)",
    0x2B5E: "writes mode byte = 0 (Windows)",
    0x2B80: "writes mode byte = 3 (Android); mode 2 has no writer",
})

# ===========================================================================
# P3  gates a patch must respect
# ===========================================================================
out("")
out("=" * 78)
out("= P3  IMAGE-SIDE GATES")
out("=" * 78)
out("")
out("[L] length")
out(f"    image is {len(img)} B; the tool's RCDATA size gate compares the loaded")
out("    size against 0x8400 for chip records whose field0 == 0 (analysis/isp_gate.py,")
out("    fn 0x427120 @0x4272BD). Patching in place keeps the length, so the gate's")
out("    verdict is identical to the stock flow's; only *growing* the image can trip")
out("    it. Do not pad or truncate.")
out("")
out("[V] version word")
out("    The upload flow (fn 0x401100 @0x40144C..0x401486) compares a dword of the")
out("    image against the four version bytes the device reports, and refuses with")
out("    'Firmware Version is not for this chip!!' on mismatch. The dword index")
out("    comes from the chip record (+0x1F -> +0xD), i.e. it is a fixed image")
out("    offset for a given chip. Every target in P1 sits at 0x16A96 or above;")
out("    keep the head of the image (below the first table) byte-identical to be")
out("    safe, and diff the patched file against the stock one before flashing.")
out("")
out("[C] checksum")
out("    No checksum field lives in the image (verified: sum16/sum32/crc32/negsum16")
out("    over five window shapes, every 4-aligned offset -> no hits). The tool")
out("    recomputes from the file it loaded (0x40A800 big-endian 16-bit word sum;")
out("    0x40A7D0 32-bit byte sum), so a patched image is self-consistent; the")
out("    displayed value changes and that is expected.")
out("")
out("[S] signature")
out("    None observed: the Authenticode signature covers the exe, not RCDATA 4000,")
out("    and no signature check appears in the upload path. The bootloader lives")
out("    outside the 0x7E000 app span, so an interrupted write is the failure mode")
out("    to plan for, not a rejected patch.")

out("")
out("targets: 3 data hooks + 5 LED ranges + 4 code constant sites; all byte edits,")
out("no relocation, no length change, nothing above needs a rebuild.")

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"report: {len(lines)} lines -> {REPORT.name}")
