#!/usr/bin/env python3
"""fw_fallback.py - take the factory-usage fallback out of the key handler.

    python analysis/fw_fallback.py                  # CapsLock, current device base
    python analysis/fw_fallback.py --dry-run
    python analysis/fw_fallback.py --base analysis/out/fw_bake3.bin --name fb2

Why this shape
--------------
The 2026-10-25 wake test settled the shape of the leak: it is ONE event, not a
window. Waking with the macro key types CapsLock; pressing the same key again
immediately runs the macro. Waking with Fn held absorbs the leak invisibly,
because Fn's own factory usage is a state-only code that emits nothing.

So the tables are correct a few milliseconds later, and the very first event
after a wireless wake is handled while the per-key record is still empty. In
0x5D28 that state is the kind==0 && settings==0 branch at 0x5E66, which falls
into 0x5E80 and emits the FACTORY usage staged from 0x16B3E at 0x5D4A. For the
macro key the factory usage is 0x39 - CapsLock - and that is the whole leak.

Earlier builds tried to drop reports on a clock and were structurally inert
(no wfi in the poll loop, so the ms tick never stops; the only self-reset is the
HardFault path, so an uptime window is never true at a wake). This one has no
clock and no state: it removes the fallback itself.

The three edits
---------------
1. 0x16B3E + 18 = 0x00     position 18 (the scan grid maps it to id 0x30) no
                           longer stages a factory usage at all.
2. 0x5D54 = nop;nop;nop    the `cmp.w fp,#0 / beq 0x5E56` bail would otherwise
                           drop the key before its record is read. It exists for
                           positions with no factory usage: all 67 zero bytes of
                           0x16B3E are non-physical positions, so removing it is
                           inert for every real key.
3. 0x5E80 = b.w 0x5EA4     the empty-record branch jumps straight to the exit
                           instead of emitting the staged factory byte.

Net effect: a key whose per-key record is empty emits nothing, and a configured
macro still runs because the record path is untouched. Wired is unchanged, the
arrow bake underneath is preserved, and the Fn overlays are untouched.

Cost, stated plainly: Fn + this key no longer produces CapsLock, because that
path read the same factory byte. That is the trade accepted on 2026-10-25.

Gates: length unchanged, tail magic, everything below the scan grid byte-identical,
only position 18 loses its factory usage, the hook from the previous build is
left alone, and the version word stays below everything we touch.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import capstone

SCRIPT_DIR = Path(__file__).resolve().parent
OUT = SCRIPT_DIR / "out"

IMG_LEN = 0x7E000
TAIL = 0x7DFFC
SCAN_GRID = 0x16A96          # position -> key id (128 bytes)
STAGED = 0x16B3E             # position -> factory usage (128 bytes)
LAYER0 = 0x16C3E             # Windows Fn overlay, 51 rows of 2 bytes
CATALOG = 0x9600             # id -> 4-byte record
KEY_ID = 0x30                # CapsLock
KEY_USAGE = 0x39

BAIL = 0x5D54                # cmp.w fp,#0 ; beq 0x5E56
BAIL_BYTES = bytes.fromhex("bbf1000f7dd0")
BAIL_PATCH = bytes.fromhex("00bf00bf00bf")   # nop ; nop ; nop

EMPTY = 0x5E80               # kind==0 && settings==0 -> emit factory usage
EMPTY_BYTES = bytes.fromhex("962a10d3")      # cmp r2,#0x96 ; blo 0x5EA6
EMPTY_PATCH = bytes.fromhex("00f010b8")      # b.w 0x5EA4 (exit)

KNOWN_BASES = {
    "617eef7f4bb4cd5ceecaaee5d4d54124836f9ba63691b17185e094c3c744cd16":
        "arrow-cluster bake (fw_build.py's acceptance image)",
    "4dd3201cae72e7d4974731d9c300797255236399ea014479467a4261e0f3d4bb":
        "arrow bake + inert dead-window stub (the image on the device)",
    "0eb37a76f741c824b8c96a9405fbb6a868ce658941799b1cf5252c9fcefc0e02":
        "macro guard, clock-free (fw_macroguard.py's image)",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fail(msg: str) -> int:
    print("FAIL:", msg)
    return 1


def disasm(data: bytes, at: int, n: int = 8):
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    return list(md.disasm(data[at:at + 0x40], at))[:n]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", type=Path, default=OUT / "fw_deadwin_remap.bin",
                    help="image to patch (default: the image on the device)")
    ap.add_argument("--name", default="fw_fallback")
    ap.add_argument("--out-dir", type=Path, default=OUT)
    ap.add_argument("--no-exe", action="store_true")
    ap.add_argument("--allow-any-base", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    if not args.base.exists():
        return fail(f"{args.base} does not exist - run the earlier builders first")

    img = bytearray(args.base.read_bytes())
    if len(img) != IMG_LEN:
        return fail(f"base is {len(img):#x} bytes, expected {IMG_LEN:#x}")
    if bytes(img[TAIL:TAIL + 4]) != bytes.fromhex("5555aaaa"):
        return fail("tail magic is not 55 55 AA AA - not the firmware image")
    base_sha = sha256(img)
    print(f"base     : {args.base.name} {IMG_LEN} bytes {base_sha}")
    if base_sha not in KNOWN_BASES and not args.allow_any_base:
        return fail(f"unrecognised base {base_sha}; pass --allow-any-base if that is"
                    " the image you really mean")
    if base_sha in KNOWN_BASES:
        print(f"           {KNOWN_BASES[base_sha]}")

    # ---- what the base already says -------------------------------------
    positions = [p for p in range(128) if img[SCAN_GRID + p] == KEY_ID]
    if positions != [18]:
        return fail(f"scan grid maps id 0x{KEY_ID:02X} to positions {positions},"
                    " expected the single position 18")
    pos = positions[0]
    if img[STAGED + pos] != KEY_USAGE:
        return fail(f"factory usage at position {pos} is 0x{img[STAGED + pos]:02X},"
                    f" expected 0x{KEY_USAGE:02X}")
    cat = bytes(img[CATALOG + KEY_ID * 4:CATALOG + KEY_ID * 4 + 4])
    if cat != bytes([2, 0, KEY_USAGE, 0]):
        return fail(f"catalog record for id 0x{KEY_ID:02X} is {cat.hex(' ')}")
    if bytes(img[BAIL:BAIL + 6]) != BAIL_BYTES:
        return fail(f"0x{BAIL:05X} is {bytes(img[BAIL:BAIL + 6]).hex(' ')},"
                    f" expected {BAIL_BYTES.hex(' ')}")
    if bytes(img[EMPTY:EMPTY + 4]) != EMPTY_BYTES:
        return fail(f"0x{EMPTY:05X} is {bytes(img[EMPTY:EMPTY + 4]).hex(' ')},"
                    f" expected {EMPTY_BYTES.hex(' ')}")

    # Every physical position must still stage a usage; only the patched one may
    # go silent, otherwise removing the bail would wake dead scan slots.
    physical = [p for p in range(128) if img[SCAN_GRID + p] != 0x7D]
    zeros = [p for p in physical if img[STAGED + p] == 0]
    if zeros:
        return fail(f"physical positions already without a factory usage: {zeros}")
    # Every non-physical position stages 0x00; that is exactly what the 0x5D54
    # bail was guarding, and it is why removing the bail cannot wake a dead slot.
    stray = [p for p in range(128)
             if img[SCAN_GRID + p] == 0x7D and img[STAGED + p] != 0]
    if stray:
        return fail(f"non-physical positions staging a usage: {stray}")
    layer0_rows = [r for r in range(51) if img[LAYER0 + r * 2] == KEY_USAGE]
    if layer0_rows:
        return fail(f"layer0 already has a row keyed 0x{KEY_USAGE:02X}: {layer0_rows}")

    # ---- apply -----------------------------------------------------------
    patched = bytearray(img)
    patched[STAGED + pos] = 0x00
    patched[BAIL:BAIL + 6] = BAIL_PATCH
    patched[EMPTY:EMPTY + 4] = EMPTY_PATCH

    changed = [i for i in range(IMG_LEN) if img[i] != patched[i]]
    allowed = set(range(BAIL, BAIL + 6)) | set(range(EMPTY, EMPTY + 4)) | {STAGED + pos}
    outside = [c for c in changed if c not in allowed]
    if outside:
        return fail(f"bytes changed outside the three edits: {[hex(c) for c in outside]}")
    if STAGED + pos not in changed:
        return fail("the factory usage byte did not change")
    if len(patched) != IMG_LEN:
        return fail("length changed")
    if bytes(patched[TAIL:TAIL + 4]) != bytes.fromhex("5555aaaa"):
        return fail("tail magic changed")
    if bytes(patched[:0x5000]) != bytes(img[:0x5000]):
        return fail("something below 0x5000 changed (vector table / version word band)")

    # ---- prove the patch means what we say -------------------------------
    bail = disasm(patched, BAIL, 4)
    if [(i.mnemonic, i.op_str) for i in bail[:3]] != [("nop", ""), ("nop", ""), ("nop", "")]:
        return fail(f"0x{BAIL:05X} does not disassemble as three nops: {[(i.mnemonic, i.op_str) for i in bail]}")
    empty = disasm(patched, EMPTY, 2)
    if (empty[0].mnemonic, empty[0].op_str) != ("b.w", "#0x5ea4"):
        return fail(f"0x{EMPTY:05X} is {empty[0].mnemonic} {empty[0].op_str}")
    if not empty[0].size == 4:
        return fail("the replacement at 0x5E80 must be one 4-byte instruction")

    log: list[str] = []

    def p(*a):
        line = " ".join(str(x) for x in a)
        print(line)
        log.append(line)

    p("")
    p("the leak")
    p("  first event after a wireless wake is handled while the per-key record is")
    p("  still empty -> 0x5E66 kind==0 && settings==0 -> 0x5E80 emits the factory")
    p(f"  usage staged from 0x16B3E[{pos}] = 0x{KEY_USAGE:02X} (CapsLock).")
    p("  the next event sees the loaded record, which is why only one key leaks.")
    p("")
    p("the edits")
    p(f"  0x{STAGED + pos:05X}  {KEY_USAGE:02x} -> 00     position {pos} (id 0x{KEY_ID:02X}) stages no usage")
    p(f"  0x{BAIL:05X}  {BAIL_BYTES.hex(' ')} -> {BAIL_PATCH.hex(' ')}")
    p("           cmp.w fp,#0 / beq 0x5E56 removed: the record is still read")
    p(f"  0x{EMPTY:05X}  {EMPTY_BYTES.hex(' ')} -> {EMPTY_PATCH.hex(' ')}  b.w 0x5EA4")
    p("           the empty-record branch exits instead of emitting")
    p("")
    p("why it is safe")
    p("  67 zero factory bytes exist, all of them non-physical positions: the bail")
    p("  only ever guarded slots the scan grid never produces.")
    p("  every physical position still has a usage except position 18, by design.")
    p(f"  layer0 has no row keyed 0x{KEY_USAGE:02X}, so Fn mapping is untouched (it")
    p("  simply loses the CapsLock passthrough for this key - the accepted trade).")
    p("")
    p("gates    : length unchanged; tail magic; below 0x5000 identical; hook 0x127E0")
    p("           untouched; checksum recomputed tool-side; version word untouched")
    p(f"diff     : {len(changed)} bytes vs the base")
    p("")

    dst_bin = args.out_dir / f"{args.name}.bin"
    dst_exe = args.out_dir / f"{args.name}.exe"
    dst_txt = args.out_dir / f"{args.name}_build.txt"
    p("out image:", dst_bin.name, IMG_LEN, "bytes", sha256(bytes(patched)))
    if args.dry_run:
        p("dry run  : nothing written")
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    dst_bin.write_bytes(bytes(patched))
    p("written  :", dst_bin)

    if not args.no_exe:
        import mkflasher
        if mkflasher.main([str(dst_bin), "--out", str(dst_exe)]) != 0:
            return fail("mkflasher refused the image; see the message above")
        p("out exe  :", dst_exe.name, dst_exe.stat().st_size, "bytes",
          sha256(dst_exe.read_bytes()))

    dst_txt.write_text("\n".join(log) + "\n", encoding="utf-8")
    p("report   :", dst_txt)
    p("")
    p("test     : after the flash the macro has to be re-entered (the write erases")
    p("           the settings pages). Then:")
    p("             wired     - the key runs the macro; nothing else changed")
    p("             wireless  - wake with this key: it types NOTHING (no CapsLock)")
    p("             wireless  - press it again: the macro runs")
    p("             wireless  - other keys unaffected; arrow cluster unaffected")
    p("           If the CapsLock still appears, the leak is not this branch, and the")
    p("           next read is the kind==2 record path at 0x5ECC instead.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
