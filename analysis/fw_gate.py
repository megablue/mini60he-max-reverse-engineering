#!/usr/bin/env python3
"""fw_gate.py - ignore the record-kind dispatch gate at 0x37E2 (first-press probe).

    python analysis/fw_gate.py --dry-run
    python analysis/fw_gate.py

The first press after a wireless wake types the factory usage of the key (once
CapsLock) instead of running the macro that key carries. Reading the dispatcher
showed why that is possible:

    0x37E2  ldr r0,=0x2000008F
    0x37E4  ldrb r0,[r0]
    0x37E6  cbz r0, 0x37F0          ; zero -> dispatch by the per-key record kind
    0x37E8  pop.w {...}             ; non-zero -> straight to the generic handler
    0x37EC  b.w 0x5D28

    0x37F0  ldr r0,[sp,#8]          ; record kind
            kind 9 / 0xA -> 0x5A00
            kind 0xB / 0xC -> 0x7500
            anything else -> 0x5D28

So one byte decides whether a macro key is treated as a macro at all. Nothing in
the image writes 0x2000008F directly (three sweeps: literal-based stores, taint
of add/mov, and calls with an argument in that block), so the writer is indirect
and cannot be pinned cheaply. This probe tests the gate instead of chasing it:

    0x37E6  18 B1  cbz r0, 0x37F0
    0x37E6  03 E0  b   0x37F0        ; always dispatch by record kind

Two bytes, nothing else. If the wake leak's "first press" is really this gate,
the macro runs on the first press after a wake. If something else depends on the
gate (Fn chords over media records, for instance), that shows up in wired mode
immediately, which is why the ladder starts there.

Revert path: reflash the released image (ecb236fb...) or the vendor exe.
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
GATE_LDR = 0x37E2          # ldr r0,=0x2000008F
GATE_BYTES = bytes.fromhex("1d48007818b1")   # ldr / ldrb / cbz r0, 0x37F0
GATE_OFF = 0x37E6          # the cbz itself
GATE_PATCH = bytes.fromhex("03e0")           # b 0x37F0

KNOWN_BASES = {
    "ecb236fb447298891582426603b880288e3994119cdabf0b20dded8a465db517":
        "released image (arrow bake + wake fix + Fn+Left = VolDown)",
}


def sha256(d: bytes) -> str:
    return hashlib.sha256(d).hexdigest()


def fail(msg: str) -> int:
    print("FAIL:", msg)
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", type=Path,
                    default=OUT / "release" / "mini60he_max_remap.bin")
    ap.add_argument("--name", default="fw_gate")
    ap.add_argument("--out-dir", type=Path, default=OUT)
    ap.add_argument("--no-exe", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    if not args.base.exists():
        return fail(f"{args.base} not found - build the release image first")
    img = bytearray(args.base.read_bytes())
    if len(img) != IMG_LEN:
        return fail(f"base is {len(img):#x} bytes, expected {IMG_LEN:#x}")
    if bytes(img[TAIL:TAIL + 4]) != bytes.fromhex("5555aaaa"):
        return fail("tail magic is not 55 55 AA AA")
    base_sha = sha256(img)
    print(f"base     : {args.base.name} {base_sha}")
    if base_sha not in KNOWN_BASES:
        return fail("unrecognised base; pass the released image")
    print(f"           {KNOWN_BASES[base_sha]}")

    if bytes(img[GATE_LDR:GATE_LDR + 6]) != GATE_BYTES:
        return fail(f"0x{GATE_LDR:05X} is {bytes(img[GATE_LDR:GATE_LDR + 6]).hex(' ')},"
                    f" expected {GATE_BYTES.hex(' ')}")

    patched = bytearray(img)
    patched[GATE_OFF:GATE_OFF + 2] = GATE_PATCH
    changed = [i for i in range(IMG_LEN) if img[i] != patched[i]]
    if changed != [GATE_OFF, GATE_OFF + 1]:
        return fail(f"diff is {[hex(c) for c in changed]}, expected exactly the cbz")
    if len(patched) != IMG_LEN or bytes(patched[TAIL:TAIL + 4]) != bytes.fromhex("5555aaaa"):
        return fail("length or tail magic changed")
    if bytes(patched[:0x1000]) != bytes(img[:0x1000]):
        return fail("something below 0x1000 changed (vector table / version word band)")

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    ins = list(md.disasm(bytes(patched[GATE_LDR:GATE_LDR + 0x10]), GATE_LDR))
    got = [(i.address, i.mnemonic, i.op_str) for i in ins[:3]]
    want = [(GATE_LDR, "ldr", "r0, [pc, #0x74]"),
            (GATE_LDR + 2, "ldrb", "r0, [r0]"),
            (GATE_LDR + 4, "b", "#0x37f0")]
    if got != want:
        return fail(f"patched disassembly is {got}, expected {want}")

    log: list[str] = []

    def p(*a):
        line = " ".join(str(x) for x in a)
        print(line)
        log.append(line)

    p("")
    p("the gate")
    p("  0x2000008F != 0  -> every event goes to 0x5D28, the generic handler")
    p("  0x2000008F == 0  -> events dispatch by record kind")
    p("  no direct writer exists in the image; three sweeps found none")
    p("")
    p("the probe")
    p(f"  0x{GATE_OFF:05X}  {bytes(img[GATE_OFF:GATE_OFF + 2]).hex(' ')} -> {GATE_PATCH.hex(' ')}"
      "   cbz r0,0x37F0 -> b 0x37F0")
    p("  record kind decides the handler for every event, always")
    p("")
    p("read it like this")
    p("  wired, Fn+Right/Fn+Left/Fn+1 and the macro still work  -> the gate is safe to ignore")
    p("  wired, any of those changes                          -> the gate has a purpose, stop here")
    p("  wireless wake with the macro key runs the macro      -> the gate WAS the first-press cause")
    p("  wireless still types CapsLock or nothing             -> the gate is not the cause")
    p("")
    p(f"diff     : {len(changed)} bytes vs the base")
    p("")

    dst_bin = args.out_dir / f"{args.name}.bin"
    dst_exe = args.out_dir / f"{args.name}.exe"
    txt = args.out_dir / f"{args.name}_build.txt"
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
            return fail("mkflasher refused the image")
        p("out exe  :", dst_exe.name, dst_exe.stat().st_size, "bytes",
          sha256(dst_exe.read_bytes()))
    txt.write_text("\n".join(log) + "\n", encoding="utf-8")
    p("report   :", txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
