#!/usr/bin/env python3
"""fw_armgate.py - stop the inner gate in 0x5A00 from diverting the macro arm.

    python analysis/fw_armgate.py --dry-run
    python analysis/fw_armgate.py

Evidence trail: the release build silences the first press after a wireless wake
by clearing the staged factory usage at 0x16B50; putting that byte back brings
CapsLock back even with the empty-record branch still exiting, so the staged byte
is emitted downstream of whatever handler ran. A capture at 0x5E80 never fired.
Together that says the macro key's record is a macro kind, so its handler is
0x5A00, not 0x5D28.

0x5A00 has its own inner gate:

    0x5A9E  add.w r2,r2,#0xB000
    0x5AA2  ldrb  r2,[r2]        ; per-key byte in the settings page
    0x5AA4  cbz   r2, 0x5AAE     ; no settings -> normal path
    0x5AA6  ldr   r2,=0x2000008F
    0x5AA8  ldrb  r2,[r2]
    0x5AAA  cmp   r2,#0
    0x5AAC  bne   0x5B18         ; <- diversion
    0x5AAE  ...                  ; the arming path

So a key that HAS settings is diverted whenever 0x2000008F is non-zero, and the
diverted path never arms the macro. This build removes the diversion:

    0x5AAC  34 D1  bne 0x5B18  ->  00 BF  nop

Two bytes. When 0x2000008F is zero nothing changes; when it is set, a configured
key takes the arming path instead of the alternative.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
OUT = SCRIPT_DIR / "out"

IMG_LEN = 0x7E000
TAIL = 0x7DFFC
OFF = 0x5AAC
WANT = bytes.fromhex("34d1")
PATCH = bytes.fromhex("00bf")

KNOWN = {
    "ecb236fb447298891582426603b880288e3994119cdabf0b20dded8a465db517":
        "released image (arrow bake + wake fix + Fn+Left = VolDown)",
}


def sha256(d: bytes) -> str:
    return hashlib.sha256(d).hexdigest()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", type=Path,
                    default=OUT / "release" / "mini60he_max_remap.bin")
    ap.add_argument("--name", default="fw_armgate")
    ap.add_argument("--out-dir", type=Path, default=OUT)
    ap.add_argument("--no-exe", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    img = bytearray(args.base.read_bytes())
    if len(img) != IMG_LEN or bytes(img[TAIL:TAIL + 4]) != bytes.fromhex("5555aaaa"):
        print("FAIL: not the firmware image")
        return 1
    base = sha256(img)
    print(f"base     : {args.base.name} {base}")
    if base not in KNOWN:
        print("FAIL: unrecognised base")
        return 1
    if bytes(img[OFF:OFF + 2]) != WANT:
        print(f"FAIL: 0x{OFF:05X} is {bytes(img[OFF:OFF + 2]).hex(' ')},"
              f" expected {WANT.hex(' ')}")
        return 1

    patched = bytearray(img)
    patched[OFF:OFF + 2] = PATCH
    changed = [i for i in range(IMG_LEN) if img[i] != patched[i]]
    if changed != [OFF, OFF + 1]:
        print(f"FAIL: diff {[hex(c) for c in changed]}")
        return 1
    if bytes(patched[:0x1000]) != bytes(img[:0x1000]):
        print("FAIL: something below 0x1000 changed")
        return 1

    print("")
    print(f"  0x{OFF:05X}  {WANT.hex(' ')} -> {PATCH.hex(' ')}"
          "   bne 0x5B18 -> nop")
    print("  a configured key now takes the arming path even when 0x2000008F is set")
    print("")
    print("out image:", IMG_LEN, "bytes", sha256(bytes(patched)))
    if args.dry_run:
        return 0

    dst_bin = args.out_dir / f"{args.name}.bin"
    dst_exe = args.out_dir / f"{args.name}.exe"
    dst_bin.write_bytes(bytes(patched))
    print("written  :", dst_bin)
    if not args.no_exe:
        import mkflasher
        if mkflasher.main([str(dst_bin), "--out", str(dst_exe)]) != 0:
            return 1
        print("out exe  :", dst_exe.name, dst_exe.stat().st_size, "bytes",
              sha256(dst_exe.read_bytes()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
