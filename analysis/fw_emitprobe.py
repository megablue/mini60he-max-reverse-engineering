#!/usr/bin/env python3
"""fw_emitprobe.py - where does the first-press CapsLock actually get emitted?

    python analysis/fw_emitprobe.py --dry-run
    python analysis/fw_emitprobe.py

The release build silences the first press after a wireless wake by clearing the
factory usage at 0x16B50 (position 18) and making the empty-record branch exit at
0x5E80. The deferred-press build then captured at 0x5E80 and replayed - and it
stayed silent, which suggests the first event never takes that branch.

This probe restores the factory byte (0x16B50 = 0x39) and changes nothing else:

  * if CapsLock comes back on the first press, the staged byte is emitted
    somewhere downstream of 0x5D28 (the dispatcher reads 0x2000008C after the
    handler returns), so the capture site was wrong and belongs before 0x5D4A;
  * if it stays silent, 0x5E80 really is the emitter, the capture site was right,
    and the replay failed for another reason.

One byte. Nothing else moves.
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
OFF = 0x16B50                 # 0x16B3E + 18, the macro key's scan position
CUR = 0x00
NEW = 0x39

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
    ap.add_argument("--name", default="fw_emitprobe")
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
    if img[OFF] != CUR:
        print(f"FAIL: 0x{OFF:05X} is {img[OFF]:02x}, expected {CUR:02x}")
        return 1

    patched = bytearray(img)
    patched[OFF] = NEW
    changed = [i for i in range(IMG_LEN) if img[i] != patched[i]]
    if changed != [OFF]:
        print(f"FAIL: diff {[hex(c) for c in changed]}")
        return 1

    print("")
    print(f"  0x{OFF:05X}  {CUR:02x} -> {NEW:02x}"
          "   the factory usage is back (CapsLock for the macro key)")
    print("  0x5E80 stays the exit; 0x5D54 stays three nops; nothing else moves")
    print("")
    print("read it like this")
    print("  first press after a wireless wake types CapsLock -> the staged byte is")
    print("      emitted downstream of 0x5D28; the capture site was wrong")
    print("  first press stays silent -> 0x5E80 really is the emitter; the replay")
    print("      failed for a different reason")
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
