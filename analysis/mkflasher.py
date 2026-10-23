"""mkflasher.py - wrap an arbitrary firmware image into a copy of the vendor updater.

    python analysis/mkflasher.py <image.bin> [--out analysis/out/NAME.exe]

What it does:
  * verifies the vendor exe (SHA-256 pin) and finds the RCDATA 4000 blob by
    walking the resource tree (no hardcoded file offset),
  * checks the replacement image fits the slot exactly (same length, so the
    Authenticode overlay, section table and the tool's own size gate are unchanged),
  * writes the patched exe + a manifest .txt beside it, and prints a diff summary.

The Authenticode signature covers the exe, so the copy is unsigned/invalid once the
blob changes - the vendor tool still runs, it simply shows an invalid signature.
Read-only with respect to any device: nothing here talks to the keyboard.
"""
import argparse
import hashlib
import struct
import sys
from pathlib import Path

import pefile

ROOT = Path(__file__).resolve().parent
BASE_EXE = ROOT.parent / "bin" / "MINI 60 HE MAX_V1.52.exe"
BASE_SHA = "958a39951d2f908a7fe925e0fa598c321924cb235239bf37484ae7c8213512d6"
RT_RCDATA = 10
FW_ID = 0xFA0
FW_LEN = 0x7E000
TAIL_MAGIC = 0xAAAA5555


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def find_rcdata(pe, want_id):
    """[(id, file_offset, size)] for every RT_RCDATA entry"""
    found = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_RESOURCE", []).entries:
        if entry.id != RT_RCDATA:
            continue
        for item in entry.directory.entries:
            for leaf in item.directory.entries:
                data = leaf.data.struct
                found.append((item.id, pe.get_offset_from_rva(data.OffsetToData), data.Size))
    return found


def main(argv=None):
    ap = argparse.ArgumentParser(description="wrap a firmware image into the vendor updater")
    ap.add_argument("image", type=Path, help="firmware image (.bin) to embed")
    ap.add_argument("--out", type=Path, help="output exe (default: out/<image stem>.exe)")
    ap.add_argument("--base", type=Path, default=BASE_EXE, help="vendor updater to patch")
    ap.add_argument("--allow-length", action="store_true",
                    help="permit an image that is not 0x7E000 bytes (shifts the file layout)")
    args = ap.parse_args(argv)

    base = args.base.read_bytes()
    if args.base.resolve() == BASE_EXE.resolve():
        if sha256(base) != BASE_SHA:
            return fail("vendor exe SHA-256 changed:\n  expected %s\n  got      %s" % (BASE_SHA, sha256(base)))
    else:
        print("note: non-default base exe, SHA-256 pin not enforced")

    image = args.image.read_bytes()
    if len(image) != FW_LEN and not args.allow_length:
        return fail("image is %d bytes, slot is %d (0x%X); pass --allow-length to override"
                    % (len(image), FW_LEN, FW_LEN))
    if len(image) >= 4:
        magic = struct.unpack_from("<I", image, len(image) - 4)[0]
        if magic != TAIL_MAGIC:
            print("warning: tail dword is 0x%08X, stock image ends with 0x%08X" % (magic, TAIL_MAGIC))

    pe = pefile.PE(data=base, fast_load=False)
    blobs = find_rcdata(pe, FW_ID)
    if not blobs:
        return fail("no RT_RCDATA resources found")
    match = [b for b in blobs if b[0] == FW_ID]
    if not match:
        return fail("RCDATA id 0x%X missing; ids present: %s" % (FW_ID, [hex(b[0]) for b in blobs]))
    _rid, off, size = match[0]
    if size != len(image):
        return fail("RCDATA 0x%X is %d bytes at file 0x%X, image is %d" % (FW_ID, size, off, len(image)))
    if base[off:off + size] == image:
        print("note: image is byte-identical to the embedded one - output would equal the base")

    out = bytearray(base)
    out[off:off + size] = image
    diff = [i for i in range(len(base)) if base[i] != out[i]]
    outside = [i for i in diff if not (off <= i < off + size)]
    if outside:
        return fail("internal error: %d diffs outside the slot" % len(outside))

    dst = args.out or (ROOT / "out" / (args.image.stem + ".exe"))
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(bytes(out))

    try:
        check = pefile.PE(data=bytes(out), fast_load=True)
        sections = len(check.sections)
    except Exception as exc:  # pragma: no cover - defensive
        return fail("patched exe does not parse: %s" % exc)

    manifest = [
        "mkflasher manifest",
        "base exe  : %s (%d bytes, sha256 %s)" % (args.base.name, len(base), sha256(base)),
        "image     : %s (%d bytes, sha256 %s)" % (args.image.name, len(image), sha256(image)),
        "slot      : RT_RCDATA 0x%X at file 0x%X, %d bytes" % (FW_ID, off, size),
        "out exe   : %s (%d bytes, sha256 %s)" % (dst.name, len(out), sha256(bytes(out))),
        "diffs     : %d bytes" % len(diff),
        "diff offs : %s" % " ".join("0x%06X" % d for d in diff[:256]),
        "pe        : parses, %d sections" % sections,
        "signature : Authenticode overlay left untouched -> invalid signature on this copy",
        "gate note : same length, so the tool's RCDATA size gate verdict is unchanged",
    ]
    (dst.with_suffix(".txt")).write_text("\n".join(manifest) + "\n", encoding="utf-8")

    print("\n".join(manifest))
    return 0


def fail(msg):
    print("error:", msg)
    return 2


if __name__ == "__main__":
    sys.exit(main())
