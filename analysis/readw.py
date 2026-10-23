#!/usr/bin/env python3
"""readw.py - print raw UTF-16LE strings from the pinned exe (scratch helper).

    python analysis/readw.py 0x588E38 [count]

Prints `count` wide strings starting at the given file VA (one per line,
hex va first). Read-only bytes.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "bin" / "MINI 60 HE MAX_V1.52.exe"

base = 0x400000
import pefile
raw = EXE.read_bytes()
pe = pefile.PE(data=raw)
ib = pe.OPTIONAL_HEADER.ImageBase


def va_to_off(va):
    rva = va - ib
    return pe.get_offset_from_rva(rva)


def wstr(off, maxc=64):
    out = []
    while len(out) < maxc:
        w = int.from_bytes(raw[off:off + 2], "little")
        if w == 0:
            break
        out.append(chr(w) if 0x20 <= w < 0xFFF0 else f"<{w:04X}>")
        off += 2
    return "".join(out)


def main():
    va = int(sys.argv[1], 0)
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    off = va_to_off(va)
    for i in range(count):
        s = wstr(off)
        print(f"0x{va:06X}: {s!r}")
        off += 2 * (len(s) + 1)
        va = ib + (pe.get_rva_from_offset(off))


if __name__ == "__main__":
    main()
