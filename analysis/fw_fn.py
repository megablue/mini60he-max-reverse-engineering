#!/usr/bin/env python3
"""fw_fn.py - dump disassembly of functions from the RCDATA-4000 image.

Usage: python analysis/fw_fn.py 0x57F8 [0x588C ...]
       python analysis/fw_fn.py --range 0x5100 0x5300
       python analysis/fw_fn.py --fn 0x57F8 --bytes 0x200

Read-only. Prints Thumb-2 disassembly with pc-relative literal values resolved,
so register-setup idioms (`ldr r0,[pc,#8]` -> 0x40038008) are readable.
"""
from __future__ import annotations

import sys
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[1]
IMG = ROOT / "analysis" / "out" / "rcdata_4000.bin"
img = IMG.read_bytes()
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
md.detail = True


def r32(off: int) -> int | None:
    if off < 0 or off + 4 > len(img):
        return None
    return int.from_bytes(img[off:off + 4], "little")


def rn(r: int) -> str:
    try:
        return md.reg_name(r) or f"r{r}"
    except Exception:
        return f"r{r}"


def dump(start: int, end: int):
    print(f"--- 0x{start:05X} .. 0x{end:05X}")
    addr = start
    while addr < end:
        ins = next(iter(md.disasm(bytes(img[addr:addr + 4]), addr)), None)
        if ins is None:
            print(f"{addr:05X}: .hword 0x{int.from_bytes(img[addr:addr + 2], 'little'):04X}")
            addr += 2
            continue
        note = ""
        mem = next((o for o in ins.operands if o.type == capstone.arm.ARM_OP_MEM), None)
        if mem is not None and rn(mem.mem.base) == "pc" and mem.mem.index == 0:
            la = ((addr + 4) & ~3) + mem.mem.disp
            v = r32(la)
            note = f"   ; [0x{la:05X}] = 0x{v:08X}" if v is not None else ""
        print(f"{addr:05X}: {ins.mnemonic:8s} {ins.op_str:44s}{note}")
        addr += ins.size


def main(argv: list[str]):
    if not argv:
        print(__doc__)
        return 1
    if argv[0] == "--range":
        dump(int(argv[1], 0), int(argv[2], 0))
        return 0
    if argv[0] == "--fn":
        n = int(argv[2], 0) if len(argv) > 2 else 0x100
        dump(int(argv[1], 0), int(argv[1], 0) + n)
        return 0
    for a in argv:
        start = int(a, 0)
        # crude extent: next 4-byte-aligned literal/word boundary is unknown, use 0x120
        dump(start, min(start + 0x120, len(img)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
