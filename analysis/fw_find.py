#!/usr/bin/env python3
"""fw_find.py - pattern search over a linear Thumb disassembly of the fw image.

Usage: python analysis/fw_find.py "<regex>" [--ctx N] [--max N] [--region main|band|all]

The linear sweep is a reconnaissance aid: a match is a lead, not a fact. Each
hit prints N instructions of context either side so the neighbouring code can
be judged directly. Addresses are image file offsets (== flash offsets).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[1]
img = (ROOT / "analysis" / "out" / "rcdata_4000.bin").read_bytes()
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
md.detail = True

REGIONS = {
    "main": (0x0000, 0x09810),
    "island": (0x0AE10, 0x0B000),
    "band": (0x0BA00, 0x185E8),
    "all": None,
}


def sweep(lo: int, hi: int):
    ins = []
    addr = lo
    while addr < hi:
        got = next(iter(md.disasm(bytes(img[addr:addr + 4]), addr)), None)
        if got is None:
            addr += 2
            continue
        ins.append((got.address, got.mnemonic, got.op_str, got.size))
        addr += got.size
    return ins


def main(argv):
    if not argv:
        print(__doc__)
        return 1
    pat = re.compile(argv[0], re.I)
    ctx = 6
    maxhits = 30
    region = "all"
    i = 1
    while i < len(argv):
        if argv[i] == "--ctx":
            ctx = int(argv[i + 1]); i += 2
        elif argv[i] == "--max":
            maxhits = int(argv[i + 1]); i += 2
        elif argv[i] == "--region":
            region = argv[i + 1]; i += 2
        else:
            i += 1
    regs = REGIONS[region]
    if regs is None:
        spans = [(0x0000, 0x09810), (0x0AE10, 0x0B000), (0x0BA00, 0x185E8)]
    else:
        spans = [regs]
    hits = 0
    for lo, hi in spans:
        ins = sweep(lo, hi)
        for idx, (a, m, o, s) in enumerate(ins):
            if pat.search(f"{m} {o}"):
                hits += 1
                if hits > maxhits:
                    print(f"... stopping at {maxhits} hits")
                    return 0
                print(f"\n=== hit {hits}: 0x{a:05X}  {m} {o}")
                for k in range(max(0, idx - ctx), min(len(ins), idx + ctx + 1)):
                    b, bm, bo, _ = ins[k]
                    mark = ">>" if k == idx else "  "
                    print(f" {mark} {b:05X}: {bm:8s} {bo}")
    print(f"\n[{hits} hits]")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
