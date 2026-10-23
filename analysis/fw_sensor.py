#!/usr/bin/env python3
"""fw_sensor.py - hunt the sensor front end that fills the per-key arrays.

Input : analysis/out/rcdata_4000.bin (RCDATA 4000 firmware image, pinned exe)
Output: analysis/out/fw_sensor.txt

Read-only, static. No device, no exe execution.

Question (open item): which code samples the analog/contact sensors and writes
the per-id u16 value array 0x2000376E / threshold array 0x200030AE that the
actuation state machine at 0x32AC compares?

Approach:
1. Linear Thumb sweep of the code regions; resolve every PC-relative literal
   load and MOVW/MOVT pair. Report every literal in RAM 0x20002000..0x20004000
   together with the code sites that load it (these are the array base
   registers the earlier displacement work saw).
2. For a chosen base literal, list the loads/stores done through it with
   immediate offsets inside the next 0x40 bytes of code, so the stride and
   direction (read vs write) are visible.
3. Dump candidate functions named by the caller analysis (0x106B0 sampler,
   0x57F8 / 0x6D70 GPIO init) for a hand read.

Usage: python analysis/fw_sensor.py [--dump 0x106B0 0x200] [--base 0x200030AE]
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[1]
IMG = ROOT / "analysis" / "out" / "rcdata_4000.bin"
OUT = ROOT / "analysis" / "out" / "fw_sensor.txt"

img = IMG.read_bytes()
assert len(img) == 0x7E000, len(img)

REGIONS = (
    (0x00000, 0x09810),
    (0x0AE10, 0x0B000),
    (0x0BA00, 0x185E8),
)

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
md.detail = True

lines: list[str] = []


def out(*a):
    line = " ".join(str(x) for x in a)
    lines.append(line)
    print(line)


def r32(off: int) -> int | None:
    if off < 0 or off + 4 > len(img):
        return None
    return int.from_bytes(img[off:off + 4], "little")


def in_code(a: int) -> bool:
    return any(lo <= a < hi for lo, hi in REGIONS)


def region_name(a: int) -> str:
    if 0x20000000 <= a < 0x20008000:
        return "RAM"
    if 0x40000000 <= a < 0x50000000:
        return "PERIPH"
    if in_code(a):
        return "FLASH-code"
    if 0x0BA00 <= a < 0x185E8:
        return "FLASH-band"
    return "other"


# ---------------------------------------------------------------------------
# pass 1: literal / movw+movt resolution over the whole image
# ---------------------------------------------------------------------------
sites: list[tuple[int, int, str]] = []  # (code site, target, how)
literal_sites: dict[int, list[int]] = defaultdict(list)

addr = 0x0
end = 0x185E8
while addr < end:
    if not in_code(addr):
        addr += 2
        continue
    ins = next(iter(md.disasm(bytes(img[addr:addr + 4]), addr)), None)
    if ins is None:
        addr += 2
        continue
    # pc-relative literal load
    if ins.mnemonic.startswith("ldr") and "[pc" in ins.op_str:
        tgt = None
        mem = next((o for o in ins.operands if o.type == capstone.arm.ARM_OP_MEM), None)
        if mem is not None and md.reg_name(mem.mem.base) == "pc":
            la = ((addr + 4) & ~3) + mem.mem.disp
            tgt = r32(la)
        if tgt is not None:
            tgt &= 0xFFFFFFFF
            literal_sites[tgt].append(addr)
            sites.append((addr, tgt, "ldr-lit"))
    addr += ins.size

RAM_LO, RAM_HI = 0x20002000, 0x20004000
arrays = {k: v for k, v in literal_sites.items() if RAM_LO <= k < RAM_HI}
out(f"== pass 1: {len(literal_sites)} distinct literal targets, "
    f"{sum(len(v) for v in literal_sites.values())} load sites")
out(f"== RAM array-band literals 0x{RAM_LO:08X}..0x{RAM_HI:08X}: {len(arrays)}")
for tgt in sorted(arrays):
    out(f"  base 0x{tgt:08X}  loads: " + " ".join(f"0x{a:05X}" for a in sorted(arrays[tgt])))

# ---------------------------------------------------------------------------
# pass 2: accesses through a chosen base literal
# ---------------------------------------------------------------------------
TARGET_BASES = [0x200030AE, 0x2000376E, 0x200031AE, 0x200028AE,
                0x20003A16, 0x20003B16]

out("")
out("== pass 2: nearest base literal at or below each array, and its access sites")
# The arrays are reached as base + byte offset, so the loaded literal is the
# array start or a nearby struct start. Match any base within 0x800 below.
all_lit = {k: v for k, v in literal_sites.items()}
for arr in TARGET_BASES:
    cands = sorted(k for k in all_lit if arr - 0x800 <= k <= arr)
    out(f"-- array 0x{arr:08X}: {len(cands)} candidate bases in [0x{arr-0x800:08X}, 0x{arr:08X}]")
    for base in cands:
        off = arr - base
        out(f"   base 0x{base:08X} (delta +0x{off:X}) loaded at "
            + " ".join(f"0x{a:05X}" for a in sorted(all_lit[base])))


# ---------------------------------------------------------------------------
# pass 3: writer hunt - straight-line register tracking to find stores that
# land inside the per-key arrays (the sampler is whoever strh's into 0x376E)
# ---------------------------------------------------------------------------
INTEREST = {
    0x200028AE: "config records (8B/key)",
    0x200030AE: "threshold u16[128]",
    0x200031AE: "flags u16[128]",
    0x2000376E: "value u16[128]",
    0x20003A16: "state u16[128]",
    0x20003B16: "timer u16[128]",
}
WRITE_LO, WRITE_HI = 0x20002000, 0x20004100

out("")
out("== pass 3: straight-line register tracking, stores into the per-key arrays")
writes: list[tuple[int, int, str, str]] = []  # site, eff addr, mnemonic, func-hint


def track_block(start: int, stop: int):
    regs: dict[int, int] = {}
    a = start
    while a < stop:
        ins = next(iter(md.disasm(bytes(img[a:a + 4]), a)), None)
        if ins is None:
            regs.clear()
            a += 2
            continue
        m = ins.mnemonic
        ops = ins.operands
        if m == "ldr" and len(ops) == 2 and ops[1].type == capstone.arm.ARM_OP_MEM \
                and md.reg_name(ops[1].mem.base) == "pc" and ops[1].mem.index == 0:
            la = ((a + 4) & ~3) + ops[1].mem.disp
            v = r32(la)
            if v is not None:
                regs[ops[0].reg] = v
            else:
                regs.pop(ops[0].reg, None)
        elif m in ("movw", "mov") and len(ops) == 2 and ops[1].type == capstone.arm.ARM_OP_IMM:
            if m == "mov" and ops[0].reg in regs:
                regs[ops[0].reg] = regs[ops[0].reg] & 0xFFFF0000 | (ops[1].imm & 0xFFFF)
            else:
                regs[ops[0].reg] = ops[1].imm
        elif m == "movt" and len(ops) == 2 and ops[1].type == capstone.arm.ARM_OP_IMM:
            base = regs.get(ops[0].reg, 0)
            regs[ops[0].reg] = (base & 0xFFFF) | ((ops[1].imm & 0xFFFF) << 16)
        elif m in ("add", "adds", "add.w") and len(ops) == 3 \
                and ops[1].type == capstone.arm.ARM_OP_REG and ops[2].type == capstone.arm.ARM_OP_IMM \
                and ops[1].reg in regs:
            regs[ops[0].reg] = (regs[ops[1].reg] + ops[2].imm) & 0xFFFFFFFF
        elif m in ("sub", "subs") and len(ops) == 3 \
                and ops[1].type == capstone.arm.ARM_OP_REG and ops[2].type == capstone.arm.ARM_OP_IMM \
                and ops[1].reg in regs:
            regs[ops[0].reg] = (regs[ops[1].reg] - ops[2].imm) & 0xFFFFFFFF
        elif m.startswith("str") and ops and ops[-1].type == capstone.arm.ARM_OP_MEM:
            mem = ops[-1].mem
            base = regs.get(mem.base)
            if base is not None and 0 <= mem.disp < 0x400:
                # indexed store ([base, idx, lsl #1]) has a dynamic target, but
                # the base tells us which array it lands in.
                eff = base + mem.disp
                if WRITE_LO <= eff < WRITE_HI:
                    writes.append((a, eff, m + ("[idx]" if mem.index else ""), ""))
        elif m.startswith("ldr"):
            # loads are fine, but a load into a tracked reg invalidates it
            if ops and ops[0].type == capstone.arm.ARM_OP_REG:
                regs.pop(ops[0].reg, None)
        elif m in ("bl", "blx", "b", "bx", "cbz", "cbnz", "tbb", "tbh") \
                or m.startswith("b.") or m.startswith("it"):
            regs.clear()
        a += ins.size


a = 0
while a < 0x185E8:
    if not in_code(a):
        a += 2
        continue
    track_block(a, min(a + 0x400, 0x185E8))
    a += 0x400

seen = set()
for site, eff, m, _ in sorted(writes):
    key = (site, eff)
    if key in seen:
        continue
    seen.add(key)
    tag = ""
    for base, name in INTEREST.items():
        if base <= eff < base + 0x100:
            tag = f"{name} +0x{eff-base:X}"
            break
    out(f"  0x{site:05X}: {m:8s} -> 0x{eff:08X}  {tag}")
out(f"  stores in array band: {len(seen)}")

# ---------------------------------------------------------------------------
# pass 4: the sensor chain, decoded from the bytes it runs on
# ---------------------------------------------------------------------------
out("")
out("== pass 4: sensor chain facts")
# (a) the 16-channel read order: pairs of `ldr rX,[r4,#imm]` / `strh rX,[r0,#imm2]`
order: list[tuple[int, int]] = []
pend: tuple[int, int] | None = None
a = 0x1028
while a < 0x1072:
    ins = next(iter(md.disasm(bytes(img[a:a + 4]), a)), None)
    if ins is None:
        a += 2
        continue
    mem = next((o for o in ins.operands if o.type == capstone.arm.ARM_OP_MEM), None)
    if ins.mnemonic == "ldr" and mem is not None and md.reg_name(mem.mem.base) == "r4":
        pend = (mem.mem.disp, ins.operands[0].reg)
    elif ins.mnemonic.startswith("strh") and mem is not None and pend is not None \
            and ins.operands[0].reg == pend[1]:
        order.append((pend[0], mem.mem.disp // 2))
        pend = None
    a += ins.size
out(f"  channel read order ({len(order)} pairs): column -> peripheral offset")
out("   " + "  ".join(f"c{c}=+0x{off:02X}" for off, c in order))
assert [c for _, c in order] == list(range(16)), order

# (b) the per-row fill target and the id arithmetic
out("  raw matrix base 0x2000221E, row stride 0x20 bytes (16 x u16)")
out("  id = row + 8*col   (add.w r2, r0, r1, lsl #3 at 0x056E8)")
out("  sample gate: raw < 0x3E8 (1000) -> sample := 0x3E8 (0x05708)")

# (c) per-key filter record initialisation (fn 0x7E74)
f_eps = r32(0x07E9C)
f_w = r32(0x07EA4)
import struct
out(f"  calibration record 24 B/key @ 0x20001330: [0]=[+0x10]={struct.unpack('<f', f_eps.to_bytes(4,'little'))[0]:g}"
    f"  [+0x14]={struct.unpack('<f', f_w.to_bytes(4,'little'))[0]:g}  (+4/+8/+0xC = 0)")

# (d) the default tables the loader copies into RAM
for addr, name, stride, dest in (
    (0x8400, "press threshold u16", 2, 0x200030AE),
    (0x8500, "release threshold u16", 2, 0x200031AE),
    (0x9600, "4-byte key catalog", 4, 0x200024AE),
    (0xB000, "runtime settings (blank)", 4, 0x200026AE),
    (0xB600, "runtime profile byte (blank)", 8, 0x2000386E),
):
    vals = [img[addr + i * stride] for i in range(8)]
    out(f"  table 0x{addr:05X} -> 0x{dest:08X} stride {stride}: first bytes "
        + " ".join(f"{v:02X}" for v in vals))

# (e) scan position -> logical key id map at 0x16A96 (id = row + 8*col)
pos = img[0x16A96:0x16A96 + 128]
grid = [[pos[c * 8 + r] for c in range(16)] for r in range(8)]
keys = [v for v in pos if v != 0x7D]
out("  position map 0x16A96: 16 drive lines x 8 channels, index = channel + 8*drive")
out(f"    occupied positions: {len(keys)}  distinct ids: {len(set(keys))}")
assert len(keys) == 61 and len(set(keys)) == 61, (len(keys), len(set(keys)))
assert all(v < 0x79 for v in keys), max(keys)
for r in range(8):
    out(f"    channel{r} (one keyboard row, across drive lines): "
        + " ".join(f"{v:02X}" for v in grid[r]))

# (f) cross-check: every occupied position resolves through the usage table
tab = 0x16DDA
usage = {}
i = tab
prev = -1
while True:
    a, b = img[i], img[i + 1]
    if a <= prev or a > 0x78:       # ids ascend through 0x78, sentinel after
        break
    usage[a] = b
    prev = a
    i += 2
out(f"  usage table 0x{tab:05X}: {len(usage)} (id -> HID usage) entries, "
    f"ids 0x00..0x78 minus the gaps")
assert all(v in usage for v in keys), [hex(v) for v in keys if v not in usage]
out("  every occupied scan position resolves to a usage (assert held)")


def dump(start: int, nbytes: int):
    out("")
    out(f"--- disasm 0x{start:05X} .. 0x{start+nbytes:05X}")
    a = start
    stop = start + nbytes
    while a < stop:
        ins = next(iter(md.disasm(bytes(img[a:a + 4]), a)), None)
        if ins is None:
            out(f"{a:05X}: .hword 0x{int.from_bytes(img[a:a+2],'little'):04X}")
            a += 2
            continue
        note = ""
        mem = next((o for o in ins.operands if o.type == capstone.arm.ARM_OP_MEM), None)
        if mem is not None and md.reg_name(mem.mem.base) == "pc":
            la = ((a + 4) & ~3) + mem.mem.disp
            v = r32(la)
            if v is not None:
                note = f"   ; [0x{la:05X}] = 0x{v:08X} ({region_name(v)})"
        out(f"{a:05X}: {ins.mnemonic:8s} {ins.op_str:44s}{note}")
        a += ins.size


def callers(target: int):
    out("")
    out(f"== callers of 0x{target:05X}")
    hits = 0
    a = 0
    while a < 0x185E8:
        if not in_code(a):
            a += 2
            continue
        ins = next(iter(md.disasm(bytes(img[a:a + 4]), a)), None)
        if ins is None:
            a += 2
            continue
        if ins.mnemonic in ("bl", "b.w", "b") and ins.op_str.startswith("#"):
            try:
                t = int(ins.op_str[1:], 16)
            except ValueError:
                t = -1
            if t == target:
                out(f"  0x{a:05X}: {ins.mnemonic} 0x{target:05X}")
                hits += 1
        a += ins.size
    out(f"  {hits} site(s)")


def lit_report(addrs: list[int]):
    out("")
    out("== literal load sites for requested addresses")
    for a in addrs:
        sites_a = literal_sites.get(a, [])
        out(f"  0x{a:08X}: " + ("NONE" if not sites_a else
            " ".join(f"0x{s:05X}" for s in sorted(sites_a))))


def main(argv: list[str]):
    dump_requests: list[tuple[int, int]] = []
    caller_targets: list[int] = []
    lit_addrs: list[int] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--dump":
            dump_requests.append((int(argv[i + 1], 0), int(argv[i + 2], 0)))
            i += 3
        elif argv[i] == "--callers":
            caller_targets.append(int(argv[i + 1], 0))
            i += 2
        elif argv[i] == "--lit":
            lit_addrs.append(int(argv[i + 1], 0))
            i += 2
        else:
            i += 1
    if lit_addrs:
        lit_report(lit_addrs)
    for t in caller_targets:
        callers(t)
    for start, n in dump_requests:
        dump(start, n)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main(sys.argv[1:])
