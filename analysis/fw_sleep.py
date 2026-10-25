#!/usr/bin/env python3
"""fw_sleep.py - does the millisecond tick survive the low-power state?

Input : analysis/out/rcdata_4000.bin (written by probe_pe.py from the pinned exe)
Output: analysis/out/fw_sleep.txt + console summary

Read-only, static. No device, nothing executed.

Motivation: the wireless dead-window stub (fw_deadwin.py) decided "we just woke
up" from our own wall-clock gap -- now - last_key >= 30 s -- on the ms counter
at 0x200004A8. On hardware the predicate never became true: the keyboard typed
normally straight through the wake window. One testable explanation is that the
counter stops advancing while the MCU is asleep, so after a wake the gap reads
~0 and the window is never armed.

Checks:
1. Tick block census: every 4-aligned literal in the image that names
   0x200004A4..0x200004B0, plus every code site that touches 0x200004A8
   (base register tracked through ldr [pc,#..] / movw+movt).
2. SysTick / SCB census: literal-named 0xE000E000..0xE000E020 and
   0xE000ED00..0xE000ED20, with the same base tracking.
3. Low-power census: every wfi/wfe in the image and whether SysTick's ENABLE
   bit is cleared anywhere.
4. The tick handler 0x3FE8 and its callers (who feeds the counter).
"""
from __future__ import annotations

from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[1]
IMG = ROOT / "analysis" / "out" / "rcdata_4000.bin"
OUT = ROOT / "analysis" / "out"
REPORT = OUT / "fw_sleep.txt"

lines: list[str] = []


def out(*a):
    line = " ".join(str(x) for x in a)
    lines.append(line)
    print(line)


img = IMG.read_bytes()
assert len(img) == 0x7E000, len(img)
assert img[0x7DFFC:0x7E000] == bytes([0x55, 0x55, 0xAA, 0xAA]), "tail magic"

REGIONS = (
    (0x00000, 0x09810, "main"),
    (0x0AE10, 0x0B000, "island"),
    (0x0BA00, 0x185E8, "band"),
)

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
md.detail = True
MEM = capstone.arm.ARM_OP_MEM
IMM = capstone.arm.ARM_OP_IMM
REG = capstone.arm.ARM_OP_REG


def r32(off: int) -> int | None:
    if off < 0 or off + 4 > len(img):
        return None
    return int.from_bytes(img[off:off + 4], "little")


def in_code(a: int) -> bool:
    return any(lo <= a < hi for lo, hi, _ in REGIONS)


TICK_LO, TICK_HI = 0x200004A4, 0x200004B0
SYS_LO, SYS_HI = 0xE000E000, 0xE000E020
SCB_LO, SCB_HI = 0xE000ED00, 0xE000ED20


def interesting(ea: int) -> str | None:
    if TICK_LO <= ea < TICK_HI:
        return "tick"
    if SYS_LO <= ea < SYS_HI:
        return "systick"
    if SCB_LO <= ea < SCB_HI:
        return "scb"
    return None


# ---------------------------------------------------------------------------
# 1. literal census (4-aligned dwords inside the code regions)
# ---------------------------------------------------------------------------
out("=" * 72)
out("1. literal census for the tick block")
out("=" * 72)
pool_hits = []
for lo, hi, _ in REGIONS:
    for off in range(lo & ~3, hi, 4):
        v = r32(off)
        if v is not None and TICK_LO <= v < TICK_HI:
            pool_hits.append((off, v))
for off, v in pool_hits:
    out(f"  literal 0x{off:05X} = 0x{v:08X}")
out(f"  [{len(pool_hits)} literal(s)]")


# ---------------------------------------------------------------------------
# 2./3. sweep with light register tracking
# ---------------------------------------------------------------------------
def sweep(lo: int, hi: int):
    """Linear Thumb sweep -> list of (addr, mnemonic, op_str, size)."""
    insns = []
    addr = lo
    while addr < hi:
        got = next(iter(md.disasm(bytes(img[addr:addr + 4]), addr)), None)
        if got is None:
            addr += 2
            continue
        insns.append(got)
        addr += got.size
    return insns


def reg_name(ins, r: int) -> str:
    try:
        return ins.reg_name(r) or f"r{r}"
    except Exception:
        return f"r{r}"


def track(insns, want: str):
    """Follow ldr [pc,#] / movw+movt into base registers, report mem operands."""
    hits = []
    val: dict[str, int] = {}
    for ins in insns:
        m, ops = ins.mnemonic, ins.operands
        keep: set[str] = set()
        # literal load into a register
        if m in ("ldr", "ldr.w") and len(ops) == 2 and ops[1].type == MEM:
            mem = ops[1].mem
            if reg_name(ins, mem.base) == "pc" and mem.index == 0:
                la = ((ins.address + 4) & ~3) + mem.disp
                v = r32(la)
                if v is not None and ops[0].type == REG:
                    val[reg_name(ins, ops[0].reg)] = v
                    keep.add(reg_name(ins, ops[0].reg))
        elif m in ("movw", "mov.w") and len(ops) == 2 and ops[1].type == IMM:
            if ops[0].type == REG:
                val[reg_name(ins, ops[0].reg)] = ops[1].imm & 0xFFFF
                keep.add(reg_name(ins, ops[0].reg))
        elif m == "movt" and len(ops) == 2 and ops[1].type == IMM:
            if ops[0].type == REG:
                r = reg_name(ins, ops[0].reg)
                val[r] = ((val.get(r, 0) & 0xFFFF) | ((ops[1].imm & 0xFFFF) << 16))
                keep.add(r)
        # report memory accesses whose base we resolved
        if len(ops) >= 2 and ops[1].type == MEM:
            mem = ops[1].mem
            base = reg_name(ins, mem.base)
            if base in val and mem.index == 0:
                ea = val[base] + mem.disp
                kind = interesting(ea)
                if kind == want:
                    hits.append((ins.address, m, ins.op_str, ea))
        # a write to any register invalidates what we knew about it
        try:
            _, writes = ins.regs_access()
        except Exception:
            writes = ()
        for r in writes:
            n = reg_name(ins, r)
            if n != "pc" and n not in keep:
                val.pop(n, None)
    return hits


def show_hits(title: str, hits):
    out("")
    out(title)
    for a, m, o, ea in hits:
        out(f"  0x{a:05X}: {m:8s} {o:34s} -> 0x{ea:08X}")


all_ins = []
for lo, hi, name in REGIONS:
    got = sweep(lo, hi)
    out(f"  sweep {name:7s} 0x{lo:05X}-0x{hi:05X}: {len(got)} insns")
    all_ins.extend(got)

show_hits("2. code sites touching the tick block", track(all_ins, "tick"))

out("")
out("=" * 72)
out("3. SysTick / SCB accesses")
out("=" * 72)
show_hits("   SysTick (0xE000E0xx)", track(all_ins, "systick"))
show_hits("   SCB (0xE000EDxx)", track(all_ins, "scb"))

out("")
out("=" * 72)
out("4. low-power instructions")
out("=" * 72)
wfi = [(i.address, i.mnemonic) for i in all_ins if i.mnemonic in ("wfi", "wfe", "sev")]
for a, m in wfi:
    out(f"  0x{a:05X}: {m}")
out(f"  [{len(wfi)} hit(s)]")

out("")
out("=" * 72)
out("5. callers of the tick handler 0x3FE8 / getter 0x3F08 / 0x3F14")
out("=" * 72)
for target in (0x3FE8, 0x3F08, 0x3F14):
    callers = []
    for ins in all_ins:
        if ins.mnemonic in ("bl", "b", "b.w", "blx") and ins.operands:
            o = ins.operands[0]
            if o.type == IMM and o.imm == target:
                callers.append((ins.address, ins.mnemonic))
    out(f"  0x{target:05X}: " + (", ".join(f"0x{a:05X} {m}" for a, m in callers) or "no direct caller"))
    for a, m in callers:
        lo = max(0x00000, a - 0x10)
        out(f"    context around 0x{a:05X}:")
        for ins in all_ins:
            if lo <= ins.address <= a + 0x8:
                out(f"      0x{ins.address:05X}: {ins.mnemonic:8s} {ins.op_str}")

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"\n[written {REPORT}]")
