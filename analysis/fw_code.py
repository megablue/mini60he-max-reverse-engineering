#!/usr/bin/env python3
"""fw_code.py - phase-4 static Thumb code walk of the RCDATA-4000 image.

Input : analysis/out/rcdata_4000.bin (written by probe_pe.py from the pinned exe)
Output: analysis/out/fw_code.txt + console summary

Read-only, static: capstone Thumb disassembly and byte statistics only. No device.

Checks (plan phase 4):
1. Image asserts + zero-gap verification (the gaps split the code).
2. Vector table dump.
3. Recursive-descent Thumb disassembly from every vector handler, the known
   island at 0xAE10, and every direct branch target. Falls back to a tolerant
   linear sweep over bytes no traversal reached, so uncovered code is reported
   instead of silently ignored.
4. Register/literal tracking inside each function: literal loads (LDR [pc,#..]),
   MOVW/MOVT and MOV immediate feed load/store operands -> peripheral, RAM and
   flash-table access sites (matrix-scan-loop hunt + table-band consumers).
5. Key-id -> HID-usage converter hunt: sliding-window scorer over the image for
   a >=61-slot dense usage table (values 0x04..0x67 / E0..E7), plus functions
   with large compare chains against 1..0x3D.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[1]
IMG = ROOT / "analysis" / "out" / "rcdata_4000.bin"
OUT = ROOT / "analysis" / "out"
REPORT = OUT / "fw_code.txt"

lines: list[str] = []


def out(*a):
    line = " ".join(str(x) for x in a)
    lines.append(line)
    print(line)


img = IMG.read_bytes()
assert len(img) == 0x7E000, len(img)
assert img[0x7DFFC:0x7E000] == bytes([0x55, 0x55, 0xAA, 0xAA]), "tail magic"

REGIONS = (
    (0x00000, 0x09810, "main code"),
    (0x0AE10, 0x0B000, "island"),
    (0x0BA00, 0x185E8, "usb/band"),
)

for lo, hi, name in (
    (0x9810, 0xAE10, "gap1"),
    (0xB000, 0xBA00, "gap2"),
):
    nonz = [i for i in range(lo, hi) if img[i]]
    out(f"gap check {name} 0x{lo:05X}-0x{hi:05X}: "
        + ("ALL ZERO" if not nonz else f"FIRST NONZERO 0x{nonz[0]:04X} value 0x{img[nonz[0]]:02X}"))


def r32(off: int) -> int | None:
    if off < 0 or off + 4 > len(img):
        return None
    return int.from_bytes(img[off:off + 4], "little")


def in_region(a: int) -> bool:
    return any(lo <= a < hi for lo, hi, _ in REGIONS)


def region_of(a: int) -> str:
    for lo, hi, name in REGIONS:
        if lo <= a < hi:
            return name
    return "outside"


# ===========================================================================
# 1. vector table
# ===========================================================================
sp = r32(0)
out(f"SP initial 0x{sp:08X}")

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
md.detail = True

# The table has zero holes (unimplemented IRQs), so scan a fixed window instead
# of stopping at the first zero dword.
vecs: list[tuple[int, int]] = []
for i in range(1, 0x40):
    v = r32(i * 4)
    if v is None:
        break
    if v and (v & 1) and in_region(v & ~1):
        vecs.append((i - 1, v & ~1))
out(f"vector entries: {len(vecs)} (non-zero thumb pointers in dwords 1..0x3F)")
for i, a in vecs:
    out(f"  vec[{i:3d}] 0x{a:05X}  ({region_of(a)})")


def one(addr: int):
    for ins in md.disasm(bytes(img[addr:addr + 4]), addr):
        return ins
    return None


def reg_name(r: int) -> str:
    try:
        return md.reg_name(r) or f"r{r}"
    except Exception:
        return f"r{r}"


def classify(t: int) -> str:
    if 0x40000000 <= t < 0x50000000:
        return "periph"
    if 0x20000000 <= t < 0x20010000:
        return "ram"
    if 0 <= t < 0x7E000:
        return "flash"
    return "const"


stubs = []
real_seeds = []
for i, a in vecs:
    ins = one(a)
    if ins and ins.mnemonic == "b" and ins.operands and ins.operands[0].type == capstone.arm.ARM_OP_IMM \
            and int(ins.operands[0].imm) == a:
        stubs.append(a)
    else:
        real_seeds.append(a)
stubs = sorted(set(stubs))
out(f"handlers: {len(set(real_seeds))} real, {len(stubs)} 'b .' self-loop stubs "
    f"at {', '.join('0x%05X' % s for s in stubs)}")

# ===========================================================================
# 2. recursive-descent disassembly (fixpoint: branch targets + literal pointers)
# ===========================================================================
fn_starts: set[int] = set(real_seeds) | {0xAE10}
# also seed every aligned dword in the image that looks like a Thumb code pointer:
# the firmware dispatches through RAM/literal function-pointer tables, so bl-only
# reachability covers a quarter of the code.
ptr_seeds = set()
for lo, hi, name in REGIONS:
    for off in range(lo, hi - 3, 2):
        v = r32(off)
        if v and (v & 1) and in_region(v & ~1) and (v & ~1) >= 0x1C0:
            ptr_seeds.add(v & ~1)
out(f"thumb-pointer seeds from raw dwords: {len(ptr_seeds)}")
fn_starts |= ptr_seeds
ins_by_addr: dict[int, tuple[int, str, str]] = {}
visited: set[int] = set()
skipped: set[int] = set()

BRANCH = {"b", "bl", "blx", "bx", "cbz", "cbnz"}
STOP = {"bx", "tbb", "tbh", "udf", "svc"}
CODE_PTRS: set[int] = set()
pending: set[int] = set(fn_starts)

while pending:
    worklist = list(pending)
    pending = set()
    while worklist:
        addr = worklist.pop() & ~1
        if addr in visited or not in_region(addr):
            continue
        guard = 0
        while in_region(addr) and addr not in visited:
            guard += 1
            if guard > 60000:
                out(f"!! traversal guard at 0x{addr:05X}")
                break
            visited.add(addr)
            ins = one(addr)
            if ins is None:
                # data halfword inside a code run (literal pool, jump table)
                skipped.add(addr)
                addr += 2
                continue
            ins_by_addr[addr] = (ins.size, ins.mnemonic, ins.op_str)
            m = ins.mnemonic
            ops = ins.operands
            # literal-pool value that points at code -> possible function entry
            if m == "ldr" and ops and ops[0].type == capstone.arm.ARM_OP_REG:
                mem = next((o for o in ops if o.type == capstone.arm.ARM_OP_MEM), None)
                if mem is not None and reg_name(mem.mem.base) == "pc":
                    la = ((addr + 4) & ~3) + mem.mem.disp
                    v = r32(la)
                    if v and (v & 1) and in_region(v & ~1) and abs((v & ~1) - la) < 0x40000:
                        p = v & ~1
                        if p not in visited:
                            pending.add(p)
                            fn_starts.add(p)
            tgt = None
            if ops and ops[0].type == capstone.arm.ARM_OP_IMM and m in BRANCH:
                tgt = int(ops[0].imm)
            if tgt is not None and in_region(tgt) and (tgt & 1) == 0:
                if m in ("bl", "blx"):
                    fn_starts.add(tgt)
                    pending.add(tgt)
                elif tgt not in visited:
                    worklist.append(tgt)
            if m in ("bl", "blx"):
                pass  # fall through after a call
            elif m == "b":
                break  # unconditional: no fallthrough
            elif m in STOP:
                break
            elif m == "pop" and "pc" in ins.op_str:
                break
            addr += ins.size

fn_starts = {a for a in fn_starts if a in ins_by_addr}
out(f"\nrecursive descent: {len(ins_by_addr)} instructions in {len(fn_starts)} function starts, "
    f"{len(skipped)} undecodable halfwords stepped over")

# coverage accounting
for lo, hi, name in REGIONS:
    covered = sum(s for a, (s, _, _) in ins_by_addr.items() if lo <= a < hi)
    out(f"  {name:10s} 0x{lo:05X}-0x{hi:05X}  insn-bytes 0x{covered:05X} / 0x{hi - lo:05X}"
        f"  ({100.0 * covered / (hi - lo):5.1f}%)")

# ===========================================================================
# 3. linear fallback sweep: what the traversal did not reach
# ===========================================================================
sweep_extra: dict[int, int] = {}
for lo, hi, name in REGIONS:
    addr = lo
    while addr < hi:
        if addr in ins_by_addr:
            addr += ins_by_addr[addr][0]
            continue
        ins = one(addr)
        if ins is None:
            addr += 2
            continue
        sweep_extra[addr] = ins.size
        addr += ins.size
out(f"linear sweep on unreached bytes: {len(sweep_extra)} more decoded instructions")
runs = []
run = []
for a in sorted(sweep_extra):
    if run and a != run[-1] + sweep_extra[run[-1]]:
        runs.append(run)
        run = []
    run.append(a)
if run:
    runs.append(run)
big = [(r[0], r[-1] + sweep_extra[r[-1]]) for r in runs if len(r) >= 16]
out(f"unreached decoded runs >=16 insns: {len(big)}")
for a, b in big[:40]:
    out(f"  run 0x{a:05X}-0x{b:05X} ({b - a} bytes)")

# ===========================================================================
# 4. per-function literal/register tracking -> memory access sites
# ===========================================================================
LOAD = {"ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrd"}
STORE = {"str", "strb", "strh", "strd"}
LOAD_M = LOAD | STORE

access: list[tuple[int, str, str, int, str]] = []  # addr, ins, base, target, kind
lit_values: Counter = Counter()
lit_sites: list[tuple[int, int, int]] = []  # addr, literal_addr, value


fn_bounds = sorted(fn_starts)
code_addrs = sorted(ins_by_addr)
fn_of: dict[int, int] = {}
cur = None
for a in code_addrs:
    if a in fn_starts:
        cur = a
    fn_of[a] = cur

reg_val: dict[str, int] = {}
for addr in code_addrs:
    size, mnem, ops = ins_by_addr[addr]
    if addr in fn_starts:
        reg_val = {}
    if mnem in ("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh"):
        # literal load? detect from operands, not from the op_str prefix
        ins = one(addr)
        mem = next((o for o in ins.operands if o.type == capstone.arm.ARM_OP_MEM), None)
        if mem is not None and reg_name(mem.mem.base) == "pc" and mem.mem.index == 0:
            la = ((addr + 4) & ~3) + mem.mem.disp
            v = r32(la)
            lit_sites.append((addr, la, v if v is not None else -1))
            dst = reg_name(ins.operands[0].reg)
            reg_val[dst] = v if v is not None else -1
            if v is not None:
                lit_values[v] += 1
            continue
    if mnem in ("movw", "movt", "mov", "movs", "add", "adds", "sub", "subs"):
        ins = one(addr)
        dst = reg_name(ins.operands[0].reg) if ins.operands and ins.operands[0].type == capstone.arm.ARM_OP_REG else None
        if dst:
            base = None
            imm = 0
            for o in ins.operands[1:]:
                if o.type == capstone.arm.ARM_OP_REG and o.shift.type == 0:
                    base = reg_name(o.reg)
                elif o.type == capstone.arm.ARM_OP_IMM:
                    imm = int(o.imm)
            if mnem == "movt":
                old = reg_val.get(dst, 0)
                if old >= 0:
                    reg_val[dst] = ((imm & 0xFFFF) << 16) | (old & 0xFFFF)
                continue
            if mnem in ("mov", "movs") and base is None:
                reg_val[dst] = imm
                continue
            if base and base in reg_val and mnem.startswith("add"):
                reg_val[dst] = reg_val[base] + imm
                continue
            if base and base in reg_val and mnem.startswith("sub"):
                reg_val[dst] = reg_val[base] - imm
                continue
            reg_val.pop(dst, None)
            continue
    ins = one(addr)
    if mnem in LOAD_M:
        memop = None
        for o in ins.operands:
            if o.type == capstone.arm.ARM_OP_MEM:
                memop = o
                break
        if memop is not None:
            b = reg_name(memop.mem.base)
            idxr = reg_name(memop.mem.index) if memop.mem.index else None
            if idxr is None and b in reg_val and reg_val[b] >= 0:
                t = reg_val[b] + memop.mem.disp
                access.append((addr, f"{mnem} {ops}", b, t, classify(t)))
        # destination values are unknown unless the load was a literal (handled above)
        if mnem in LOAD:
            dst = reg_name(ins.operands[0].reg) if ins.operands and ins.operands[0].type == capstone.arm.ARM_OP_REG else None
            if dst:
                reg_val.pop(dst, None)
        continue
    # any other write clobbers its operands
    try:
        writes, _ = ins.regs_access()
    except Exception:
        writes = []
    for r in writes:
        nm = reg_name(r)
        if nm not in ("pc",):
            reg_val.pop(nm, None)

out(f"\nliteral loads: {len(lit_sites)}")
pc_vals = [v for v in lit_values if 0 <= v < 0x7E000]
out(f"  literals pointing inside image (flash/table pointers): {len(pc_vals)} distinct")
per = [(a, t) for a, la, t in lit_sites if 0x40000000 <= t < 0x50000000]
out(f"  literals pointing at peripherals: {len(per)} sites, {len({t for _, t in per})} distinct")


def hist(kind):
    return Counter(t for _, _, _, t, k in access if k == kind)


out(f"\naccess sites: total {len(access)}  "
    f"periph {sum(1 for s in access if s[4] == 'periph')}  "
    f"ram {sum(1 for s in access if s[4] == 'ram')}  "
    f"flash {sum(1 for s in access if s[4] == 'flash')}")

out("\nperipheral target histogram (value x count):")
for v, n in hist("periph").most_common(40):
    out(f"  0x{v:08X}  x{n}")

out("\nRAM target histogram (top 50):")
for v, n in hist("ram").most_common(50):
    out(f"  0x{v:08X}  x{n}")

band = [s for s in access if s[4] == "flash" and 0x16000 <= s[3] < 0x18000]
out(f"\nflash-table access sites inside the 0x16000-0x18000 band: {len(band)}")
for addr, ins_s, b, t, _ in band:
    out(f"  0x{addr:05X}: {ins_s:26s} -> 0x{t:05X}")

# functions touching peripherals, for the scan-loop hunt
fn_periph = defaultdict(set)
for addr, _, _, t, k in access:
    if k == "periph":
        fn_periph[fn_of[addr]].add(t)
out(f"\nfunctions that touch peripherals: {len(fn_periph)}")
for f, ts in sorted(fn_periph.items()):
    out(f"  fn 0x{f:05X}  {len(ts)} targets: {', '.join('0x%08X' % t for t in sorted(ts))}")

out("\nall peripheral access sites (chronological):")
for addr, ins_s, b, t, k in access:
    if k == "periph":
        out(f"  0x{addr:05X}: {ins_s:30s} base={b:4s} tgt=0x{t:08X}  fn 0x{fn_of[addr]:05X}")

# ===========================================================================
# 5. HID usage table hunt
# ===========================================================================
VALID = set(range(0x04, 0x68)) | set(range(0xE0, 0xE8))
cands = []
for start in range(0, len(img) - 0x3D):
    n = 0
    while start + n < len(img) and img[start + n] in VALID and n < 0x80:
        n += 1
    if n >= 0x3D:
        cands.append((start, n))
# collapse overlapping windows, keep the widest
merged = []
for s, n in cands:
    if merged and s <= merged[-1][0] + merged[-1][1]:
        if s + n > merged[-1][0] + merged[-1][1]:
            merged[-1] = (merged[-1][0], s + n - merged[-1][0])
    else:
        merged.append((s, n))
out(f"\nHID-usage-density runs >=0x3D bytes: {len(merged)}")
for s, n in merged[:30]:
    out(f"  0x{s:05X} len {n:3d} region={region_of(s)}")

# compare chains against key-id range
fn_cmp = defaultdict(list)
for addr, (size, mnem, ops) in ins_by_addr.items():
    if mnem in ("cmp", "cmn") and "#" in ops:
        try:
            v = int(ops.split("#")[1].split(",")[0], 0)
        except (IndexError, ValueError):
            continue
        if 1 <= v <= 0x3D:
            fn_cmp[fn_of[addr]].append((addr, v))
out("\nfunctions with >=6 compares against 1..0x3D (converter / key-count loops):")
for f, hits in sorted(fn_cmp.items(), key=lambda kv: -len(kv[1])):
    if len(hits) >= 6:
        out(f"  fn 0x{f:05X}  {len(hits)} hits, values {sorted({v for _, v in hits})}")

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
out(f"\n[report written: {REPORT.name}]")
