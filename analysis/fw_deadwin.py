#!/usr/bin/env python3
"""fw_deadwin.py - wireless dead window: drop the first 2 s of keys after a wake.

    python analysis/fw_deadwin.py
    python analysis/fw_deadwin.py --base analysis/out/fw_bake3.bin --name fw_deadwin_menu
    python analysis/fw_deadwin.py --dry-run

What it builds (one hook, one stub, no table edits):

    0x127E0   4 bytes   b.w 0x20000       (replaces the stock push.w)
    0x20000  64 bytes   the stub + its three literal words

The stub runs before every key is staged into the HID report. In wireless mode it
keeps two dwords of its own (last key, armed): a press that comes at least 30 s
after the previous one is treated as a wake, and everything for the next 2 s is
dropped by returning early - nothing is staged, so nothing is sent. Wired mode
leaves through the first branch, so its path is byte-for-byte the stock one.

Why here: 0x127E0 is the single action-byte -> report converter. A plain key
reaches it by the dispatcher's tail branch at 0x147F8; the modifier/Fn kinds call
it from 0x5A00. The report itself is assembled later (0x15FC folds the staged
buffers, 0x10768 sends), so an early return is indistinguishable from "no key".

Why not a link hook: the module reply handler declares the link ready at 0x1EB2
(lighting 0x4B), but its call frequency is not provable statically, and arming
there could re-arm on every reply and mute the keyboard. The idle gap is our own
edge and can only ever expire.

What it does not do: it hides the factory binding, it does not stop the RF
settings replay that causes it, and it does not shorten it. Constants 2000/30000
are two immediates in the stub; the builder checks their encoding.

Gates: length unchanged, size gate unaffected, checksum recomputed tool-side,
version word untouched (0x127E0 was a function prologue, 0x20000 was zero fill).
No readback exists, so every test is a flash; the unmodified updater is the
revert path.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import capstone

SCRIPT_DIR = Path(__file__).resolve().parent
OUT = SCRIPT_DIR / "out"
IMG = OUT / "rcdata_4000.bin"

STOCK_SHA = "06A1A47432A6CA7EC060103378E2D984A46F9AFA98F19FCCD99219EAEA4A88E0"
IMG_LEN = 0x7E000
TAIL_MAGIC = 0xAAAA5555

HOOK = 0x127E0                 # entry of the action-byte -> HID report converter
STUB = 0x20000                 # blank flash, 0x18600-0x7DFFC band
STATE = 0x20000610             # two dwords of our own: [0] last key, [4] armed
MODE = 0x20000378              # transport object: 0 wired, 1/2 wireless
NOW = 0x200004A8               # SysTick millisecond counter

WINDOW_MS = 2000               # how long after a wake keys are dropped
IDLE_MS = 30000                # a gap at least this long counts as a wake
STUB_LEN = 0x40

STOCK_PUSH = bytes.fromhex("2de9f05f")      # push.w {r4-r11, ip, lr}
STOCK_NEXT = bytes.fromhex("614f624e")      # 0x127E4: ldr r7,[pc,#0x184]; ldr r6,[pc,#0x188]


def sha256(data) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def movw(rd: int, imm: int) -> bytes:
    """Thumb-2 MOVW (T3): imm16 = imm4:i:imm3:imm8."""
    assert 0 <= imm <= 0xFFFF and 0 <= rd <= 15
    imm16 = imm
    imm4 = (imm16 >> 12) & 0xF
    i = (imm16 >> 11) & 1
    imm3 = (imm16 >> 8) & 7
    imm8 = imm16 & 0xFF
    hw1 = 0xF240 | (i << 10) | imm4
    hw2 = (imm3 << 12) | (rd << 8) | imm8
    return hw1.to_bytes(2, "little") + hw2.to_bytes(2, "little")


def build_stub(window_ms: int = WINDOW_MS, idle_ms: int = IDLE_MS) -> bytes:
    """The stub, instruction by instruction, plus its literal pool.

    Layout: code 0x00-0x33, literals 0x34-0x3f. The three literal loads all use
    imm8 = 0x0b, because the pool sits 0x2c bytes past each Align(PC, 4).
    """
    ops: list[bytes] = [
        STOCK_PUSH,                                  # 0x00 push.w {r4-r11, ip, lr}
        bytes.fromhex("0b48"),                       # 0x04 ldr  r0, [pc, #0x2c]  -> MODE
        bytes.fromhex("0078"),                       # 0x06 ldrb r0, [r0]
        bytes.fromhex("90b1"),                       # 0x08 cbz  r0, 0x30  (wired: pass)
        bytes.fromhex("0b49"),                       # 0x0a ldr  r1, [pc, #0x2c]  -> NOW
        bytes.fromhex("0a68"),                       # 0x0c ldr  r2, [r1]
        bytes.fromhex("0b4b"),                       # 0x0e ldr  r3, [pc, #0x2c]  -> STATE
        bytes.fromhex("1c68"),                       # 0x10 ldr  r4, [r3]
        bytes.fromhex("141b"),                       # 0x12 subs r4, r2, r4      gap
        movw(12, idle_ms & 0xFFFF),                  # 0x14 movw ip, #idle
        bytes.fromhex("6445"),                       # 0x18 cmp  r4, ip
        bytes.fromhex("00d3"),                       # 0x1a blo  0x1e  (no re-arm)
        bytes.fromhex("5a60"),                       # 0x1c str  r2, [r3, #4]    armed = now
        bytes.fromhex("1a60"),                       # 0x1e str  r2, [r3]       last = now
        bytes.fromhex("5868"),                       # 0x20 ldr  r0, [r3, #4]
        bytes.fromhex("101a"),                       # 0x22 subs r0, r2, r0      elapsed
        movw(12, window_ms & 0xFFFF),                # 0x24 movw ip, #window
        bytes.fromhex("6045"),                       # 0x28 cmp  r0, ip
        bytes.fromhex("01d8"),                       # 0x2a bhi  0x30  (expired: pass)
        bytes.fromhex("bde8f09f"),                   # 0x2c pop.w {r4-r11, ip, pc}  drop
        bytes.fromhex("f2f7d8bb"),                   # 0x30 b.w  0x127e4  continue stock
        MODE.to_bytes(4, "little"),                  # 0x34
        NOW.to_bytes(4, "little"),                   # 0x38
        STATE.to_bytes(4, "little"),                 # 0x3c
    ]
    stub = b"".join(ops)
    assert len(stub) == STUB_LEN, f"stub is {len(stub):#x} bytes, expected {STUB_LEN:#x}"
    return stub


def hook_bytes() -> bytes:
    """b.w STUB from HOOK (T4). Encoded once and pinned by disassembly below."""
    return bytes.fromhex("0df00ebc")


def expect_disasm(stub: bytes) -> list[tuple[str, str]]:
    """The exact instruction sequence the stub must disassemble into."""
    return [
        ("push.w", "{r4, r5, r6, r7, r8, sb, sl, fp, ip, lr}"),
        ("ldr", "r0, [pc, #0x2c]"),
        ("ldrb", "r0, [r0]"),
        ("cbz", "r0, #0x20030"),
        ("ldr", "r1, [pc, #0x2c]"),
        ("ldr", "r2, [r1]"),
        ("ldr", "r3, [pc, #0x2c]"),
        ("ldr", "r4, [r3]"),
        ("subs", "r4, r2, r4"),
        ("movw", f"ip, #{IDLE_MS:#x}"),
        ("cmp", "r4, ip"),
        ("blo", "#0x2001e"),
        ("str", "r2, [r3, #4]"),
        ("str", "r2, [r3]"),
        ("ldr", "r0, [r3, #4]"),
        ("subs", "r0, r2, r0"),
        ("movw", f"ip, #{WINDOW_MS:#x}"),
        ("cmp", "r0, ip"),
        ("bhi", "#0x20030"),
        ("pop.w", "{r4, r5, r6, r7, r8, sb, sl, fp, ip, pc}"),
        ("b.w", "#0x127e4"),
    ]


def check_disasm(stub: bytes) -> None:
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    got = [(i.mnemonic, i.op_str) for i in md.disasm(stub[:0x34], STUB)]
    want = expect_disasm(stub)
    assert got == want, "stub disassembly changed:\n" + "\n".join(
        f"  want {w[0]:8s} {w[1]:40s} got {g[0]:8s} {g[1]}" for w, g in zip(want, got) if w != g)
    assert stub[0x34:0x40] == (MODE.to_bytes(4, "little") + NOW.to_bytes(4, "little")
                               + STATE.to_bytes(4, "little")), "stub literal pool changed"
    hk = next(iter(md.disasm(hook_bytes(), HOOK)))
    assert (hk.mnemonic, hk.op_str) == ("b.w", f"#{STUB:#x}"), \
        f"hook disassembles as {hk.mnemonic} {hk.op_str}"


def ram_references(img: bytes, lo: int, hi: int) -> list[tuple[int, str, str]]:
    """Straight-line base+disp tracking: every ldr/str that lands in [lo, hi)."""
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    hits: list[tuple[int, str, str]] = []
    a = 0
    while a < 0x18600:
        regs: dict[int, int] = {}
        while a < 0x18600:
            ins = next(iter(md.disasm(img[a:a + 4], a)), None)
            if ins is None:
                regs.clear()
                a += 2
                continue
            m, ops = ins.mnemonic, ins.operands
            if m == "ldr" and len(ops) == 2 and ops[1].type == capstone.arm.ARM_OP_MEM \
                    and md.reg_name(ops[1].mem.base) == "pc" and ops[1].mem.index == 0:
                la = ((a + 4) & ~3) + ops[1].mem.disp
                v = int.from_bytes(img[la:la + 4], "little") if la + 4 <= len(img) else None
                if v is None or v >= 0x1000000:
                    regs.pop(ops[0].reg, None)
                else:
                    regs[ops[0].reg] = v
            elif m == "movw" and len(ops) == 2 and ops[1].type == capstone.arm.ARM_OP_IMM:
                regs[ops[0].reg] = ops[1].imm
            elif m == "mov" and len(ops) == 2:
                if ops[1].type == capstone.arm.ARM_OP_IMM:
                    regs[ops[0].reg] = ops[1].imm
                else:
                    regs.pop(ops[0].reg, None)
            elif m == "movt" and len(ops) == 2 and ops[1].type == capstone.arm.ARM_OP_IMM:
                regs[ops[0].reg] = (regs.get(ops[0].reg, 0) & 0xFFFF) | ((ops[1].imm & 0xFFFF) << 16)
            elif m in ("add", "adds", "add.w") and len(ops) == 3 \
                    and ops[1].type == capstone.arm.ARM_OP_REG and ops[2].type == capstone.arm.ARM_OP_IMM \
                    and ops[1].reg in regs:
                regs[ops[0].reg] = (regs[ops[1].reg] + ops[2].imm) & 0xFFFFFFFF
            elif m.startswith(("ldr", "str")) and ops and ops[-1].type == capstone.arm.ARM_OP_MEM:
                mem = ops[-1].mem
                base = regs.get(mem.base)
                if base is not None and lo <= base + mem.disp < hi:
                    hits.append((a, m, ins.op_str))
                if m.startswith("ldr") and ops[0].type == capstone.arm.ARM_OP_REG:
                    regs.pop(ops[0].reg, None)
            elif m in ("bl", "blx", "b", "bx", "cbz", "cbnz", "tbb", "tbh") \
                    or m.startswith(("b.", "it")):
                regs.clear()
            a += ins.size
    return hits


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="add the wireless dead window to a firmware image and wrap it in the updater",
        epilog="example: python analysis/fw_deadwin.py --base analysis/out/fw_bake3.bin")
    ap.add_argument("--base", type=Path, default=IMG,
                    help="image to patch (default: the stock RCDATA 4000, or a previous build)")
    ap.add_argument("--name", default="fw_deadwin", help="output stem")
    ap.add_argument("--out-dir", type=Path, default=OUT)
    ap.add_argument("--no-exe", action="store_true", help="write the image only")
    ap.add_argument("--dry-run", action="store_true", help="print the plan, write nothing")
    ap.add_argument("--window", type=int, default=WINDOW_MS, metavar="MS",
                    help=f"how long keys are dropped after a wake (default {WINDOW_MS})")
    ap.add_argument("--idle", type=int, default=IDLE_MS, metavar="MS",
                    help=f"key gap that counts as a wake (default {IDLE_MS})")
    args = ap.parse_args(argv)

    if not args.base.exists():
        return fail(f"{args.base} is missing - run `python analysis/probe_pe.py` first")
    img = args.base.read_bytes()
    stem = sha256(img)
    kind = "stock image" if stem == STOCK_SHA.lower() else "derived image"

    problems: list[str] = []
    if len(img) != IMG_LEN:
        problems.append(f"image is {len(img):#x} bytes, expected {IMG_LEN:#x}")
    if int.from_bytes(img[-4:], "little") != TAIL_MAGIC:
        problems.append("tail magic 55 55 AA AA is missing - wrong file?")
    if img[HOOK:HOOK + 4] != STOCK_PUSH:
        problems.append(f"0x{HOOK:05X} is not the stock push.w ({img[HOOK:HOOK + 4].hex(' ')})"
                        " - already hooked, or not this image")
    if img[HOOK + 4:HOOK + 8] != STOCK_NEXT:
        problems.append(f"0x{HOOK + 4:05X} is not the stock continuation ({img[HOOK + 4:HOOK + 8].hex(' ')})")
    if any(img[STUB:STUB + STUB_LEN]):
        problems.append(f"0x{STUB:05X} is not blank: {img[STUB:STUB + STUB_LEN].hex(' ')}")
    if not 1 <= args.window <= 0xFFFF:
        problems.append(f"--window {args.window} does not fit a 16-bit immediate")
    if not 1 <= args.idle <= 0xFFFF:
        problems.append(f"--idle {args.idle} does not fit a 16-bit immediate")
    # our RAM must be unreferenced, and no literal may name it
    hits = ram_references(img, STATE, STATE + 8)
    if hits:
        problems.append("the state window is referenced: " +
                        ", ".join(f"{a:#05x} {m} {o}" for a, m, o in hits[:4]))
    for off in range(0, len(img) - 4):
        if STATE <= int.from_bytes(img[off:off + 4], "little") < STATE + 8:
            problems.append(f"a literal at 0x{off:05X} names the state window")
            break

    if problems:
        for pr in problems:
            print("  ", pr, file=sys.stderr)
        return fail("nothing built")

    stub = build_stub(args.window, args.idle)
    check_disasm(stub)

    patched = bytearray(img)
    patched[HOOK:HOOK + 4] = hook_bytes()
    patched[STUB:STUB + STUB_LEN] = stub

    changed = {i for i in range(IMG_LEN) if patched[i] != img[i]}
    expected = set(range(HOOK, HOOK + 4)) | set(range(STUB, STUB + STUB_LEN))
    assert not (changed - expected), f"unexpected diff at {sorted(changed - expected)[:4]}"
    assert len(patched) == IMG_LEN
    assert patched[HOOK + 4:HOOK + 8] == STOCK_NEXT
    assert patched[-4:] == img[-4:]

    log: list[str] = []

    def p(*a):
        line = " ".join(str(x) for x in a)
        log.append(line)
        print(line)

    p("fw_deadwin - wireless dead window (drop keys for a moment after a wake)")
    p("base     :", args.base.name, len(img), "bytes", stem, f"({kind})")
    p("hook     :", f"0x{HOOK:05X}  {STOCK_PUSH.hex(' ')} -> {hook_bytes().hex(' ')}"
                    f"   b.w 0x{STUB:05X}")
    p("stub     :", f"0x{STUB:05X}  {STUB_LEN} bytes, blank before the write")
    p("state    :", f"0x{STATE:08X}  two dwords, no literal and no base+disp reference in the image")
    p("window   :", f"{args.window} ms after a wake of {args.idle} ms idle, wireless only")
    p("")
    p("wire     : in wired mode the stub takes the first branch and the stock converter runs")
    p("           unchanged; in wireless mode a wake press and the next",
      args.window, "ms are dropped, so nothing is staged and nothing is sent")
    p("")
    p("gates    : length unchanged (size gate sees the stock value); checksum recomputed")
    p("           tool-side; version word untouched (0x127E0 was a prologue, 0x20000 zero fill)")
    p("")
    p(f"diff     : {len(changed)} bytes, exactly the hook ({HOOK:#x}) and the stub ({STUB:#x})")

    p("")
    p("stub disassembly")
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    for ins in md.disasm(stub[:0x34], STUB):
        p(f"  {ins.address:05X}: {ins.bytes.hex(' '):12s} {ins.mnemonic:8s} {ins.op_str}")
    p(f"  {STUB + 0x34:05X}: {stub[0x34:].hex(' ')}   literals MODE / NOW / STATE")

    dst_bin = args.out_dir / f"{args.name}.bin"
    dst_exe = args.out_dir / f"{args.name}.exe"
    dst_txt = args.out_dir / f"{args.name}_deadwin.txt"
    p("")
    p("out image:", dst_bin.name, IMG_LEN, "bytes", sha256(patched))
    if args.dry_run:
        p("dry run  : nothing written")
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    dst_bin.write_bytes(bytes(patched))
    p("written  :", dst_bin)

    if not args.no_exe:
        import mkflasher
        if mkflasher.main([str(dst_bin), "--out", str(dst_exe)]) != 0:
            return fail("mkflasher refused the image; see the message above")
        p("out exe  :", dst_exe.name, dst_exe.stat().st_size, "bytes",
          sha256(dst_exe.read_bytes()))

    dst_txt.write_text("\n".join(log) + "\n", encoding="utf-8")
    p("report   :", dst_txt)
    p("")
    p("flash    : run the updater, pick this exe, Start.")
    p("           Ladder: wired first, then one wireless wake press, then typing inside/after")
    p("           the window, then continuous typing, then a wired->wireless switch.")
    return 0


def fail(message: str) -> int:
    print("error:", message, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
