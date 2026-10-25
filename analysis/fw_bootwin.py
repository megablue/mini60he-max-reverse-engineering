#!/usr/bin/env python3
"""fw_bootwin.py - drop keys for the first milliseconds of a wireless boot.

    python analysis/fw_bootwin.py                     # on the arrow-cluster bake
    python analysis/fw_bootwin.py --boot-ms 3000
    python analysis/fw_bootwin.py --dry-run

Why a second dead-window build: the idle-gap version (fw_deadwin.py) never
fired on hardware. Static work then showed the gap predicate could not have been
true at a wireless wake - the ms counter and our own state word are both 0 right
after a reset, so "now - last >= 30 s" reads 0 - while the factory binding that
leaks is the key TABLE being refilled only at link-up (0x59F0 is called from the
link re-init 0x6EB8 at 0x6F16, i.e. after the settling window).

So this build keys the window on uptime instead of on an idle gap:

    drop  <=>  mode != 0  and  0 < now <= BOOT_MS

Consequences, in order of how much they are trusted:
* If the wireless wake restarts the MCU, `now` is small for BOOT_MS and exactly
  the window in which the tables are still factory is dropped. This is the
  hypothesis the build tests.
* If it does not restart, `now` is large and the build is a no-op: typing is
  byte-for-byte the stock path. It cannot make things worse.
* `now == 0` passes, so a stopped tick can never mute the keyboard.
* Wired (mode == 0) passes on the first branch, so replug stays instant.

The window is measured on the same counter the stock delays use (0x3BA2 polls
0x200004A8), so it is milliseconds, not polls.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import capstone

SCRIPT_DIR = Path(__file__).resolve().parent
OUT = SCRIPT_DIR / "out"

sys.path.insert(0, str(SCRIPT_DIR))
from fw_deadwin import STOCK_PUSH, STOCK_NEXT, hook_bytes, movw  # noqa: E402

STOCK_SHA = "06A1A47432A6CA7EC060103378E2D984A46F9AFA98F19FCCD99219EAEA4A88E0"
IMG_LEN = 0x7E000
TAIL_MAGIC = 0xAAAA5555

HOOK = 0x127E0                  # entry of the action-byte -> HID report converter
STUB = 0x20000                  # blank flash, 0x18600-0x7DFFC band
MODE = 0x20000378               # transport object: 0 wired, 1/2 wireless
NOW = 0x200004A8                # SysTick millisecond counter
BOOT_MS = 2500                  # keys are dropped until this much uptime

STUB_LEN = 0x34


def sha256(data) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def b_w(addr: int, target: int) -> int:
    """Distance the stub's pass branch must encode (bytes are pinned by disasm).

    The stub reuses the already-verified encoding f2 f7 d8 bb, so this exists to
    prove the address pair still matches that encoding rather than to build it.
    """
    return target - (addr + 4)


def build_stub(boot_ms: int = BOOT_MS) -> bytes:
    """The stub plus its two literal words.

    code 0x00-0x1f (drop path), literals 0x20-0x27, 8 bytes of unreachable pad,
    then the pass branch at 0x30 so its bytes are the ones already in use
    (b.w 0x20030 -> 0x127e4 = f2 f7 d8 bb, verified in fw_deadwin's stub).
    """
    ops = [
        STOCK_PUSH,                                  # 0x00 push.w {r4-r11, ip, lr}
        bytes.fromhex("0648"),                       # 0x04 ldr  r0, [pc, #0x18]  -> MODE
        bytes.fromhex("0078"),                       # 0x06 ldrb r0, [r0]
        bytes.fromhex("0028"),                       # 0x08 cmp  r0, #0
        bytes.fromhex("11d0"),                       # 0x0a beq  0x30  (wired: pass)
        bytes.fromhex("0549"),                       # 0x0c ldr  r1, [pc, #0x14]  -> NOW
        bytes.fromhex("0a68"),                       # 0x0e ldr  r2, [r1]
        bytes.fromhex("002a"),                       # 0x10 cmp  r2, #0
        bytes.fromhex("0dd0"),                       # 0x12 beq  0x30  (no tick: pass)
        movw(12, boot_ms & 0xFFFF),                  # 0x14 movw ip, #boot_ms
        bytes.fromhex("6245"),                       # 0x18 cmp  r2, ip
        bytes.fromhex("09d8"),                       # 0x1a bhi  0x30  (window over: pass)
        bytes.fromhex("bde8f09f"),                   # 0x1c pop.w {r4-r11, ip, pc}  drop
        MODE.to_bytes(4, "little"),                  # 0x20
        NOW.to_bytes(4, "little"),                   # 0x24
        bytes.fromhex("00bf00bf00bf00bf"),           # 0x28 pad, never reached
        bytes.fromhex("f2f7d8bb"),                   # 0x30 b.w  0x127e4  continue stock
    ]
    stub = b"".join(ops)
    assert len(stub) == STUB_LEN, f"stub is {len(stub):#x} bytes, expected {STUB_LEN:#x}"
    return stub


def expect_disasm(boot_ms: int) -> list[tuple[str, str]]:
    return [
        ("push.w", "{r4, r5, r6, r7, r8, sb, sl, fp, ip, lr}"),
        ("ldr", "r0, [pc, #0x18]"),
        ("ldrb", "r0, [r0]"),
        ("cmp", "r0, #0"),
        ("beq", "#0x20030"),
        ("ldr", "r1, [pc, #0x14]"),
        ("ldr", "r2, [r1]"),
        ("cmp", "r2, #0"),
        ("beq", "#0x20030"),
        ("movw", f"ip, #{boot_ms:#x}"),
        ("cmp", "r2, ip"),
        ("bhi", "#0x20030"),
        ("pop.w", "{r4, r5, r6, r7, r8, sb, sl, fp, ip, pc}"),
        ("b.w", "#0x127e4"),
    ]


def check(stub: bytes, boot_ms: int) -> None:
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    # the code is 0x00-0x1d, then the pool, pad, and the pass branch at 0x30
    got = [(i.mnemonic, i.op_str) for i in md.disasm(stub[:0x20], STUB)]
    want = expect_disasm(boot_ms)[:13]
    assert got == want, "stub disassembly changed:\n" + "\n".join(
        f"  want {w[0]:8s} {w[1]:40s} got {g[0]:8s} {g[1]}" for w, g in zip(want, got))
    tail = [(i.mnemonic, i.op_str) for i in md.disasm(stub[0x30:], STUB + 0x30)]
    assert tail == [expect_disasm(boot_ms)[13]], f"pass branch changed: {tail}"
    assert stub[0x20:0x28] == (MODE.to_bytes(4, "little") + NOW.to_bytes(4, "little")), \
        "stub literal pool changed"
    assert stub[0x28:0x30] == bytes.fromhex("00bf00bf00bf00bf"), "pad changed"
    # the literal loads must resolve onto the pool, not into code
    for at, imm in ((0x04, 0x18), (0x0c, 0x14)):
        assert STUB + (((at + 4) & ~3) + imm) == STUB + (0x20 if at == 0x04 else 0x24), \
            f"literal load at {at:#x} no longer reaches the pool"
    assert b_w(STUB + 0x30, 0x127E4) == -0xD850, "pass branch distance changed"
    hk = next(iter(md.disasm(hook_bytes(), HOOK)))
    assert (hk.mnemonic, hk.op_str) == ("b.w", f"#{STUB:#x}"), \
        f"hook disassembles as {hk.mnemonic} {hk.op_str}"


def fail(message: str) -> int:
    print("error:", message, file=sys.stderr)
    return 2


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="drop wireless keys until the firmware has been up for a moment",
        epilog="example: python analysis/fw_bootwin.py --base analysis/out/fw_bake3.bin")
    ap.add_argument("--base", type=Path, default=OUT / "fw_bake3.bin",
                    help="image to patch (default: the arrow-cluster bake)")
    ap.add_argument("--name", default="fw_bootwin_remap", help="output stem")
    ap.add_argument("--out-dir", type=Path, default=OUT)
    ap.add_argument("--boot-ms", type=int, default=BOOT_MS, metavar="MS",
                    help=f"drop keys until this much uptime (default {BOOT_MS})")
    ap.add_argument("--no-exe", action="store_true", help="write the image only")
    ap.add_argument("--dry-run", action="store_true", help="print the plan, write nothing")
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
        problems.append(f"0x{HOOK:05X} is not the stock prologue "
                        f"({img[HOOK:HOOK + 4].hex(' ')}) - already hooked?")
    if any(img[STUB:STUB + STUB_LEN]):
        problems.append(f"0x{STUB:05X} is not blank: {img[STUB:STUB + STUB_LEN].hex(' ')}")
    if not 1 <= args.boot_ms <= 0xFFFF:
        problems.append(f"--boot-ms {args.boot_ms} does not fit a 16-bit immediate")
    if problems:
        for pr in problems:
            print("  ", pr, file=sys.stderr)
        return fail("nothing built")

    stub = build_stub(args.boot_ms)
    check(stub, args.boot_ms)

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

    p("fw_bootwin - drop wireless keys until the firmware has been up for a moment")
    p("base     :", args.base.name, len(img), "bytes", stem, f"({kind})")
    p("hook     :", f"0x{HOOK:05X}  {STOCK_PUSH.hex(' ')} -> {hook_bytes().hex(' ')}"
                    f"   b.w 0x{STUB:05X}")
    p("stub     :", f"0x{STUB:05X}  {STUB_LEN} bytes, blank before the write")
    p("rule     :", f"drop while mode != 0 and 0 < now <= {args.boot_ms} ms")
    p("")
    p("if the wireless wake restarts the MCU, this covers exactly the window in which")
    p("the per-key tables are still factory (they are refilled by 0x59F0 at link-up)")
    p("if it does not restart, `now` is large, the stub passes and typing is stock")
    p("now == 0 passes  : a stopped tick can never mute the keyboard")
    p("wired            : mode == 0 passes on the first branch, replug stays instant")
    p("")
    p("gates    : length unchanged (size gate sees the stock value); checksum recomputed")
    p("           tool-side; version word untouched (0x127E0 was a prologue, 0x20000 zero fill)")
    p("")
    p(f"diff     : {len(changed)} bytes, exactly the hook ({HOOK:#x}) and the stub ({STUB:#x})")

    p("")
    p("stub disassembly")
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    for ins in md.disasm(stub[:0x20], STUB):
        p(f"  {ins.address:05X}: {ins.bytes.hex(' '):12s} {ins.mnemonic:8s} {ins.op_str}")
    p(f"  {STUB + 0x20:05X}: {stub[0x20:0x28].hex(' ')}   literals MODE / NOW")
    p(f"  {STUB + 0x28:05X}: {stub[0x28:0x30].hex(' ')}   pad (unreachable)")
    p(f"  {STUB + 0x30:05X}: {stub[0x30:].hex(' ')}   b.w 0x127E4")

    dst_bin = args.out_dir / f"{args.name}.bin"
    dst_exe = args.out_dir / f"{args.name}.exe"
    dst_txt = args.out_dir / f"{args.name}_bootwin.txt"
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
    p("test     : wake the keyboard and press a key at once.")
    p("           typing appears immediately  -> the wake does not restart the counter")
    p("           ~2 s of silence then typing -> it does, and the window is doing its job")
    return 0


if __name__ == "__main__":
    sys.exit(main())
