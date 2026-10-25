#!/usr/bin/env python3
"""fw_deadwin_probe.py - make the dead-window stub say what it sees.

    python analysis/fw_deadwin_probe.py
    python analysis/fw_deadwin_probe.py --base analysis/out/rcdata_4000.bin
    python analysis/fw_deadwin_probe.py --dry-run

The dead-window build (fw_deadwin.py) drops a key at the report funnel when the
mode byte says wireless and its own timer says "in window". It was flashed on
2026-10-24 and changed nothing: the CapsLock leak survived. One of those two
inputs is therefore not what the static reading says it is, and there is no
readback, so the device has to report the value itself.

This build keeps the hook and the timer and throws the drop away. Instead of
returning early it rewrites the action byte 0x2000008C, so the host types one
letter that encodes what the stub saw:

    mode byte == 0                    -> 'a'
    wireless, timer says in window    -> 'q'
    wireless, timer says outside      -> 'w'

Reading it:

    real keys / CapsLock still leaks   the hook or the write never landed
    'a' in the window and after        the mode byte is 0 in wireless
    'a' in the window, 'w' after it    the switch read lies during bring-up
    'q' for ~2 s, then 'w'             hook, mode and timer are all fine

Only the last case would leave the drop path itself at fault (an early return
may lose something the stock epilogue does); the first three each point at a
different gate. Nothing is dropped in this build, so the keyboard types letters
until it is reflashed.

What it writes (same shape as fw_deadwin.py):

    0x127E0    4 bytes   b.w 0x20000        (replaces the stock push.w)
    0x20000   88 bytes   the stub, a 3-byte letter table and four literal words

Gates: length unchanged (the size gate sees the stock value), checksum is
recomputed tool-side, the version word is untouched, 0x20000 was zero fill, and
the state window 0x20000610 carries no literal and no base+disp reference
anywhere in the image. The unmodified vendor updater is the revert path.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import capstone

import fw_deadwin as dw

SCRIPT_DIR = Path(__file__).resolve().parent
OUT = SCRIPT_DIR / "out"
DEFAULT_BASE = OUT / "fw_bake3.bin"

STUB_LEN = 0x58
SLOT = 0x2000008C              # [base+4]: the action byte the converter reads
TABLE = bytes([0x04, 0x14, 0x1A])          # 'a' wired, 'q' in window, 'w' outside

CONDS = {"eq": 0, "ne": 1, "cs": 2, "hs": 2, "cc": 3, "lo": 3, "mi": 4, "pl": 5,
         "vs": 6, "vc": 7, "hi": 8, "ls": 9, "ge": 10, "lt": 11, "gt": 12, "le": 13,
         "al": 14}


class Stub:
    """Two-pass Thumb emitter: bytes in order, labels resolved once at the end.

    Hand-encoding every branch offset is how the first draft of this file went
    wrong, so the offsets are computed from labels instead.
    """

    def __init__(self) -> None:
        self.buf = bytearray()
        self.labels: dict[str, int] = {}
        self.fix: list[tuple[int, str, str]] = []

    def at(self, name: str) -> None:
        assert name not in self.labels
        self.labels[name] = len(self.buf)

    def raw(self, hx) -> None:
        self.buf += bytes.fromhex(hx) if isinstance(hx, str) else bytes(hx)

    def _slot(self, kind: str, label: str, size: int) -> None:
        self.fix.append((len(self.buf), kind, label))
        self.buf += b"\x00" * size

    def ldr(self, rd: int, label: str) -> None:
        self._slot(f"ldr:{rd}", label, 2)

    def b(self, label: str) -> None:
        self._slot("b", label, 2)

    def bcond(self, cond: str, label: str) -> None:
        c = cond[1:] if cond.startswith("b") and cond[1:] in CONDS else cond
        assert c in CONDS, cond
        self._slot(c, label, 2)

    def cbz(self, rn: int, label: str) -> None:
        self._slot(f"cbz:{rn}", label, 2)

    def bw(self, target: int) -> None:
        """b.w to an absolute address outside the stub (the stock continuation)."""
        self._slot(f"abs:{target}", "", 4)

    def pad4(self) -> None:
        while len(self.buf) % 4:
            self.raw("00bf")                                  # nop

    def resolve(self, base: int = 0) -> bytes:
        out = bytearray(self.buf)
        for at, kind, label in self.fix:
            tgt = int(kind[4:]) if kind.startswith("abs:") else base + self.labels[label]
            if kind.startswith("ldr:"):
                rd = int(kind.split(":")[1])
                off = tgt - ((base + at + 4) & ~3)
                assert off % 4 == 0 and 0 <= off <= 1020, f"{kind} -> {label}: {off}"
                out[at] = off >> 2
                out[at + 1] = 0x48 | rd
                continue
            off = tgt - (base + at + 4)
            if kind.startswith("abs:"):
                assert off % 2 == 0 and -0x1000000 <= off <= 0xFFFFFE
                u = off & 0x1FFFFFF
                s, i1, i2 = (u >> 24) & 1, (u >> 23) & 1, (u >> 22) & 1
                imm10, imm11 = (u >> 12) & 0x3FF, (u >> 1) & 0x7FF
                j1, j2 = (1 - i1) ^ s, (1 - i2) ^ s
                hw1 = 0xF000 | (s << 10) | imm10
                hw2 = 0x8000 | (j1 << 13) | 0x1000 | (j2 << 11) | imm11
                out[at:at + 4] = hw1.to_bytes(2, "little") + hw2.to_bytes(2, "little")
                continue
            assert off % 2 == 0, f"{kind} -> {label}: odd offset {off}"
            if kind.startswith("cbz:"):
                assert 0 <= off <= 126, f"cbz -> {label}: {off}"
                out[at] = ((off >> 1) << 3) | int(kind.split(":")[1])
                out[at + 1] = 0xB1
            elif kind == "b":
                assert -2048 <= off <= 2046, f"b -> {label}: {off}"
                hw = 0xE000 | ((off >> 1) & 0x7FF)          # T2: 11100 imm11
                out[at] = hw & 0xFF
                out[at + 1] = hw >> 8
            else:
                assert kind in CONDS, kind
                assert -256 <= off <= 254, f"{kind} -> {label}: {off}"
                out[at] = (off >> 1) & 0xFF
                out[at + 1] = 0xD0 | CONDS[kind]
        return bytes(out)


def build_stub(idle_ms: int = dw.IDLE_MS, window_ms: int = dw.WINDOW_MS) -> tuple[bytes, dict[str, int]]:
    """The probe stub: report the two inputs, then run the stock converter."""
    s = Stub()
    s.raw("2de9f05f")                       # push.w {r4-r11, ip, lr}
    s.ldr(0, "mode")                        # ldr  r0, =0x20000378
    s.raw("0078")                           # ldrb r0, [r0]
    s.cbz(0, "wire")                        # wired -> idx 0
    s.ldr(1, "now")                         # ldr  r1, =0x200004A8
    s.raw("0a68")                           # ldr  r2, [r1]        now
    s.ldr(3, "state")                       # ldr  r3, =0x20000610
    s.raw("1c68")                           # ldr  r4, [r3]        last
    s.raw("141b")                           # subs r4, r2, r4      gap
    s.raw(dw.movw(12, idle_ms & 0xFFFF))    # movw ip, #idle
    s.raw("6445")                           # cmp  r4, ip
    s.bcond("blo", "keep")                  # short gap: no re-arm
    s.raw("5a60")                           # str  r2, [r3, #4]    armed = now
    s.at("keep")
    s.raw("1a60")                           # str  r2, [r3]        last = now
    s.raw("5868")                           # ldr  r0, [r3, #4]
    s.raw("101a")                           # subs r0, r2, r0      elapsed
    s.raw(dw.movw(12, window_ms & 0xFFFF))  # movw ip, #window
    s.raw("6045")                           # cmp  r0, ip
    s.bcond("bhi", "out")                   # past the window
    s.raw("0120")                           # movs r0, #1          in window
    s.b("have")
    s.at("out")
    s.raw("0220")                           # movs r0, #2          outside
    s.at("have")
    s.ldr(1, "table")                       # ldr  r1, =letter table
    s.raw("085c")                           # ldrb r0, [r1, r0]
    s.ldr(1, "slot")                        # ldr  r1, =0x2000008C
    s.raw("0870")                           # strb r0, [r1]
    s.bw(dw.HOOK + 4)                       # b.w  0x127e4
    s.at("wire")
    s.raw("0020")                           # movs r0, #0
    s.b("have")
    s.pad4()
    s.at("pool")
    s.at("table")
    s.raw((TABLE + b"\x00").hex())                # 'a' 'q' 'w'
    s.at("slot")
    s.raw(SLOT.to_bytes(4, "little").hex())       # 0x2000008C
    s.at("mode")
    s.raw(dw.MODE.to_bytes(4, "little").hex())    # 0x20000378
    s.at("now")
    s.raw(dw.NOW.to_bytes(4, "little").hex())     # 0x200004A8
    s.at("state")
    s.raw(dw.STATE.to_bytes(4, "little").hex())   # 0x20000610

    stub = s.resolve(dw.STUB)
    assert len(stub) == STUB_LEN, f"stub is {len(stub):#x}, expected {STUB_LEN:#x}"
    return stub, s.labels


def expect_disasm(lab: dict[str, int]) -> list[tuple[str, str]]:
    """The exact instruction sequence, with every target taken from a label."""
    base = dw.STUB

    def pc(at: int, label: str) -> str:
        return f"#0x{lab[label] - ((at + 4) & ~3):x}"

    def target(label: str) -> str:
        return f"#0x{base + lab[label]:x}"

    return [
        ("push.w", "{r4, r5, r6, r7, r8, sb, sl, fp, ip, lr}"),
        ("ldr", f"r0, [pc, {pc(0x04, 'mode')}]"),
        ("ldrb", "r0, [r0]"),
        ("cbz", f"r0, {target('wire')}"),
        ("ldr", f"r1, [pc, {pc(0x0A, 'now')}]"),
        ("ldr", "r2, [r1]"),
        ("ldr", f"r3, [pc, {pc(0x0E, 'state')}]"),
        ("ldr", "r4, [r3]"),
        ("subs", "r4, r2, r4"),
        ("movw", f"ip, #{dw.IDLE_MS:#x}"),
        ("cmp", "r4, ip"),
        ("blo", target("keep")),
        ("str", "r2, [r3, #4]"),
        ("str", "r2, [r3]"),
        ("ldr", "r0, [r3, #4]"),
        ("subs", "r0, r2, r0"),
        ("movw", f"ip, #{dw.WINDOW_MS:#x}"),
        ("cmp", "r0, ip"),
        ("bhi", target("out")),
        ("movs", "r0, #1"),
        ("b", target("have")),
        ("movs", "r0, #2"),
        ("ldr", f"r1, [pc, {pc(0x32, 'table')}]"),
        ("ldrb", "r0, [r1, r0]"),
        ("ldr", f"r1, [pc, {pc(0x36, 'slot')}]"),
        ("strb", "r0, [r1]"),
        ("b.w", "#0x127e4"),
        ("movs", "r0, #0"),
        ("b", target("have")),
        ("nop", ""),
    ]


def check(stub: bytes, lab: dict[str, int]) -> None:
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    code = stub[:lab["pool"]]
    got = [(i.mnemonic, i.op_str) for i in md.disasm(code, dw.STUB)]
    want = expect_disasm(lab)
    assert got == want, "stub disassembly changed:\n" + "\n".join(
        f"  want {w[0]:8s} {w[1]:44s} got {g[0]:8s} {g[1]}"
        for w, g in zip(want, got) if w != g)
    assert sum(i.size for i in md.disasm(code, dw.STUB)) == len(code), "code has a gap"
    assert stub[lab["table"]:lab["table"] + 4] == TABLE + b"\x00", "letter table changed"
    for name, val in (("slot", SLOT), ("mode", dw.MODE), ("now", dw.NOW), ("state", dw.STATE)):
        at = lab[name]
        assert stub[at:at + 4] == val.to_bytes(4, "little"), f"{name} literal changed"
    hk = next(iter(md.disasm(dw.hook_bytes(), dw.HOOK)))
    assert (hk.mnemonic, hk.op_str) == ("b.w", f"#{dw.STUB:#x}"), \
        f"hook disassembles as {hk.mnemonic} {hk.op_str}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="marker build: report what the dead-window stub sees")
    ap.add_argument("--base", type=Path, default=DEFAULT_BASE,
                    help=f"image to patch (default {DEFAULT_BASE.name})")
    ap.add_argument("--name", default="fw_deadwin_probe", help="output stem")
    ap.add_argument("--out-dir", type=Path, default=OUT)
    ap.add_argument("--no-exe", action="store_true", help="write the image only")
    ap.add_argument("--dry-run", action="store_true", help="print the plan, write nothing")
    args = ap.parse_args(argv)

    if not args.base.exists():
        return dw.fail(f"{args.base} is missing - run `python analysis/probe_pe.py` first")
    img = args.base.read_bytes()
    kind = "stock image" if dw.sha256(img) == dw.STOCK_SHA.lower() else "derived image"

    problems: list[str] = []
    if len(img) != dw.IMG_LEN:
        problems.append(f"image is {len(img):#x} bytes, expected {dw.IMG_LEN:#x}")
    if int.from_bytes(img[-4:], "little") != dw.TAIL_MAGIC:
        problems.append("tail magic 55 55 AA AA is missing - wrong file?")
    if img[dw.HOOK:dw.HOOK + 4] != dw.STOCK_PUSH:
        problems.append(f"0x{dw.HOOK:05X} is not the stock push.w ({img[dw.HOOK:dw.HOOK + 4].hex(' ')})"
                        " - already hooked, or not this image")
    if img[dw.HOOK + 4:dw.HOOK + 8] != dw.STOCK_NEXT:
        problems.append(f"0x{dw.HOOK + 4:05X} is not the stock continuation "
                        f"({img[dw.HOOK + 4:dw.HOOK + 8].hex(' ')})")
    if any(img[dw.STUB:dw.STUB + STUB_LEN]):
        problems.append(f"0x{dw.STUB:05X} is not blank: {img[dw.STUB:dw.STUB + STUB_LEN].hex(' ')}")
    hits = dw.ram_references(img, dw.STATE, dw.STATE + 8)
    if hits:
        problems.append("the state window is referenced: " +
                        ", ".join(f"{a:#05x} {m} {o}" for a, m, o in hits[:4]))
    for off in range(0, len(img) - 4):
        if dw.STATE <= int.from_bytes(img[off:off + 4], "little") < dw.STATE + 8:
            problems.append(f"a literal at 0x{off:05X} names the state window")
            break
    if problems:
        for pr in problems:
            print("  ", pr, file=sys.stderr)
        return dw.fail("nothing built")

    stub, lab = build_stub()
    check(stub, lab)

    patched = bytearray(img)
    patched[dw.HOOK:dw.HOOK + 4] = dw.hook_bytes()
    patched[dw.STUB:dw.STUB + STUB_LEN] = stub

    changed = {i for i in range(dw.IMG_LEN) if patched[i] != img[i]}
    expected = set(range(dw.HOOK, dw.HOOK + 4)) | set(range(dw.STUB, dw.STUB + STUB_LEN))
    assert not (changed - expected), f"unexpected diff at {sorted(changed - expected)[:4]}"
    assert len(patched) == dw.IMG_LEN
    assert patched[dw.HOOK + 4:dw.HOOK + 8] == dw.STOCK_NEXT
    assert patched[-4:] == img[-4:]

    log: list[str] = []

    def p(*a):
        line = " ".join(str(x) for x in a)
        log.append(line)
        print(line)

    p("fw_deadwin_probe - marker build: report what the dead-window stub sees")
    p("base     :", args.base.name, len(img), "bytes", dw.sha256(img), f"({kind})")
    p("hook     :", f"0x{dw.HOOK:05X}  {dw.STOCK_PUSH.hex(' ')} -> {dw.hook_bytes().hex(' ')}"
                    f"   b.w 0x{dw.STUB:05X}")
    p("stub     :", f"0x{dw.STUB:05X}  {STUB_LEN} bytes, blank before the write")
    p("timer    :", f"wake = a gap of {dw.IDLE_MS} ms, window = {dw.WINDOW_MS} ms"
                    f" (the same immediates as fw_deadwin.py)")
    p("")
    p("what it types back")
    p("  'a'  mode byte 0x20000378 == 0        (the firmware says wired)")
    p("  'q'  wireless, timer says in window   (the drop condition was true)")
    p("  'w'  wireless, timer says outside     (the drop condition was false)")
    p("")
    p("reading it")
    p("  real keys / CapsLock still leak  -> the hook or the write never landed")
    p("  'a' in the window and after it   -> the mode byte is 0 in wireless; new predicate")
    p("  'a' in the window, 'w' after     -> the switch read lies during bring-up")
    p("  'q' for ~2 s, then 'w'           -> hook, mode and timer are all fine, so the")
    p("                                      early return is what loses the drop")
    p("")
    p("gates    : length unchanged; checksum recomputed tool-side; version word untouched")
    p(f"diff     : {len(changed)} bytes, exactly the hook ({dw.HOOK:#x}) and the stub ({dw.STUB:#x})")
    p("")
    p("stub disassembly")
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    for ins in md.disasm(stub[:lab["pool"]], dw.STUB):
        p(f"  {ins.address:05X}: {ins.bytes.hex(' '):12s} {ins.mnemonic:8s} {ins.op_str}")
    p(f"  {dw.STUB + lab['table']:05X}: {stub[lab['table']:lab['table'] + 4].hex(' ')}"
      f"   table 'a' 'q' 'w'")
    p(f"  {dw.STUB + lab['slot']:05X}: {stub[lab['slot']:lab['slot'] + 4].hex(' ')}"
      f"   SLOT  {SLOT:#x}   (action byte)")
    p(f"  {dw.STUB + lab['mode']:05X}: {stub[lab['mode']:lab['mode'] + 4].hex(' ')}"
      f"   MODE  {dw.MODE:#x}")
    p(f"  {dw.STUB + lab['now']:05X}: {stub[lab['now']:lab['now'] + 4].hex(' ')}"
      f"   NOW   {dw.NOW:#x}")
    p(f"  {dw.STUB + lab['state']:05X}: {stub[lab['state']:lab['state'] + 4].hex(' ')}"
      f"   STATE {dw.STATE:#x}")

    dst_bin = args.out_dir / f"{args.name}.bin"
    dst_exe = args.out_dir / f"{args.name}.exe"
    dst_txt = args.out_dir / f"{args.name}_marker.txt"
    p("")
    p("out image:", dst_bin.name, dw.IMG_LEN, "bytes", dw.sha256(patched))
    if args.dry_run:
        p("dry run  : nothing written")
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    dst_bin.write_bytes(bytes(patched))
    p("written  :", dst_bin)

    if not args.no_exe:
        import mkflasher
        if mkflasher.main([str(dst_bin), "--out", str(dst_exe)]) != 0:
            return dw.fail("mkflasher refused the image; see the message above")
        p("out exe  :", dst_exe.name, dst_exe.stat().st_size, "bytes",
          dw.sha256(dst_exe.read_bytes()))

    dst_txt.write_text("\n".join(log) + "\n", encoding="utf-8")
    p("report   :", dst_txt)
    p("")
    p("flash    : run the updater, pick this exe, Start.")
    p("           Test: wired -> one key ('a'); then 2.4G, idle until it sleeps,")
    p("           press a key and keep pressing one per second for ~5 s.")
    p("           Then reflash fw_deadwin.exe or the vendor exe - this build types letters.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
