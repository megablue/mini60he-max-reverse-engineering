#!/usr/bin/env python3
"""fw_macroguard.py - stop one key's factory usage leaking before its macro is armed.

    python analysis/fw_macroguard.py                      # CapsLock, current device base
    python analysis/fw_macroguard.py --key CapsLock --dry-run
    python analysis/fw_macroguard.py --base analysis/out/fw_bake3.bin --name mv2

Why this shape
--------------
The wireless dead window is not a wire-mode problem and not a general "config is
late" problem. Two user tests narrow it to one action:

    a plain remap of the same physical key   works on the first press after wake
    a macro on that same key                 leaks the key's FACTORY usage
                                             (CapsLock) for ~2 s, then runs

Both builds so far dropped reports on a *timer* (fw_deadwin.py armed on a 30 s
idle gap, fw_bootwin.py on uptime <= 2.5 s). Neither predicate can be true at a
wireless wake: the MCU does not sleep (no wfi in the poll loop, so the ms tick
never stops and the gap never opens) and it does not reboot (the only self-reset
is the HardFault path 0x518C). That is why both builds were inert.

So the guard has to look at *what is being sent*, not at a clock. The factory
byte is staged by the per-event handler 0x5D28 at 0x5D4A from table 0x16B3E and
survives whenever the per-key record does not overwrite it - which is exactly
what a macro key looks like while its macro is not playable. This build reads
the staged action at the single report funnel 0x127E0 and refuses the key's
factory usage while the macro player is idle, in wireless mode only.

The rule
--------
At 0x127E0 (every action passes here), before anything is staged:

    mode 0x20000378 == 0                  -> stock (wired is untouched)
    0x200000B3 != 0 (macro running)       -> stock (macro output is never blocked)
    0x20000090 != 1 (not a press)         -> stock (releases are untouched)
    action 0x2000008C != the guard usage  -> stock
    otherwise                             -> return without staging anything

Worst case: that one usage produces nothing while the player is idle. It can
never emit a wrong key, never wedges the funnel (the press is simply absent from
its pressed list, and the matching release is a no-op), and wired mode is
byte-for-byte stock behaviour. The old stub is replaced, so the arrow-cluster
bake underneath is preserved.

The guard usage is derived, not hardcoded: --key is resolved through
fw_names/fw_build to the id that owns it, and the guard is that id's factory
usage from table 0x16B3E (CapsLock -> id 0x30 -> 0x39).

Gates: length unchanged, tail magic, the hook site was the stock push.w, the
continuation 0x127E4 is untouched, the stub fits in the blank band 0x18600+, and
the version word stays below everything we touch. Nothing here is flashed by
this script.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import capstone

import fw_build as fb
import fw_deadwin as dw
import fw_names
from fw_deadwin_probe import Stub

SCRIPT_DIR = Path(__file__).resolve().parent
OUT = SCRIPT_DIR / "out"

HOOK = dw.HOOK                  # 0x127E0, entry of the action -> report funnel
STUB = dw.STUB                  # 0x20000, blank flash
STUB_LEN = 0x40
MODE = dw.MODE                  # 0x20000378: 0 wired, 1/2 wireless
SLOT = 0x2000008C               # the staged action byte
PRESS = 0x20000090              # 1 on a press, 0 on a release
MACRO = 0x200000B3              # macro player active flag
STAGED = 0x16B3E                # position -> factory usage (the leaking table)

# Bases we recognise on purpose: the factory image, and the image the keyboard
# currently runs (arrow bake + the inert dead-window stub).
KNOWN_BASES = {
    dw.STOCK_SHA.lower(): "stock image",
    "617eef7f4bb4cd5ceecaaee5d4d54124836f9ba63691b17185e094c3c744cd16":
        "arrow-cluster bake (fw_build.py's acceptance image)",
    "4dd3201cae72e7d4974731d9c300797255236399ea014479467a4261e0f3d4bb":
        "arrow bake + inert dead-window stub (the image on the device)",
}


def guard_usage(img: bytes, key: str) -> tuple[int, int, int]:
    """(id, factory usage, usage) for the key named on the command line."""
    usage = fw_names.usage_of(key)
    ids = [i for i in range(0x79) if i != 0x6F
           and img[fb.pair_usage_off(i)] == usage]
    if not ids:
        raise SystemExit(f"{key} (usage 0x{usage:02X}) is carried by no id")
    key_id = ids[0]
    cat = img[fb.catalog_usage_off(key_id) - 2:fb.catalog_usage_off(key_id) + 2]
    if cat[0] != 2 or cat[2] != usage:
        raise SystemExit(f"catalog record for id 0x{key_id:02X} is {cat.hex(' ')},"
                         f" not a kind-2 0x{usage:02X} record")
    # 0x16B3E is indexed by scan position, not by id: find the position that
    # resolves to this id through the 0x16A96 grid.
    positions = [p for p in range(128) if img[fb.SCAN_GRID + p] == key_id]
    if not positions:
        raise SystemExit(f"id 0x{key_id:02X} owns no scan position")
    factory = img[STAGED + positions[0]]
    if factory != usage:
        raise SystemExit(f"id 0x{key_id:02X} stages factory usage 0x{factory:02X},"
                         f" but its catalog usage is 0x{usage:02X}")
    if factory >= 0x78:
        raise SystemExit(f"0x{factory:02X} is not a bitmap usage; pick another key")
    return key_id, factory, usage


def build_stub(guard: int) -> tuple[bytes, dict[str, int]]:
    s = Stub()
    s.raw("2de9f05f")                       # push.w {r4-r11, ip, lr}
    s.ldr(0, "mode")
    s.raw("0078")                           # ldrb r0, [r0]
    s.cbz(0, "pass")                        # wired -> stock
    s.ldr(0, "slot")
    s.raw("0078")                           # ldrb r0, [r0]
    s.raw(f"{guard:02x}28")                 # cmp  r0, #guard
    s.bcond("ne", "pass")
    s.ldr(0, "press")
    s.raw("0078")                           # ldrb r0, [r0]
    s.raw("0128")                           # cmp  r0, #1
    s.bcond("ne", "pass")                   # release -> stock
    s.ldr(0, "macro")
    s.raw("0078")                           # ldrb r0, [r0]
    s.raw("0028")                           # cmp  r0, #0
    s.bcond("ne", "pass")                   # macro playing -> stock
    s.raw("bde8f08f")                       # pop.w {r4-r11, ip, pc}   drop
    s.at("pass")
    s.bw(HOOK + 4)                          # b.w 0x127e4
    s.pad4()
    s.at("pool")
    for name, val in (("slot", SLOT), ("mode", MODE),
                      ("press", PRESS), ("macro", MACRO)):
        s.at(name)
        s.raw(val.to_bytes(4, "little").hex())

    stub = s.resolve(STUB)
    assert len(stub) <= STUB_LEN, f"stub is {len(stub):#x}, budget {STUB_LEN:#x}"
    return stub, s.labels


def expect_disasm(lab: dict[str, int], guard: int) -> list[tuple[str, str]]:
    def tgt(label: str) -> str:
        return f"#0x{STUB + lab[label]:x}"

    def pc(at: int, label: str) -> str:
        return f"#0x{lab[label] - ((at + 4) & ~3):x}"

    return [
        ("push.w", "{r4, r5, r6, r7, r8, sb, sl, fp, ip, lr}"),
        ("ldr", f"r0, [pc, {pc(0x04, 'mode')}]"),
        ("ldrb", "r0, [r0]"),
        ("cbz", f"r0, {tgt('pass')}"),
        ("ldr", f"r0, [pc, {pc(0x0A, 'slot')}]"),
        ("ldrb", "r0, [r0]"),
        ("cmp", f"r0, #{guard:#x}"),
        ("bne", tgt("pass")),
        ("ldr", f"r0, [pc, {pc(0x12, 'press')}]"),
        ("ldrb", "r0, [r0]"),
        ("cmp", "r0, #1"),
        ("bne", tgt("pass")),
        ("ldr", f"r0, [pc, {pc(0x1A, 'macro')}]"),
        ("ldrb", "r0, [r0]"),
        ("cmp", "r0, #0"),
        ("bne", tgt("pass")),
        ("pop.w", "{r4, r5, r6, r7, r8, sb, sl, fp, pc}"),
        ("b.w", f"#0x{HOOK + 4:x}"),
        ("nop", ""),
    ]


def check(stub: bytes, lab: dict[str, int], guard: int) -> None:
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    code = stub[:lab["pool"]]
    got = [(i.mnemonic, i.op_str) for i in md.disasm(code, STUB)]
    want = expect_disasm(lab, guard)
    assert got == want, "stub disassembly changed:\n" + "\n".join(
        f"  want {w[0]:8s} {w[1]:44s} got {g[0]:8s} {g[1]}"
        for w, g in zip(want, got) if w != g)
    assert sum(i.size for i in md.disasm(code, STUB)) == len(code), "code has a gap"
    for name, val in (("slot", SLOT), ("mode", MODE),
                      ("press", PRESS), ("macro", MACRO)):
        at = lab[name]
        assert stub[at:at + 4] == val.to_bytes(4, "little"), f"{name} literal changed"
    hk = next(iter(md.disasm(dw.hook_bytes(), HOOK)))
    assert (hk.mnemonic, hk.op_str) == ("b.w", f"#{STUB:#x}"), \
        f"hook disassembles as {hk.mnemonic} {hk.op_str}"


def body_takes_no_arguments(img: bytes) -> None:
    """0x127e4 must define r0-r3 before it reads them, so our clobber is safe."""
    from capstone import arm as cs_arm

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    ins = list(md.disasm(img[HOOK + 4:HOOK + 4 + 0x20], HOOK + 4))[:8]
    assert len(ins) == 8, "0x127e4 does not disassemble"
    volatile = {cs_arm.ARM_REG_R0, cs_arm.ARM_REG_R1,
                cs_arm.ARM_REG_R2, cs_arm.ARM_REG_R3}
    defined: set[int] = set()
    for i in ins:
        read, written = i.regs_access()
        early = (set(read) & volatile) - defined
        assert not early, (f"0x127e4 reads r0-r3 before writing them at {i.address:#x}:"
                           f" {i.mnemonic} {i.op_str}")
        defined |= set(written) & volatile


def pick_base(arg: Path | None) -> Path:
    if arg is not None:
        return arg
    live = OUT / "fw_deadwin_remap.bin"
    if live.exists() and dw.sha256(live.read_bytes()) in KNOWN_BASES:
        return live
    return OUT / "fw_bake3.bin"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="refuse one key's factory usage until its macro is armed")
    ap.add_argument("--key", default="CapsLock", help="the key that carries the macro")
    ap.add_argument("--base", type=Path, default=None,
                    help="image to patch (default: the image the device runs, else fw_bake3.bin)")
    ap.add_argument("--name", default="fw_macroguard", help="output stem")
    ap.add_argument("--out-dir", type=Path, default=OUT)
    ap.add_argument("--no-exe", action="store_true", help="write the image only")
    ap.add_argument("--dry-run", action="store_true", help="print the plan, write nothing")
    args = ap.parse_args(argv)

    base = pick_base(args.base)
    if not base.exists():
        return dw.fail(f"{base} is missing - run `python analysis/probe_pe.py` first")
    img = base.read_bytes()
    sha = dw.sha256(img)
    if sha not in KNOWN_BASES:
        return dw.fail(f"{base.name} is {sha}, which is not a base this build knows")

    key_id, factory, usage = guard_usage(img, args.key)

    problems: list[str] = []
    if len(img) != dw.IMG_LEN:
        problems.append(f"image is {len(img):#x} bytes, expected {dw.IMG_LEN:#x}")
    if int.from_bytes(img[-4:], "little") != dw.TAIL_MAGIC:
        problems.append("tail magic 55 55 AA AA is missing - wrong file?")
    if img[HOOK:HOOK + 4] not in (dw.STOCK_PUSH, dw.hook_bytes()):
        problems.append(f"0x{HOOK:05X} is {img[HOOK:HOOK + 4].hex(' ')},"
                        " neither the stock push.w nor our hook")
    if img[HOOK + 4:HOOK + 8] != dw.STOCK_NEXT:
        problems.append(f"0x{HOOK + 4:05X} is not the stock continuation")
    if problems:
        for pr in problems:
            print("  ", pr, file=sys.stderr)
        return dw.fail("nothing built")
    body_takes_no_arguments(img)

    stub, lab = build_stub(factory)
    check(stub, lab, factory)

    patched = bytearray(img)
    patched[HOOK:HOOK + 4] = dw.hook_bytes()
    patched[STUB:STUB + len(stub)] = stub

    changed = {i for i in range(dw.IMG_LEN) if patched[i] != img[i]}
    assert not (changed - set(range(HOOK, HOOK + 4)) - set(range(STUB, STUB + STUB_LEN))), \
        f"unexpected diff at {sorted(changed)[:4]}"
    assert len(patched) == dw.IMG_LEN
    assert patched[HOOK + 4:HOOK + 8] == dw.STOCK_NEXT
    assert patched[-4:] == img[-4:]

    log: list[str] = []

    def p(*a):
        line = " ".join(str(x) for x in a)
        log.append(line)
        print(line)

    p("fw_macroguard - one key's factory usage, refused until its macro is armed")
    p("base     :", base.name, len(img), "bytes", sha, f"({KNOWN_BASES[sha]})")
    p("guard key:", args.key, f"-> id 0x{key_id:02X}, usage 0x{usage:02X},",
      f"factory staged usage 0x{factory:02X} (table 0x{STAGED:05X}+id)")
    p("hook     :", f"0x{HOOK:05X}  {dw.STOCK_PUSH.hex(' ')} -> {dw.hook_bytes().hex(' ')}"
                    f"   b.w 0x{STUB:05X}")
    p("stub     :", f"0x{STUB:05X}  {len(stub)} bytes of {STUB_LEN:#x}")
    p("")
    p("the rule")
    p("  mode   0x20000378 == 0   -> stock    (wired untouched)")
    p("  press  0x20000090 != 1   -> stock    (releases untouched)")
    p("  macro  0x200000B3 != 0   -> stock    (macro output never blocked)")
    p(f"  action 0x2000008C != {factory:#04x} -> stock")
    p(f"  else action {factory:#04x} with a press in wireless and an idle macro player")
    p("       -> return before anything is staged (the key does nothing)")
    p("")
    p("why a clock is not in this build")
    p("  no wfi in the poll loop 0x10DE0-0x10E60 -> the ms tick never stops, so an")
    p("  idle-gap timer (fw_deadwin.py) can never arm; the only self-reset is the")
    p("  HardFault path 0x518C, so an uptime window (fw_bootwin.py) is never true at")
    p("  a wake either. Both flashed builds were structurally inert.")
    p("")
    p("gates    : length unchanged; tail magic; 0x127e4 untouched; stub inside the")
    p("           blank band; checksum recomputed tool-side; version word untouched")
    p(f"diff     : {len(changed)} bytes vs the base")
    p("")
    p("stub disassembly")
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    for ins in md.disasm(stub[:lab["pool"]], STUB):
        p(f"  {ins.address:05X}: {ins.bytes.hex(' '):12s} {ins.mnemonic:8s} {ins.op_str}")
    for name, val in (("slot", SLOT), ("mode", MODE), ("press", PRESS), ("macro", MACRO)):
        at = STUB + lab[name]
        p(f"  {at:05X}: {stub[lab[name]:lab[name] + 4].hex(' ')}"
          f"   {name.upper():5s} {val:#x}")

    dst_bin = args.out_dir / f"{args.name}.bin"
    dst_exe = args.out_dir / f"{args.name}.exe"
    dst_txt = args.out_dir / f"{args.name}_build.txt"
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
    p("test     : wired - the key still runs the macro, nothing else changed.")
    p("           wireless - wake, press this key inside the ~2 s window: it should")
    p("           type nothing at all (not CapsLock). After the window it runs the")
    p("           macro. Press any other key in the window: unaffected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
