#!/usr/bin/env python3
"""fw_defer.py - hold the first press after a wireless wake, then replay it.

    python analysis/fw_defer.py --dry-run
    python analysis/fw_defer.py

Why
---
The release build stopped the first press after a wireless wake from typing the
key's factory usage (CapsLock). It did not make that press run its macro, because
at that instant the per-key record is still empty: the only code that fills the
tables is the boot-time loader 0x58D0 (single caller 0x153EC, inside init), so the
press is being handled while the key subsystem is still coming up. The dispatch
gate probe (fw_gate.py) ruled out the kind-dispatch gate as the cause.

No table edit can help, because the information the press needs does not exist
yet. So this build holds the press and replays it once the record appears:

    capture  at 0x5E80 (the empty-record branch): remember the scan position,
             the event byte and a timestamp, then return as before
    poll     hook 0x153FC (the first call of the main loop, unconditional): when
             the record kind at 0x200024AE + id*4 is no longer 0, restore the
             event into 0x200000F4 and call 0x5D28 again - the real handler, so
             the macro arms exactly as it would on any later press
    deadline 300 ms, so a record that never arrives leaves the key silent instead
             of firing much later

State: 0x20000610, an unreferenced 2-dword hole (the same one the dead-window
stub used): +0 valid, +1 position, +2 event byte, +4 stamp (ms).

Hooks
-----
    0x5E80  00 f0 10 b8  ->  b.w CAPTURE     (our own empty-record exit)
    0x14E00 10 b5 29 4c  ->  b.w POLL        (the poll callee's prologue is
                                              replayed inside the stub)

Gates: length unchanged, tail magic intact, the two hooks are exactly four bytes
each and were the expected bytes, the stub fits the blank band, no other byte
moves, and nothing below 0x1000 (vector table / version word) changes.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import capstone

SCRIPT_DIR = Path(__file__).resolve().parent
OUT = SCRIPT_DIR / "out"

IMG_LEN = 0x7E000
TAIL = 0x7DFFC
STUB = 0x20000
STUB_LEN = 0x100

CAP_SITE = 0x5E80                 # our b.w 0x5EA4 from the release build
CAP_BYTES = bytes.fromhex("00f010b8")
POLL_SITE = 0x153FC               # bl 0x6BCC, first call of the main loop
POLL_BYTES = bytes.fromhex("f1f7e6fb")
POLL_NEXT = 0x15400               # the second loop call; the stub replays the first
POLL_REPLAY = 0x6BCC
EXIT = 0x5EA4                     # the empty-record exit inside 0x5D28
HANDLER = 0x5D28

MODE = 0x20000378
STATE = 0x20000610
NOW = 0x200004A8
GRID = 0x16A96
REC = 0x200024AE
EV = 0x200000F4
DEADLINE_MS = 300

KNOWN_BASES = {
    "ecb236fb447298891582426603b880288e3994119cdabf0b20dded8a465db517":
        "released image (arrow bake + wake fix + Fn+Left = VolDown)",
}

CONDS = {"eq": 0, "ne": 1, "cs": 2, "hs": 2, "cc": 3, "lo": 3, "mi": 4, "pl": 5,
         "vs": 6, "vc": 7, "hi": 8, "ls": 9, "ge": 10, "lt": 11, "gt": 12, "le": 13,
         "al": 14}


def sha256(d: bytes) -> str:
    return hashlib.sha256(d).hexdigest()


def fail(msg: str) -> int:
    print("FAIL:", msg)
    return 1


class Stub:
    """Two-pass Thumb emitter with labels, for ldr-pc, b, bcond, cbz/cbnz, bl/b.w."""

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

    def cbnz(self, rn: int, label: str) -> None:
        self._slot(f"cbnz:{rn}", label, 2)

    def bl(self, target: int) -> None:
        self._slot(f"bl:{target}", "", 4)

    def bw(self, target: int) -> None:
        self._slot(f"bw:{target}", "", 4)

    def pad4(self) -> None:
        while len(self.buf) % 4:
            self.raw("00bf")

    def resolve(self, base: int) -> bytes:
        out = bytearray(self.buf)
        for at, kind, label in self.fix:
            if kind.startswith(("bl:", "bw:")):
                tgt = int(kind.split(":")[1])
                wide = 0xD000 if kind.startswith("bl:") else 0x9000
            else:
                tgt = base + self.labels[label]
                wide = 0
            if kind.startswith("ldr:"):
                rd = int(kind.split(":")[1])
                off = tgt - ((base + at + 4) & ~3)
                assert off % 4 == 0 and 0 <= off <= 1020, f"{kind}->{label}: {off}"
                out[at] = off >> 2
                out[at + 1] = 0x48 | rd
                continue
            off = tgt - (base + at + 4)
            if kind.startswith(("bl:", "bw:")):
                assert off % 2 == 0 and -0x1000000 <= off <= 0xFFFFFE
                u = off & 0x1FFFFFF
                s, i1, i2 = (u >> 24) & 1, (u >> 23) & 1, (u >> 22) & 1
                imm10, imm11 = (u >> 12) & 0x3FF, (u >> 1) & 0x7FF
                j1, j2 = (1 - i1) ^ s, (1 - i2) ^ s
                hw1 = 0xF000 | (s << 10) | imm10
                hw2 = wide | (j1 << 13) | 0x1000 | (j2 << 11) | imm11
                out[at:at + 4] = hw1.to_bytes(2, "little") + hw2.to_bytes(2, "little")
                continue
            assert off % 2 == 0, f"{kind}->{label}: odd {off}"
            if kind.startswith(("cbz:", "cbnz:")):
                assert 0 <= off <= 126, f"{kind}->{label}: {off}"
                out[at] = ((off >> 1) << 3) | int(kind.split(":")[1])
                out[at + 1] = 0xB9 if kind.startswith("cbnz") else 0xB1
            elif kind == "b":
                assert -2048 <= off <= 2046, f"b->{label}: {off}"
                hw = 0xE000 | ((off >> 1) & 0x7FF)
                out[at:at + 2] = hw.to_bytes(2, "little")
            else:
                assert kind in CONDS, kind
                assert -256 <= off <= 254, f"{kind}->{label}: {off}"
                out[at] = (off >> 1) & 0xFF
                out[at + 1] = 0xD0 | CONDS[kind]
        return bytes(out)


def build() -> tuple[bytes, dict[str, int]]:
    s = Stub()
    # ---------------- capture, reached from 0x5E80 ----------------
    s.at("cap")
    s.raw("1fb4")                     # push {r0,r1,r2,r3,r4}
    s.ldr(0, "mode")
    s.raw("0078")                     # ldrb r0,[r0]
    s.cbz(0, "cap_out")               # wired -> nothing to hold
    s.ldr(0, "state")
    s.raw("0178")                     # ldrb r1,[r0]        valid
    s.cbnz(1, "cap_out")
    s.raw("0121")                     # movs r1,#1
    s.raw("0170")                     # strb r1,[r0]
    s.raw("4370")                     # strb r3,[r0,#1]     position
    s.ldr(2, "ev")
    s.raw("92f80820")                 # ldrb.w r2,[r2,#8]  event byte
    s.raw("8270")                     # strb r2,[r0,#2]
    s.ldr(1, "now")
    s.raw("0968")                     # ldr r1,[r1]
    s.raw("4160")                     # str r1,[r0,#4]
    s.at("cap_out")
    s.raw("1fbc")                     # pop {r0,r1,r2,r3,r4}
    s.bw(EXIT)
    s.pad4()

    # ---------------- poll, reached from the main loop ----------------
    s.at("poll")
    s.raw("2de90f44")                 # push.w {r0,r1,r2,r3,r10,lr}
    s.ldr(0, "state")
    s.raw("0178")                     # ldrb r1,[r0]        valid
    s.cbz(1, "poll_cont")
    s.raw("4278")                     # ldrb r2,[r0,#1]     position
    s.ldr(3, "grid")
    s.raw("9a5c")                     # ldrb r2,[r3,r2]     id
    s.raw("9200")                     # lsls r2,r2,#2
    s.ldr(3, "rec")
    s.raw("9a5c")                     # ldrb r2,[r3,r2]     kind
    s.cbnz(2, "poll_ready")
    s.ldr(2, "now")
    s.raw("1268")                     # ldr r2,[r2]
    s.raw("4368")                     # ldr r3,[r0,#4]      stamp
    s.raw("d21a")                     # subs r2,r2,r3
    s.raw("40f22c13")                 # movw r3,#300
    s.raw("9a42")                     # cmp r2,r3
    s.bcond("bls", "poll_cont")
    s.raw("0021")                     # movs r1,#0
    s.raw("0170")                     # strb r1,[r0]        give up
    s.b("poll_cont")
    s.at("poll_ready")
    s.raw("0021")                     # movs r1,#0
    s.raw("0170")                     # strb r1,[r0]        cleared before replay
    s.raw("4278")                     # ldrb r2,[r0,#1]     position
    s.ldr(3, "ev")
    s.raw("83f80920")                 # strb.w r2,[r3,#9]   the handler reads this
    s.raw("8278")                     # ldrb r2,[r0,#2]     event byte
    s.raw("83f80820")                 # strb.w r2,[r3,#8]
    s.raw("0120")                     # movs r0,#1
    s.raw("8246")                     # mov r10,r0          sl != 0 -> macro branch
    s.bl(HANDLER)
    s.at("poll_cont")
    s.raw("bde80f44")                 # pop.w {r0,r1,r2,r3,r10,lr}
    s.bl(POLL_REPLAY)                 # replay the main loop's first call
    s.bw(POLL_NEXT)
    s.pad4()

    s.at("pool")
    for name, val in (("mode", MODE), ("state", STATE), ("now", NOW),
                      ("grid", GRID), ("rec", REC), ("ev", EV)):
        s.at(name)
        s.raw(val.to_bytes(4, "little").hex())

    stub = s.resolve(STUB)
    return stub, s.labels


def check(stub: bytes, lab: dict[str, int]) -> None:
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    got = [(hex(i.address), i.mnemonic, i.op_str) for i in md.disasm(stub[:lab["pool"]], STUB)]
    totals = sum(i.size for i in md.disasm(stub[:lab["pool"]], STUB))
    assert totals == lab["pool"], f"code has a gap: {totals:#x} vs {lab['pool']:#x}"

    def want(addr: int, mnemonic: str, ops: str | None = None) -> None:
        hits = [g for g in got if g[0] == hex(addr)]
        assert hits, f"no instruction at {addr:#x}"
        assert hits[0][1] == mnemonic, f"{addr:#x}: {hits[0][1]} != {mnemonic}"
        if ops is not None:
            assert hits[0][2] == ops, f"{addr:#x}: {hits[0][2]!r} != {ops!r}"

    cap = STUB
    want(cap, "push", "{r0, r1, r2, r3, r4}")
    poll = STUB + lab["poll"]
    want(poll, "push.w", "{r0, r1, r2, r3, sl, lr}")
    bls = [g for g in got if g[1] == "bl"]
    assert {f"#{HANDLER:#x}", f"#{POLL_REPLAY:#x}"} <= {g[2] for g in bls}, bls
    assert any(g[1] == "b.w" and g[2] == f"#{EXIT:#x}" for g in got), "no b.w to the exit"
    assert any(g[1] == "b.w" and g[2] == f"#{POLL_NEXT:#x}" for g in got), "no loop replay"
    assert any(g[1] == "mov" and g[2] == "sl, r0" for g in got), "sl is not set"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", type=Path,
                    default=OUT / "release" / "mini60he_max_remap.bin")
    ap.add_argument("--name", default="fw_defer")
    ap.add_argument("--out-dir", type=Path, default=OUT)
    ap.add_argument("--no-exe", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    if not args.base.exists():
        return fail(f"{args.base} not found")
    img = bytearray(args.base.read_bytes())
    if len(img) != IMG_LEN:
        return fail("wrong image length")
    if bytes(img[TAIL:TAIL + 4]) != bytes.fromhex("5555aaaa"):
        return fail("tail magic missing")
    base_sha = sha256(img)
    print(f"base     : {args.base.name} {base_sha}")
    if base_sha not in KNOWN_BASES:
        return fail("unrecognised base; pass the released image")
    print(f"           {KNOWN_BASES[base_sha]}")

    if bytes(img[CAP_SITE:CAP_SITE + 4]) != CAP_BYTES:
        return fail(f"0x{CAP_SITE:05X} is {bytes(img[CAP_SITE:CAP_SITE + 4]).hex(' ')},"
                    f" expected {CAP_BYTES.hex(' ')}")
    if bytes(img[POLL_SITE:POLL_SITE + 4]) != POLL_BYTES:
        return fail(f"0x{POLL_SITE:05X} is {bytes(img[POLL_SITE:POLL_SITE + 4]).hex(' ')},"
                    f" expected {POLL_BYTES.hex(' ')}")
    if any(img[STUB:STUB + STUB_LEN]):
        return fail(f"0x{STUB:05X} is not blank")

    stub, lab = build()
    if len(stub) > STUB_LEN:
        return fail(f"stub is {len(stub):#x} bytes, budget {STUB_LEN:#x}")
    check(stub, lab)

    patched = bytearray(img)
    patched[STUB:STUB + len(stub)] = stub
    # hook A: 0x5E80 -> capture
    patched[CAP_SITE:CAP_SITE + 4] = bw_bytes(CAP_SITE, STUB + lab["cap"])
    # hook B: 0x14E00 -> poll
    patched[POLL_SITE:POLL_SITE + 4] = bw_bytes(POLL_SITE, STUB + lab["poll"])

    changed = [i for i in range(IMG_LEN) if img[i] != patched[i]]
    allowed = (set(range(CAP_SITE, CAP_SITE + 4)) | set(range(POLL_SITE, POLL_SITE + 4))
               | set(range(STUB, STUB + STUB_LEN)))
    outside = [c for c in changed if c not in allowed]
    if outside:
        return fail(f"bytes changed outside the two hooks and the stub: "
                    f"{[hex(c) for c in outside]}")
    if len(patched) != IMG_LEN or bytes(patched[TAIL:TAIL + 4]) != bytes.fromhex("5555aaaa"):
        return fail("length or tail magic changed")
    if bytes(patched[:0x1000]) != bytes(img[:0x1000]):
        return fail("something below 0x1000 changed")

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    hook = next(iter(md.disasm(bytes(patched[CAP_SITE:CAP_SITE + 4]), CAP_SITE)))
    if (hook.mnemonic, hook.op_str) != ("b.w", f"#0x{STUB + lab['cap']:x}"):
        return fail(f"capture hook is {hook.mnemonic} {hook.op_str}")
    hook2 = next(iter(md.disasm(bytes(patched[POLL_SITE:POLL_SITE + 4]), POLL_SITE)))
    if (hook2.mnemonic, hook2.op_str) != ("b.w", f"#0x{STUB + lab['poll']:x}"):
        return fail(f"poll hook is {hook2.mnemonic} {hook2.op_str}")

    log: list[str] = []

    def p(*a):
        line = " ".join(str(x) for x in a)
        print(line)
        log.append(line)

    p("")
    p("the rule")
    p("  capture: wireless + empty record -> remember position, event byte, time")
    p("  poll   : every 10 ms, when IC(0x200024AE + id*4) != 0, restore the event")
    p("           into 0x200000F4 and call 0x5D28 again (sl = 1 so the macro")
    p("           branch is taken)")
    p(f"  give up after {DEADLINE_MS} ms -> the key stays silent, as today")
    p("")
    p("hooks")
    p(f"  0x{CAP_SITE:05X}  {CAP_BYTES.hex(' ')} -> {bytes(patched[CAP_SITE:CAP_SITE+4]).hex(' ')}"
      f"   b.w 0x{STUB + lab['cap']:05X}")
    p(f"  0x{POLL_SITE:05X}  {POLL_BYTES.hex(' ')} -> {bytes(patched[POLL_SITE:POLL_SITE+4]).hex(' ')}"
      f"   b.w 0x{STUB + lab['poll']:05X}")
    p(f"  stub   : 0x{STUB:05X}  {len(stub)} bytes of {STUB_LEN:#x}")
    p("")
    p(f"diff     : {len(changed)} bytes vs the base")
    p("")

    dst_bin = args.out_dir / f"{args.name}.bin"
    dst_exe = args.out_dir / f"{args.name}.exe"
    txt = args.out_dir / f"{args.name}_build.txt"
    p("out image:", dst_bin.name, IMG_LEN, "bytes", sha256(bytes(patched)))
    if args.dry_run:
        p("dry run  : nothing written")
        for i in md.disasm(stub[:lab["pool"]], STUB):
            p(f"  {i.address:05X}: {i.bytes.hex():12s} {i.mnemonic:8s} {i.op_str}")
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    dst_bin.write_bytes(bytes(patched))
    p("written  :", dst_bin)
    if not args.no_exe:
        import mkflasher
        if mkflasher.main([str(dst_bin), "--out", str(dst_exe)]) != 0:
            return fail("mkflasher refused the image")
        p("out exe  :", dst_exe.name, dst_exe.stat().st_size, "bytes",
          sha256(dst_exe.read_bytes()))
    txt.write_text("\n".join(log) + "\n", encoding="utf-8")
    p("report   :", txt)
    p("")
    p("test     : wired first (typing, Fn chords, macro); then wireless, idle, wake")
    p("           with the macro key - the macro should run on that first press,")
    p("           at most ~10 ms after the key goes down.")
    return 0


def bw_bytes(addr: int, target: int) -> bytes:
    off = target - (addr + 4)
    assert off % 2 == 0 and -0x1000000 <= off <= 0xFFFFFE
    u = off & 0x1FFFFFF
    s, i1, i2 = (u >> 24) & 1, (u >> 23) & 1, (u >> 22) & 1
    imm10, imm11 = (u >> 12) & 0x3FF, (u >> 1) & 0x7FF
    j1, j2 = (1 - i1) ^ s, (1 - i2) ^ s
    hw1 = 0xF000 | (s << 10) | imm10
    hw2 = 0x9000 | (j1 << 13) | (j2 << 11) | imm11
    return hw1.to_bytes(2, "little") + hw2.to_bytes(2, "little")


if __name__ == "__main__":
    sys.exit(main())
