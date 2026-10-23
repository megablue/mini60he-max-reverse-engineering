#!/usr/bin/env python3
"""isp_open.py - close the four open questions left on docs/features/isp-protocol.html

  Q1  ISP password: exact wire length (short 0x40B7A1 form, long 0x40BB07 form)
  Q2  bank-A usage: the 05 20..24 echo loop (0x40C9D5..0x40CD9D zone)
  Q3  SZK gating:   references to the 'SZK671F' string
  Q4  EVT/I2C:      any EVT/I2C unlock strings and their code refs

Read-only: the pinned exe is opened as bytes (SHA-256 enforced), disassembled
with capstone. Never executed; no HID device touched -- static bytes only.

    python analysis/isp_open.py            # full report -> out/isp_open.txt

Artifact: analysis/out/isp_open.txt
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import capstone
import pefile

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "bin" / "MINI 60 HE MAX_V1.52.exe"
OUT = ROOT / "analysis" / "out"
REPORT = OUT / "isp_open.txt"

SHA256_PIN = "958A39951D2F908A7FE925E0FA598C321924CB235239BF37484AE7C8213512D6"

lines: list[str] = []


def out(*a):
    lines.append(" ".join(str(x) for x in a))


def hx(v: int) -> str:
    return f"0x{v:X}"


raw = EXE.read_bytes()
sha = hashlib.sha256(raw).hexdigest()
if sha.upper() != SHA256_PIN:
    raise SystemExit(f"pin mismatch: {sha}; refusing to analyze")
pe = pefile.PE(data=raw)
base = pe.OPTIONAL_HEADER.ImageBase

ranges = []
for sec in pe.sections:
    name = sec.Name.rstrip(b"\x00").decode("latin-1")
    ranges.append((sec.PointerToRawData, sec.PointerToRawData + sec.SizeOfRawData,
                   base + sec.VirtualAddress,
                   base + sec.VirtualAddress + sec.SizeOfRawData, name))


def va_bytes(va):
    for off0, off1, va0, va1, name in ranges:
        if va0 <= va < va1:
            return raw[off0:off1], va - va0, name
    return None, None, None


def off_va(off):
    for off0, off1, va0, va1, name in ranges:
        if off0 <= off < off1:
            return va0 + (off - off0), name
    return None, None


md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = False
md.skipdata = True

# ---------------------------------------------------------------- string maps
# Every printable ascii run and utf16 run in the whole file, keyed by VA.
str_by_va: dict[int, str] = {}


def harvest_str(blob: bytes, off0: int, va0: int, wide: bool):
    step = 2 if wide else 1
    i = 0
    n = len(blob)
    while i + step <= n:
        b = blob[i:i + step][0]
        if 0x20 <= b < 0x7F:
            j = i
            chars = []
            while j + step <= n:
                b2 = blob[j:j + step][0]
                if not (0x20 <= b2 < 0x7F):
                    break
                chars.append(chr(b2))
                j += step
            s = "".join(chars)
            if len(s) >= 4:
                str_by_va[va0 + i] = s
            i = j + step
        else:
            i += step


for off0, off1, va0, va1, name in ranges:
    blob = raw[off0:off1]
    harvest_str(blob, off0, va0, wide=True)
    harvest_str(blob, off0, va0, wide=False)

# ------------------------------------------------------------------- IAT map
iat_by_va: dict[int, str] = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode("latin-1")
    for imp in entry.imports:
        if imp.address and imp.name:
            iat_by_va[imp.address] = f"{dll}!{imp.name.decode('latin-1')}"

# ------------------------------------------------------- function starts (.text)
text_blob, text_rel, _ = va_bytes(base + pe.sections[0].VirtualAddress + 0)  # placeholder, fixed below

TEXT_SEC = None
for sec in pe.sections:
    if sec.Name.rstrip(b"\x00") == b".text":
        TEXT_SEC = sec
text_off0 = TEXT_SEC.PointerToRawData
text_size = TEXT_SEC.SizeOfRawData
text_va0 = base + TEXT_SEC.VirtualAddress
text = raw[text_off0:text_off0 + text_size]

import re  # noqa: E402

fn_starts = sorted({text_va0 + i for pat in (b"\x8b\xff\x55\x8b\xec", b"\x55\x8b\xec")
                    for i in range(len(text) - len(pat)) if text[i:i + len(pat)] == pat})
# stack-cookie / fastcall fns start right after int3 padding: >=4 x cc then code
run = 0
for i, b in enumerate(text):
    if b == 0xCC:
        run += 1
    else:
        if run >= 4 and i < len(text):
            fn_starts.append(text_va0 + i)
        run = 0
fn_starts = sorted(set(fn_starts))


def containing_fn(site: int):
    lo, hi = 0, len(fn_starts) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if fn_starts[mid] <= site:
            best = fn_starts[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return best


def dump(start: int, stop: int, title: str):
    """Disassemble VA range [start, stop) with annotations."""
    out(f"--- range {hx(start)}..{hx(stop)}  {title} ---")
    blob, sect_off, secn = va_bytes(start)
    va0 = None
    for off0, off1, va_a, va_b, name in ranges:
        if name == secn:
            va0 = va_a
    r = sect_off
    stop_rel = sect_off + (stop - start)
    while r < stop_rel:
        n0 = r
        try:
            for insn in md.disasm(blob[r:stop_rel], va0 + r):
                notes = []
                for tok in re.findall(r"0x[0-9a-fA-F]+", insn.op_str):
                    v = int(tok, 16)
                    if v in str_by_va:
                        notes.append(f"STR:{str_by_va[v]!r}")
                    if v in iat_by_va:
                        notes.append(f"IMP:{iat_by_va[v]}")
                b = insn.bytes.hex()
                out(f"{insn.address:08X}  {b:<22s} {insn.mnemonic:8s} "
                    f"{insn.op_str}{'   ; ' + ' '.join(notes) if notes else ''}")
                r = (insn.address - va0) + insn.size
                break
        except Exception as e:  # noqa: BLE001
            out(f"disasm error at {hx(va0 + r)}: {e}")
            break
        if r <= n0:
            r = n0 + 1  # no progress without an exception -> force move
    out("--- end range ---")


# ============================================================================ Q1
out("")
out("================================================================ Q1")
out("= Q1 password: wire length of Compare ISP Password frames")
out("================================================================")
# 0x40B7A1 = short 8B form site; 0x40BB07 = long 0x40 form site.
for site, tag in ((0x40B7A1, "short-form site"), (0x40BB07, "long 0x40-form site")):
    fn = containing_fn(site)
    out(f"site {hx(site)} ({tag}) sits in function start {hx(fn)}")
# Dump the code from just before each site backwards-inclusive windows,
# plus the whole containing function heads, to show the frame build + copy loop.
dump(0x40B6E0, 0x40B810, "password short form: frame build -> send")
dump(0x40BA60, 0x40BC40, "password long form: frame build -> send")

# ============================================================================ Q2
out("")
out("================================================================ Q2")
out("= Q2 bank-A usage: the 05 20..24 echo loop")
out("================================================================")
dump(0x40C900, 0x40CE00, "bank echo loop zone 0x40C9D5..0x40CD9D")

# ============================================================================ Q3
out("")
out("================================================================ Q3")
out("= Q3 SZK671F: string VA and every code reference")
out("================================================================")
# one pass over .text: record every dword immediate site once
def imm_sites():
    m = {}
    append = lambda v, s: m.setdefault(v, []).append(s)
    for i in range(len(text) - 4):
        append(int.from_bytes(text[i:i + 4], "little"), text_va0 + i)
    return m


sites_of = imm_sites()

# ============================================================================ Q3
out("")
out("================================================================ Q3")
out("= Q3 SZK671F: string VA and every code reference")
out("================================================================")
szk_vas = sorted(va for va, s in str_by_va.items() if s == "SZK671F")
out(f"SZK671F string occurrences: {[hx(v) for v in szk_vas]}")
szk_fns = set()
for va in szk_vas:
    hits = sites_of.get(va, [])
    out(f"VA {hx(va)}: .text refs {len(hits)}: {[hx(h) for h in hits]}")
    for h in hits:
        fn = containing_fn(h)
        out(f"function containing {hx(h)} starts at {hx(fn)}")
        szk_fns.add(fn)

for f in sorted(szk_fns):
    if f:
        dump(f, min(f + 0x900, 0x500000), f"function start {hx(f)} (SZK ref)")

# ============================================================================ Q4
out("")
out("================================================================ Q4")
out("= Q4 EVT / I2C strings and their VAs")
out("================================================================")
for needle in ("I2C", "Iic", "i2c", "EVT", "evt", "EvT"):
    vas = sorted(va for va, s in str_by_va.items() if needle in s)
    out(f"'{needle}': {len(vas)} string VAs")
    for va in vas[:40]:
        out(f"  {hx(va)}: {str_by_va[va]!r}")

# ------------------------------------------------------ Q4b wider needle sweep
out("")
out("================================================================ Q4b")
out("= Q4b wider needles: unlock/EDS/IIC/SPI/write-password strings")
out("================================================================")
NEEDLES = ("I2C", "IIC", "Iic", "i2c", "EVT", "evt", "unlock", "Unlock",
           "UNLOCK", "EDS", "SPI", "PRESERV", "erase")
for va, s in sorted(str_by_va.items()):
    low = s.lower()
    if any(n.lower() in low for n in NEEDLES):
        hits = sites_of.get(va, [])
        out(f"{hx(va)}: {s!r}  refs {len(hits)} {[hx(h) for h in hits[:4]]}")

# ============================================================ Q5 password path
out("")
out("================================================================ Q5")
out("= Q5 password path: callers of the two password frame builders,")
out("= and the 0x41D770 loader window around the pw resource handling")
out("================================================================")
# caller scan: direct call targets of the builder functions.
def call_sites(target):
    res = []
    for i in range(len(text) - 5):
        opcode = text[i:i + 5]
        if opcode[0] == 0xE8:
            rel = int.from_bytes(opcode[1:5], "little", signed=True)
            site = text_va0 + i
            if site + 5 + rel == target:
                res.append(site)
    return res

for target in (0x40B740, 0x40BAC0, 0x40BB80):
    sites = call_sites(target)
    out(f"call target {hx(target)}: sites {len(sites)} "
        f"{[hx(s) for s in sites]} fns {[hx(containing_fn(s)) for s in sites]}")

# the short-form builder 0x40B740 reads its dword from [ecx]; find how callers
# build ecx. Also dump the config loader window around any RCDATA 4007 mnemonic:
site4k7 = sites_of.get(4007, []) and sites_of.get(4007, [])[0]
if site4k7:
    fn0 = 0x41D770
    dump(fn0, min(fn0 + 0x1800, 0x550000), "config loader 0x41D770 head")

# ============================================================ cross-section SZK
out("")
out("================================================================ Q3b")
out("= Q3b SZK refs: which section, and +-64 byte windows at each ref")
out("================================================================")
def section_of(va):
    for off0, off1, va0, va1, name in ranges:
        if va0 <= va < va1:
            return name, va0, off0, va1 - va0
    return None, None, None, None

def hexwin(va, before=32, after=64):
    secname, va0, off0, size = section_of(va)
    if secname is None:
        out(f"  {hx(va)}: no section")
        return
    p = off0 + (va - va0)
    lo = max(0, p - before)
    hi = min(len(raw), p + after)
    for row in range(lo, hi, 16):
        chunk = raw[row:min(row + 16, hi)]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        # ascii rendering aligned
        asci = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        va_row = va0 + (row - off0)
        marks = "<--" if lo < row <= p - 16 or row <= p < row + 16 else ""
        out(f"  {va_row:08X}  {hexs:<47s} |{asci}|{marks}")

for va in szk_vas:
    out(f"string SZK671F at {hx(va)} (section {section_of(va)[0]})")
for site in [thermal for va in szk_vas for thermal in sites_of.get(va, [])]:
    secname = section_of(site)[0]
    out(f"ref site {hx(site)} in section {secname}")
    hexwin(site - 4, 32, 96)

# find .rdata/data pointers targeting near the SZK string usage zone:
# for each ref site S in a non-text section, scan raw for dword in [S-0x800, S]
out("")
out("== pointers into the SZK ref zones (searching all sections for dwords near each site) ==")
for site in sorted({s for va in szk_vas for s in sites_of.get(va, [])}):
    targets = set()
    for off in range(0, len(raw) - 4):
        v = int.from_bytes(raw[off:off + 4], "little")
        if site - 0x900 <= v <= site:
            va_p, _ = off_va(off)
            if va_p:
                targets.add((va_p, v))
    out(f"site {hx(site)}: {len(targets)} ptrs within 0x900 below")
    for va_p, v in sorted(targets)[:12]:
        out(f"  ptr {hx(va_p)} -> {hx(v)}  (delta {hx(site - v)})")

# ============================================================ Q6 targeted windows
out("")
out("================================================================ Q6")
out("= Q6 targeted windows: pw-builder call sites, loader RCDATA site,")
out("= SZK installer, SZK strings, C&C=IIC")
out("================================================================")
out("-- callers of 0x40B740 (short pw form), +-0x60 --")
for s in (0x40252E, 0x402FEE, 0x403A19, 0x405FFD, 0x40678B, 0x408BAB, 0x409D90):
    dump(s - 0x60, s + 0x40, f"caller window at {hx(s)}")
out("-- callers of 0x40BB80 (long pw form), +-0x60 --")
for s in (0x4027A2, 0x4031B0, 0x403CB3, 0x40618D, 0x40695D, 0x408D6C):
    dump(s - 0x60, s + 0x40, f"caller window at {hx(s)}")
out("-- loader RCDATA 4007 site window --")
site4k7b = sites_of.get(4007, [])
if site4k7b:
    dump(site4k7b[0] - 0x100, site4k7b[0] + 0x60, "RCDATA 4007 site in 0x41D770")
out("-- wrong_password string site refs --")
wp_vas = sorted(va for va, s in str_by_va.items() if "wrong password" in s.lower())
out(f"wrong-password strings: {[hx(v) for v in wp_vas]}")
for va in wp_vas:
    for h in sites_of.get(va, []):
        dump(h - 0x100, h + 0x200, f"wrong_password ref at {hx(h)}")
out("-- SZK installer full window 0x5560f0..0x556400 --")
dump(0x5560F0, 0x556400, "SZK installer (one of 5)")
out("-- strings around SZK671F (0x588F60..0x589080) --")
for va in [v for v in sorted(str_by_va) if 0x588F60 <= v <= 0x589080]:
    out(f"  {hx(va)}: {str_by_va[va]!r}")
out("-- C&C=IIC windows --")
for va in (0x56B0FE, 0x57EA5E):
    out(f"  {hx(va)} in section {section_of(va)[0]}")
    hexwin(va - 16, 128, 160)

# ============================================================ Q9 stack tracker
out("")
out("================================================================ Q9")
out("= Q9 symbolic-ESP frame reconstruction of the pw/wrappers builders")
out("================================================================")


def parse_num(s):
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def frame_trace(start: int, end: int, title: str):
    out(f"== frame trace {title}: {hx(start)}..{hx(end)} ==")
    blob, srel, secn = va_bytes(start)
    delta = 0  # current esp = entry_esp - delta
    for insn in md.disasm(blob[srel:srel + (end - start)], start):
        m, ops = insn.mnemonic, insn.op_str
        if m == "push":
            delta += 4
            out(f"{insn.address:08X}  PUSH      esp=E{delta:+d}")
            continue
        if m == "pop":
            delta -= 4
        elif m in ("sub", "add") and ops.startswith("esp,"):
            d = parse_num(ops.split(",", 1)[1].strip())
            delta += d if m == "sub" else -d
        newops = ops
        mt = re.search(r"\[esp\s*([+\-]?)\s*(0x[0-9a-f]+)?\]", ops)
        if mt:
            sgn = mt.group(1)
            val = parse_num(mt.group(2)) if mt.group(2) else 0
            if sgn == "-":
                val = -val
            abs_off = val - delta
            newops = ops.replace(mt.group(0), f"E{abs_off:+d}")
        if m == "call":
            out(f"{insn.address:08X}  CALL {newops}   (esp=E{delta:+d})")
        elif m in ("lea", "mov", "cmp") and "E" in newops:
            out(f"{insn.address:08X}  {m} {newops}" + (f"   [esp=E{delta:+d}]" if delta else ""))
    out("")


frame_trace(0x40B740, 0x40B830, "short pw form fn (8-byte frame)")
frame_trace(0x40B840, 0x40BA60, "fn 0x40B840 (??)")
frame_trace(0x40BB80, 0x40BC40, "fn 0x40BB80 (4-byte read + expect cmp)")
frame_trace(0x40BCE0, 0x40BEA0, "fn 0x40BCE0 (??)")

# ============================================================ Q7 pw bytes
out("")
out("================================================================ Q7")
out("= Q7 where the password bytes get into the frames")
out("================================================================")
out("-- tail of short-form fn 0x40B740 (0x40B810..0x40B858) --")
dump(0x40B810, 0x40B858, "fn 0x40B740 tail")
out("-- fn 0x407CA0 (Codeoption-Erase flow, calls 0x40BAC0 long pw form) --")
dump(0x407CA0, 0x4080F0, "fn 0x407CA0 full")
out("-- fn 0x408B50 head (Chip-Erase flow) --")
dump(0x408B50, 0x409000, "fn 0x408B50 head")
out("-- global 0x5b1d6c: window + code refs --")
hexwin(0x5B1D5C, 8, 56)
refs6c = sites_of.get(0x5B1D6C, []) + sites_of.get(0x5B1D68, [])
out(f"refs to 0x5B1D6C/0x5B1D68: {[hx(h) for h in refs6c]} fns {[hx(containing_fn(h)) for h in refs6c]}")

# ============================================================ Q8 rw-class
out("")
out("================================================================ Q8")
out("= Q8 0x5b1d6c read/write classification + loader RCDATA 4007 window")
out("================================================================")
import struct  # noqa: E402
for h in sorted(set(sites_of.get(0x5B1D6C, []))):
    blob, srel, secn = va_bytes(h)
    win = blob[srel - 2:srel + 12]
    insns = list(md.disasm(win, h))
    line = "; ".join(f"{i.mnemonic} {i.op_str} @ {hx(i.address)}" for i in insns[:2])
    # classify: write (mov [0x5b1d6c], reg) or read
    txt = (insns[0].mnemonic + " " + insns[0].op_str) if insns else ""
    if txt.startswith("mov dword ptr [0x5b1d6c]") or txt.startswith("mov [0x5b1d6c]"):
        cls = "WRITE"
    elif txt.startswith("mov"):
        cls = "READ"
    else:
        cls = "?"
    out(f"site {hx(h)} ({containing_fn(h) and hx(containing_fn(h))}): [{cls}] {line}")
out("-- RCDATA 4007 site inside loader 0x41D770 range --")
sig = [s for s in sites_of.get(4007, []) if 0x41D770 <= s < 0x41EF70]
out(f"sites in loader range: {[hx(s) for s in sig]}")
for s in sig:
    dump(s - 0x120, s + 0x180, f"loader 4007 site window {hx(s)}")
out("-- wrong_password usage inside loader (site ref) --")
wp_sites = sorted({s for v in wp_vas for s in sites_of.get(v, []) if 0x41D770 <= s < 0x41EF70})
for s in wp_sites:
    dump(s - 0x100, s + 0x200, f"loader wrong_password site {hx(s)}")

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"report: {len(lines)} lines -> {REPORT.name}")
