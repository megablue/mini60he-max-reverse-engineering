#!/usr/bin/env python3
"""isp_pw.py - close the password-payload leftovers on docs/features/isp-protocol.html

  W1  raw .data bytes / initial value at 0x5B1D6C, exact VA mapping
  W2  writer hunt: every encoding of 0x5B1D6C and neighbors 0x5B1D50..0x5B1D90
      across ALL sections (address-taking, cmp/mov forms, c7 05 imm writes,
      relocations, static pointer arrays)
  W3  short-frame 0x40B740 call sites: where does the payload pointer come from
  W4  RCDATA 4007 (id 0xFA7) consumers: FindResourceW/LockResource chains and
      every 0xFA7 immediate in the image
  W5  wire-dword candidates from '12345678' present as constants anywhere
  W6  the compare-gate function 0x40C140 context (cmp [0x5B1D6C],[esp+0x18])

Read-only: the pinned exe is opened as bytes (SHA-256 enforced). Never
executed; no HID device touched -- static bytes only.

    python analysis/isp_pw.py            # full report -> out/isp_pw.txt

Artifact: analysis/out/isp_pw.txt
"""
from __future__ import annotations

import hashlib
import re
import struct
from pathlib import Path

import capstone
import pefile

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "bin" / "MINI 60 HE MAX_V1.52.exe"
OUT = ROOT / "analysis" / "out"
REPORT = OUT / "isp_pw.txt"

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
for r in ranges:
    out(f"section {r[4]}: file {hx(r[0])}..{hx(r[1])} va {hx(r[2])}..{hx(r[3])}")

# overview for W1 anchor
for off0, off1, va0, va1, name in ranges:
    if va0 <= 0x5B1D6C < va1:
        out(f"0x5B1D6C lives in section {name}")


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
TEXT_SEC = None
for sec in pe.sections:
    if sec.Name.rstrip(b"\x00") == b".text":
        TEXT_SEC = sec
text_off0 = TEXT_SEC.PointerToRawData
text_size = TEXT_SEC.SizeOfRawData
text_va0 = base + TEXT_SEC.VirtualAddress
text = raw[text_off0:text_off0 + text_size]

fn_starts = sorted({text_va0 + i for pat in (b"\x8b\xff\x55\x8b\xec", b"\x55\x8b\xec")
                    for i in range(len(text) - len(pat)) if text[i:i + len(pat)] == pat})
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


# ============================================================ W1 .data raw view
out("")
out("================================================================ W1")
out("= W1 raw .data bytes at 0x5B1D50..0x5B1DA0 (file order, VA-labelled)")
out("================================================================")
for off0, off1, va0, va1, name in ranges:
    if va0 <= 0x5B1D50 < va1:
        rel = 0x5B1D50 - va0
        chunk = raw[off0 + rel:off0 + rel + 0x50]
        for k in range(0, len(chunk), 16):
            row = chunk[k:k + 16]
            hexs = " ".join(f"{b:02x}" for b in row)
            asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row)
            out(f"{0x5B1D50 + k:08X}  {hexs:<48s} |{asc}|")
        out(f"initial dword at 0x5B1D6C = "
            f"{hex(struct.unpack_from('<I', chunk, 0x5B1D6C - 0x5B1D50)[0])}")

# ================================ W2 writer hunt across every section & encoding
out("")
out("================================================================ W2")
out("= W2 writers: any encoding of 0x5B1D50..0x5B1D90 across ALL sections")
out("================================================================")
TARGET_LO, TARGET_HI = 0x5B1D50, 0x5B1D90
hits: dict[int, list[tuple[int, str]]] = {}
for off0, off1, va0, va1, name in ranges:
    blob = raw[off0:off1]
    for i in range(len(blob) - 4):
        v = int.from_bytes(blob[i:i + 4], "little")
        if TARGET_LO <= v < TARGET_HI and v % 4 == 0:
            site = va0 + i
            hits.setdefault(v, []).append((site, name))
for v in sorted(hits):
    for site, secn in hits[v]:
        out(f"value {hx(v)} referenced at {hx(site)} ({secn})")
# classify each .text hit: disasm a small window and show the instruction that
# actually encodes it (alignment-robust), then a read vs write vs addr-taken call
text_vas = {site for v, lst in hits.items() for site, secn in lst if secn == ".text"}
out("-- classification of each .text reference (window disasm) --")
for site in sorted(text_vas):
    win0 = site - 20
    blob, sect_off, secn = va_bytes(win0)
    va0 = None
    for off0, off1, va_a, va_b, name in ranges:
        if name == secn:
            va0 = va_a
    r = sect_off
    enc_insn = None
    insns_seen = []
    while r < sect_off + 64:
        try:
            for insn in md.disasm(blob[r:r + 48], va0 + r):
                insns_seen.append(insn)
                lo_i = va0 + r
                hi_i = lo_i + insn.size
                if lo_i <= site < hi_i:
                    enc_insn = insn
                    r = sect_off + (lo_i - va0) + insn.size
                    break
                r = sect_off + (lo_i - va0) + insn.size
        except Exception:  # noqa: BLE001
            r += 1
        if enc_insn is not None:
            break
    fn = containing_fn(site)
    if enc_insn is None:
        out(f"{hx(site)} in {hx(fn)}: NO containing instruction (byte-sequence only, "
            f"e.g. data inside another dword)")
        continue
    txt = f"{enc_insn.mnemonic} {enc_insn.op_str}"
    btxt = enc_insn.bytes.hex()
    if enc_insn.mnemonic == "lea":
        cls = "ADDR-TAKEN"
    elif enc_insn.mnemonic in ("mov", "add", "or", "xor", "and") and "," in enc_insn.op_str:
        dst = enc_insn.op_str.split(",")[0]
        # memory destination that is not a memory read: write form
        cls = "WRITE" if ("[" in dst and "]" in dst) else "READ"
    else:
        cls = "?"
    out(f"{hx(site)} in {hx(fn)}: [{cls}] {txt}   bytes={btxt}")

# ============================================== W3 args feeding short frame 0x40B740
out("")
out("================================================================ W3")
out("= W3 short-frame fn 0x40B740 call sites and payload-pointer provenance")
out("================================================================")


def call_sites(target: int) -> list[int]:
    found = []
    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            rel = int.from_bytes(text[i + 1:i + 5], "little", signed=True)
            va = text_va0 + i
            if va + 5 + rel == target:
                found.append(va)
    return sorted(found)


for tgt, tag in ((0x40B740, "short pw frame"), (0x40BAC0, "long pw frame")):
    out(f"-- call sites of {hx(tgt)} ({tag}) --")
    sites = call_sites(tgt)
    for s in sites:
        out(f"call site {hx(s)} in fn {hx(containing_fn(s))}")
        dump(s - 0x54, s + 0x10, f"args at call {hx(s)} -> {hx(tgt)}")

# ============================================== W4 RCDATA 4007 (id 0xFA7) consumer
out("")
out("================================================================ W4")
out("= W4 RCDATA-4007 consumer: FindResourceW chains and 0xFA7 immediates")
out("================================================================")
find_res_iat = [va for va, nm in iat_by_va.items() if "FindResource" in nm]
load_res_iat = [va for va, nm in iat_by_va.items() if "LoadResource" in nm]
lock_res_iat = [va for va, nm in iat_by_va.items() if "LockResource" in nm]
size_res_iat = [va for va, nm in iat_by_va.items() if "SizeofResource" in nm]
out(f"IAT: FindResourceW {[hx(v) for v in find_res_iat]} "
    f"LoadResourceW {[hx(v) for v in load_res_iat]} "
    f"LockResource {[hx(v) for v in lock_res_iat]} "
    f"SizeofResource {[hx(v) for v in size_res_iat]}")
# conversion imports anywhere in IAT
out("-- IAT names matching conversion --")
conv = [nm for va, nm in iat_by_va.items()
        if re.search(r"(wtoi|wtol|wcsto[lu]|atoi|atol| strtol|swscanf|_wtoi64)", nm, re.I)]
for va, nm in sorted(iat_by_va.items(), key=lambda kv: kv[1]):
    if re.search(r"atoi|atol|wcst|strto|wtoi|swscanf|sscanf", nm, re.I):
        out(f"  {hx(va)} {nm}")

for iat_va in find_res_iat:
    # call [iat] = ff 15 <disp32> in .text
    pat = b"\xff\x15" + struct.pack("<I", iat_va)
    for i in range(len(text) - 6):
        if text[i:i + 6] == pat:
            s = text_va0 + i
            out(f"FindResourceW call at {hx(s)} in fn {hx(containing_fn(s))}")
            dump(max(text_va0, s - 0x60), s + 0x10, f"FindResourceW args @ {hx(s)}")

# every 0xFA7 (4007) immediate site in .text
fa7_sites = []
for i in range(len(text) - 4):
    if int.from_bytes(text[i:i + 4], "little") == 4007:
        fa7_sites.append(text_va0 + i)
out(f"0xFA7 dword sites in .text: {[hx(s) for s in fa7_sites]}")
for s in fa7_sites:
    out(f"site {hx(s)} in fn {hx(containing_fn(s))}")
    dump(max(text_va0, s - 0x30), s + 0x20, f"0xFA7 site window @ {hx(s)}")

# ================================================== W5 dword-candidate presence
out("")
out("================================================================ W5")
out("= W5 '12345678' wire-dword candidates present as raw dwords in the exe")
out("================================================================")
s8 = "12345678"
candidates = {
    "ascii '1234' LE": int.from_bytes(s8[:4].encode("ascii"), "little"),
    "ascii '1234' BE": int.from_bytes(s8[:4].encode("ascii"), "big"),
    "dec(12345678)": 12345678,
    "hex(0x12345678)": 0x12345678,
    "utf16le '1','2'": int.from_bytes("12".encode("utf-16-le"), "little"),
    "utf16le dword at rcdata": int.from_bytes(s8[:2].encode("utf-16-le"), "little"),
}
for label, val in candidates.items():
    pat = struct.pack("<I", val)
    spots = []
    for off0, off1, va0, va1, name in ranges:
        blob = raw[off0:off1]
        start = 0
        while True:
            j = blob.find(pat, start)
            if j < 0:
                break
            spots.append((va0 + j, name))
            start = j + 1
    out(f"candidate {label} = {hex(val)}: "
        + (f"{len(spots)} hits: " + ", ".join(f"{hx(va)} ({secn})" for va, secn in spots[:40])
           if spots else "no static occurrence"))

# ==================================================== W6 compare-gate fn 0x40C140
out("")
out("================================================================ W6")
out("= W6 compare-gate functions 0x40C140 and 0x40CFE0 (cmp [0x5B1D6C],[esp+..])")
out("================================================================")
dump(0x40C140, 0x40C340, "fn 0x40C140 whole (compare gate + xor-eax fail tail)")
dump(0x40CFE0, 0x40D190, "fn 0x40CFE0 whole (compare gate + xor-eax fail tail)")

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"report: {len(lines)} lines -> {REPORT.name}")
