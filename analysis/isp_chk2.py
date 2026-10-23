from pathlib import Path
import re, struct
import capstone, pefile

ROOT = Path(".")
raw = (ROOT / "bin" / "MINI 60 HE MAX_V1.52.exe").read_bytes()
pe = pefile.PE(data=raw)
base = pe.OPTIONAL_HEADER.ImageBase
ranges = []
for sec in pe.sections:
    name = sec.Name.rstrip(b"\x00").decode("latin-1")
    ranges.append((sec.PointerToRawData, sec.PointerToRawData + sec.SizeOfRawData,
                   base + sec.VirtualAddress, base + sec.VirtualAddress + sec.SizeOfRawData, name))

TEXT_SEC = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
text = raw[TEXT_SEC.PointerToRawData:TEXT_SEC.PointerToRawData + TEXT_SEC.SizeOfRawData]
text_va0 = base + TEXT_SEC.VirtualAddress

str_by_va = {}
for off0, off1, va0, va1, name in ranges:
    blob = raw[off0:off1]
    for wide in (False, True):
        step = 2 if wide else 1
        i = 0
        n = len(blob)
        while i + step <= n:
            b = blob[i:i + step][0]
            if 0x20 <= b < 0x7F:
                j, chars = i, []
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

iat_by_va = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode("latin-1")
    for imp in entry.imports:
        if imp.address and imp.name:
            iat_by_va[imp.address] = f"{dll}!{imp.name.decode('latin-1')}"

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

# find function 0x40a7d0 and 0x40a800 end (next fn start)
def next_fn(s):
    for f in fn_starts:
        if f >= s:
            return f
    return s + 0x100

def va_bytes(va):
    for off0, off1, va0, va1, name in ranges:
        if va0 <= va < va1:
            return raw[off0:off1], va - va0, name
    return None, None, None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.skipdata = True

def dump(start, stop, title):
    lines = [f"--- range {start:#x}..{stop:#x}  {title} ---"]
    blob, sect_off, secn = va_bytes(start)
    va0 = next(va_a for off0, off1, va_a, va_b, name in ranges if name == secn)
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
                lines.append(f"{insn.address:08X}  {insn.bytes.hex():<22s} {insn.mnemonic:8s} "
                             f"{insn.op_str}{'   ; ' + ' '.join(notes) if notes else ''}")
                r = (insn.address - va0) + insn.size
                break
        except Exception as e:
            lines.append(f"disasm error at {va0 + r:#x}: {e}")
            break
        if r <= n0:
            r = n0 + 1
    lines.append("--- end range ---")
    return lines

lines = []
for fn, tag in ((0x40a7d0, "SN8 checksum helper"), (0x40a800, "bin/hex checksum helper variant")):
    lines += dump(fn, next_fn(fn + 1), f"fn {fn:#x} whole ({tag})")

(ROOT / "analysis" / "out" / "chk_helpers.txt").write_text("\n".join(lines), encoding="utf-8")
print("wrote analysis/out/chk_helpers.txt", len(lines), "lines")
