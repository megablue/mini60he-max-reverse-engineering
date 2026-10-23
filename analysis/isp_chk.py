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

targets = {
    0x55EE84: "'Bin File Check Sum : %.4X'",
    0x55EEB8: "'HEX File Check Sum : %.4X'",
    0x55E9E4: "'SN8 Check Sum : %.4X'",
    0x55F2E8: "'CheckBootLoaderID'",
}
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.skipdata = True

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


def containing_fn(site):
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


def va_bytes(va):
    for off0, off1, va0, va1, name in ranges:
        if va0 <= va < va1:
            return raw[off0:off1], va - va0, name
    return None, None, None


def dump(start, stop, title, lines):
    lines.append(f"--- range {start:#x}..{stop:#x}  {title} ---")
    blob, sect_off, secn = va_bytes(start)
    va0 = next(va_a for off0, off1, va_a, va_b, name in ranges if name == secn)
    r = sect_off
    stop_rel = sect_off + (stop - start)
    while r < stop_rel:
        n0 = r
        try:
            for insn in md.disasm(blob[r:stop_rel], va0 + r):
                lines.append(f"{insn.address:08X}  {insn.bytes.hex():<22s} {insn.mnemonic:8s} {insn.op_str}")
                r = (insn.address - va0) + insn.size
                break
        except Exception as e:
            lines.append(f"disasm error at {va0 + r:#x}: {e}")
            break
        if r <= n0:
            r = n0 + 1
    lines.append("--- end range ---")


lines = []
for va, label in targets.items():
    pat = struct.pack("<I", va)
    sites = []
    for i in range(len(text) - 4):
        if text[i:i + 4] == pat:
            sites.append(text_va0 + i)
    print(label, "refs:", [hex(s) for s in sites], "fns:", [hex(containing_fn(s)) for s in sites])
    lines.append("")
    lines.append(f"== {label}: sites {[hex(s) for s in sites]} in fns {[hex(containing_fn(s)) for s in sites]} ==")
    for s in sites:
        dump(s - 0x100, s + 0x40, f"context ref {s:#x}", lines)

out = "\n".join(lines)
(ROOT / "analysis" / "out" / "chksum_sites.txt").write_text(out, encoding="utf-8")
print("wrote analysis/out/chksum_sites.txt", len(lines), "lines")
