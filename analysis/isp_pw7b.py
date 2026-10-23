from pathlib import Path
import struct
import pefile

ROOT = Path(".")
raw = (ROOT / "bin" / "MINI 60 HE MAX_V1.52.exe").read_bytes()
pe = pefile.PE(data=raw)
base = pe.OPTIONAL_HEADER.ImageBase

TEXT_SEC = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
text = raw[TEXT_SEC.PointerToRawData:TEXT_SEC.PointerToRawData + TEXT_SEC.SizeOfRawData]
text_va0 = base + TEXT_SEC.VirtualAddress

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


# disp32 byte runs; preceding modrm must be mod=10 (regUses disp32)
def scan_disp(disp: int, ops: set[int]):
    pat = struct.pack("<I", disp)
    hits = []
    for i in range(len(text) - 6):
        if text[i:i + 4] != pat:
            continue
        modrm = text[i - 2]
        opcode = text[i - 1]
        if (modrm & 0xC0) == 0x80 and opcode in ops:
            hits.append((text_va0 + i - 1, opcode, modrm))
    return hits

OPS = {0x8B, 0x89, 0x8D, 0x3B, 0x39, 0xC7, 0x83, 0x80}
print("=== disp 0xEC references (dialog pw CString) ===")
for va, op, modrm in scan_disp(0xEC, OPS):
    print(f"  {va:#X} fn {containing_fn(va) or '-':#X} bytes {op:02X} {modrm:02X}")

print("=== disp 0x1C stores (op 89/8B-only metadata skipped; first 40) ===")
n = 0
for va, op, modrm in scan_disp(0x1C, OPS):
    if n >= 40:
        break
    n += 1
    print(f"  {va:#X} fn {containing_fn(va) or '-':#X} bytes {op:02X} {modrm:02X}")
