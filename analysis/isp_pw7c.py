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


LO, HI = 0x5B0000, 0x5B3000
by_target = {}
for i in range(len(text) - 4):
    va = text_va0 + i
    v = int.from_bytes(text[i:i + 4], "little")
    if LO <= v < HI and v % 4 == 0 and va % 4 == 0:
        by_target.setdefault(v, []).append(va)

out = []
for v in sorted(by_target):
    sites = by_target[v]
    fns = sorted({containing_fn(s) for s in sites})
    out.append(f"{v:#X}: {len(sites)} sites fns {[hex(f) for f in fns]}")
    for s in sites[:6]:
        out.append(f"    site {s:#X}")

print("\n".join(out))
