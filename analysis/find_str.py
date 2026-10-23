from pathlib import Path

raw = Path("bin/MINI 60 HE MAX_V1.52.exe").read_bytes()
RD_OFF, RD_VA = 0x15A000, 0x55B000

targets = {
    "Bin File Check Sum : %.4X": None,
    "HEX File Check Sum : %.4X": None,
    "SN8 Check Sum : %.4X": None,
    "CheckBootLoaderID": None,
}
for s in list(targets):
    t = s.encode("ascii")
    va = None
    j = raw.find(t, RD_OFF, 0x1A7C00)
    if j >= 0:
        va = RD_VA + (j - RD_OFF)
    else:
        j = raw.find(t.decode("ascii").encode("utf-16-le"), 0)
        if j >= 0:
            va = ("utf16 hit at file " + hex(j))
    targets[s] = va

for s, v in targets.items():
    print(v, repr(s))
