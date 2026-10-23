"""fw_bake3.py - build the current multi-key remap bake (read-only on the vendor exe).

Model (hardware-verified except the last group, which is the same lever):
  the emitted usage comes from the per-key CATALOG at ROM 0x9600 + id*4 (usage at +2),
  which the init loader copies to RAM 0x200024AE.  The id<->usage PAIR table at
  0x16DDA only feeds the reverse lookup (usage -> id, fn 0x327C) that the Fn layer
  path uses to find per-key state, so it is kept in step with the catalog.

Edits:
  id 0x54 (old RAlt position)  Fn            usage 0xAF
  id 0x55 (stock Fn position)  Right Arrow   usage 0x4F
  id 0x4B (RShift)             Up Arrow      usage 0x52
  id 0x56 (Menu / App)         Left Arrow    usage 0x50
  id 0x57 (RCtrl)              Down Arrow    usage 0x51
  layer0 row 32 (0x16C7E)      RightArrow -> enum 0xB9 (consumer Volume Up)

Duplicate usages: ids 0x58/0x59/0x5A already carry Left/Down/Up but own no scan
position.  fn 0x327C scans the pair table ASCENDING and returns the first match,
so the lower (physical) id wins -> the edited ids stay authoritative.
"""
import hashlib
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
SRC_EXE = ROOT.parent / "bin" / "MINI 60 HE MAX_V1.52.exe"
IMG_SHA = "06a1a474"
IMG_OFF_IN_EXE = 0x1BAA4C
IMG_LEN = 0x7E000
DST_EXE = OUT / "MINI60HE_max_bake3.exe"
DST_BIN = OUT / "fw_bake3.bin"
REPORT = OUT / "fw_bake3.txt"

CATALOG = 0x9600
PAIRS = 0x16DDA
LAYER0 = 0x16C3E
SCANGRID = 0x16A96


def pair_index(key_id):
    return key_id if key_id < 0x6F else key_id - 1


def catalog_off(key_id):
    return CATALOG + key_id * 4 + 2


def pair_off(key_id):
    return PAIRS + pair_index(key_id) * 2 + 1


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def main():
    log = []

    def p(*a):
        line = " ".join(str(x) for x in a)
        log.append(line)
        print(line)

    raw = SRC_EXE.read_bytes()
    p("exe      :", SRC_EXE.name, len(raw), "bytes", sha256(raw))
    assert raw[:2] == b"MZ" and len(raw) == 2386384

    image = bytearray(raw[IMG_OFF_IN_EXE:IMG_OFF_IN_EXE + IMG_LEN])
    img_sha = sha256(image)
    p("image    : sha256", img_sha)
    assert img_sha.startswith(IMG_SHA), img_sha
    assert struct.unpack_from("<I", image, IMG_LEN - 4)[0] == 0xAAAA5555

    grid = bytes(image[SCANGRID:SCANGRID + 128])
    physical = set(grid) - {0x7D}
    for key_id in (0x54, 0x55, 0x4B, 0x56, 0x57):
        assert key_id in physical, "id %02X is not a physical position" % key_id
    for key_id in (0x58, 0x59, 0x5A, 0x5B):
        assert key_id not in physical, "id %02X unexpectedly physical" % key_id

    rows = bytes(image[LAYER0:LAYER0 + 0x66])
    assert rows[32 * 2:32 * 2 + 2] == bytes([0x4C, 0x49]), rows[64:66].hex()
    assert 0x4F not in rows[0::2], "a layer0 row is already keyed by Right Arrow"
    assert 0xAF not in rows[0::2], "a layer0 row is already keyed by Fn usage"

    media = struct.unpack_from("<12H", image, 0x16BF6)
    assert media[0xB9 - 0xB0] == 0x00E9, hex(media[0xB9 - 0xB0])

    catalog_edits = [
        (0x54, "old RAlt position", 0xE6, 0xAF),
        (0x55, "stock Fn position", 0xAF, 0x4F),
        (0x4B, "RShift", 0xE5, 0x52),
        (0x56, "Menu / App", 0x65, 0x50),
        (0x57, "RCtrl", 0xE4, 0x51),
    ]
    edits = []
    for key_id, name, old, new in catalog_edits:
        assert image[CATALOG + key_id * 4] == 0x02, "catalog id %02X is not kind 2" % key_id
        co = catalog_off(key_id)
        assert image[co] == old, "catalog id %02X holds %02X, expected %02X" % (key_id, image[co], old)
        edits.append((co, old, new, "catalog id 0x%02X %s -> usage 0x%02X" % (key_id, name, new)))
        po = pair_off(key_id)
        assert image[po] == old, "pair row id %02X holds %02X" % (key_id, image[po])
        edits.append((po, old, new, "pair table id 0x%02X -> usage 0x%02X" % (key_id, new)))

    assert image[0x16C7E] == 0x4C and image[0x16C7F] == 0x49
    edits.append((0x16C7E, 0x4C, 0x4F, "layer0 row 32 input: Insert -> Right Arrow"))
    edits.append((0x16C7F, 0x49, 0xB9, "layer0 row 32 output: Del -> enum 0xB9 Volume Up"))

    # The chip-version gate reads a dedicated dword of the image chosen by the
    # chip record, so it is not one of the table bytes below; the only structural
    # requirement is that no edit lands in the first 0x800 bytes (vector table /
    # boot header).  The layer0 and pair-table edits of the flashed bake1 were
    # accepted by the gate on hardware.
    for off, _old, _new, why in edits:
        assert 0x800 <= off < IMG_LEN, (off, why)

    for off, old, new, _why in edits:
        assert image[off] == old
        image[off] = new

    for key_id, name, old, new in catalog_edits:
        assert image[catalog_off(key_id)] == new
        assert image[pair_off(key_id)] == new
        carriers = [i for i in range(0x79) if i != 0x6F and image[pair_off(i)] == new]
        assert carriers and carriers[0] == key_id, \
            "usage %02X would resolve to id %s, not %02X" % (new, carriers, key_id)
    assert bytes(image[SCANGRID:SCANGRID + 128]) == grid, "scan grid must not change"
    assert len(bytes(image)) == IMG_LEN

    patched = bytearray(raw)
    patched[IMG_OFF_IN_EXE:IMG_OFF_IN_EXE + IMG_LEN] = image
    diff = [i for i in range(len(raw)) if raw[i] != patched[i]]
    assert len(diff) == len(edits), "unexpected diff count %d" % len(diff)
    assert diff == sorted(IMG_OFF_IN_EXE + off for off, _o, _n, _w in edits), "diff is not the edit set"
    assert len(patched) == len(raw)

    OUT.mkdir(exist_ok=True)
    DST_BIN.write_bytes(bytes(image))
    DST_EXE.write_bytes(bytes(patched))

    p("")
    p("edits    : %d byte changes" % len(edits))
    for off, old, new, why in edits:
        p("  0x%05X  %02X -> %02X   %s" % (off, old, new, why))
    p("")
    p("exe diff :", len(diff), "bytes at", " ".join("0x%06X" % x for x in diff))
    p("out bin  :", DST_BIN.name, len(image), "bytes", sha256(bytes(image)))
    p("out exe  :", DST_EXE.name, len(patched), "bytes", sha256(bytes(patched)))
    p("")
    p("expected wire behaviour")
    p("  old RAlt       -> Fn (emits 0xAF, no keystroke to host)")
    p("  old Fn         -> Right Arrow (0x4F)")
    p("  RShift         -> Up Arrow (0x52)")
    p("  Menu / App     -> Left Arrow (0x50)")
    p("  RCtrl          -> Down Arrow (0x51)")
    p("  Fn + old Fn    -> layer0 row 32 -> enum 0xB9 -> consumer 0x00E9 Volume Up")
    p("  Fn + F12 / F11 -> Volume Up / Down (stock rows 11/12, unchanged)")
    p("  lost           -> RShift, Menu, RCtrl, RAlt and the stock Fn position")

    REPORT.write_text("\n".join(log) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
