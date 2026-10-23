"""Build a patched copy of the bundled firmware image with
Fn + <Right Arrow> = Volume Up.

The stock Fn map (layer0 @ 0x16C3E, 51 rows of `usage -> action`) has no row
keyed on 0x4F (Right Arrow), so the chord is dropped.  Row 32 is
`0x4C (Insert) -> 0x49 (Delete)`, and no scan position can emit Insert, so the
row is dead weight.  It is repurposed:

    0x16C7E:  4C 49   ->   4F B9
              Ins->Del      RightArrow->Vol+

0xB9 is the media enum value for Volume Up: the enum at 0x16BF6 is indexed as
`0xB0 + k` into consumer usages, and four members were confirmed on hardware
(0xB0 Next, 0xB1 Prev, 0xB3 Play/Pause, 0xB5 Mute); 0xB9 resolves to 0x00E9.

By default the two user remaps are baked in as well, so the patched image needs
no app-side (NVM) settings at all.  The Fn state is driven by the usage VALUE
0xAF, not by a fixed key id (proved on hardware: the key at the old RAlt
position produces F1 today only because an app remap put usage 0xAF on it), and
the usage table (0x16DDA, 120 `(id, usage)` pairs) is per-id, so moving the
value between two ids moves the role between two physical keys:

    0x16E83:  E6 -> AF   id 0x54 (old RAlt) becomes the Fn key
    0x16E85:  AF -> 4F   id 0x55 (old Fn)   becomes Right Arrow

`--chord-only` skips those two and leaves the chord dependent on the app remap
(the pre-2026-10-24 behaviour).

Never touches the exe.  Writes only under analysis/out/.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

SRC = Path("analysis/out/rcdata_4000.bin")
DST = Path("analysis/out/fw_volplus.bin")
REPORT = Path("analysis/out/fw_volpatch.txt")

EXPECT_SIZE = 0x7E000
EXPECT_SHA = "06a1a47432a6ca7ec060103378e2d984a46f9afa98f19fccd99219eaea4a88e0"

LAYER0 = 0x16C3E
LAYER0_COUNT_ADDR = 0x16CA4
SCANMAP = 0x16A96
SCANMAP_LEN = 128
EMPTY = 0x7D
USAGE_TABLE = 0x16DDA
USAGE_COUNT = 120
MEDIA_ENUM = 0x16BF6

ROW = 32                        # Insert -> Delete in the factory image
ROW_USAGE_OLD, ROW_ACTION_OLD = 0x4C, 0x49
ROW_USAGE_NEW = 0x4F            # Right Arrow
ACTION_VOL_UP = 0xB9            # enum 0xB0+9 -> consumer 0x00E9
RIGHT_ARROW_ID = 0x5B

# --- role bake (physical keys used by the owner) --------------------------
FN_ID = 0x54                    # old RAlt position: becomes the Fn key
FN_ID_USAGE_OLD = 0xE6
FN_USAGE = 0xAF
OLD_FN_ID = 0x55                # stock Fn position: becomes Right Arrow
OLD_FN_USAGE_OLD = 0xAF


def u16(b: bytes | bytearray, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def main(argv: list[str]) -> int:
    chord_only = "--chord-only" in argv

    stock = SRC.read_bytes()
    img = bytearray(stock)
    lines: list[str] = []
    log = lines.append

    log("stock image: %s" % SRC)
    log("  size 0x%X  sha256 %s" % (len(img), hashlib.sha256(img).hexdigest()))
    assert len(img) == EXPECT_SIZE, "unexpected image size"
    assert hashlib.sha256(img).hexdigest() == EXPECT_SHA, "image sha mismatch"
    assert img[-4:] == b"\x55\x55\xaa\xaa", "tail magic missing"

    # --- preconditions ---------------------------------------------------
    count = u16(img, LAYER0_COUNT_ADDR)
    assert count == 51, "layer0 row count changed: %d" % count

    row_off = LAYER0 + 2 * ROW
    assert (img[row_off], img[row_off + 1]) == (ROW_USAGE_OLD, ROW_ACTION_OLD), (
        "row %d is not the expected Ins->Del row: %02X %02X"
        % (ROW, img[row_off], img[row_off + 1])
    )

    phys = sorted({img[SCANMAP + i] for i in range(SCANMAP_LEN)} - {EMPTY})
    usage = {img[USAGE_TABLE + 2 * i]: img[USAGE_TABLE + 2 * i + 1]
             for i in range(USAGE_COUNT)}
    live = {usage[i] for i in phys}
    assert ROW_USAGE_OLD not in live, "Insert is reachable; row 32 is not dead"
    assert ROW_USAGE_NEW not in live, "Right Arrow already reachable; duplicate row"

    enum_vol_up = u16(img, MEDIA_ENUM + 2 * (ACTION_VOL_UP - 0xB0))
    assert enum_vol_up == 0x00E9, "0xB9 no longer resolves to consumer Vol+"

    def usage_off(key_id: int) -> int:
        for i in range(USAGE_COUNT):
            if img[USAGE_TABLE + 2 * i] == key_id:
                return USAGE_TABLE + 2 * i + 1
        raise AssertionError("key id 0x%02X is not in the usage table" % key_id)

    fn_off = usage_off(FN_ID)
    old_fn_off = usage_off(OLD_FN_ID)
    assert img[fn_off] == FN_ID_USAGE_OLD, "id 0x%02X does not carry 0x%02X" % (FN_ID, FN_ID_USAGE_OLD)
    assert img[old_fn_off] == OLD_FN_USAGE_OLD, "id 0x%02X does not carry 0x%02X" % (OLD_FN_ID, OLD_FN_USAGE_OLD)
    fn_carriers = [i for i in range(USAGE_COUNT) if img[USAGE_TABLE + 2 * i + 1] == FN_USAGE]
    assert [img[USAGE_TABLE + 2 * i] for i in fn_carriers] == [OLD_FN_ID], (
        "usage 0x%02X is not uniquely on id 0x%02X" % (FN_USAGE, OLD_FN_ID))
    assert FN_ID in phys and OLD_FN_ID in phys, "one of the two ids has no scan position"
    layer0_keys = {img[LAYER0 + 2 * r] for r in range(count)}
    assert FN_USAGE not in layer0_keys, "layer0 already has a row keyed 0x%02X" % FN_USAGE
    assert ROW_USAGE_NEW not in layer0_keys, "layer0 already has a row keyed 0x%02X" % ROW_USAGE_NEW

    log("  layer0 rows         : %d (count u16 @0x%05X)" % (count, LAYER0_COUNT_ADDR))
    log("  row %-2d @0x%05X    : %02X %02X  (usage 0x%02X -> action 0x%02X)"
        % (ROW, row_off, img[row_off], img[row_off + 1], ROW_USAGE_OLD, ROW_ACTION_OLD))
    log("  Insert reachable    : no  (dead row, safe to repurpose)")
    log("  Right Arrow reach.  : no  (0x%02X only via id 0x%02X / app remap)"
        % (ROW_USAGE_NEW, RIGHT_ARROW_ID))
    log("  enum 0x%02X           : consumer 0x%04X = Volume Up" % (ACTION_VOL_UP, enum_vol_up))
    log("  Fn usage 0x%02X       : only id 0x%02X carries it, usage byte 0x%05X = %02X"
        % (FN_USAGE, OLD_FN_ID, old_fn_off, img[old_fn_off]))
    log("  RAlt usage 0x%02X     : only id 0x%02X carries it, usage byte 0x%05X = %02X"
        % (FN_ID_USAGE_OLD, FN_ID, fn_off, img[fn_off]))
    log("  role bake           : %s" % ("skipped (--chord-only)" if chord_only else "ON"))

    # --- edits -----------------------------------------------------------
    edits: list[tuple[int, int, int, str]] = [
        (row_off, ROW_USAGE_OLD, ROW_USAGE_NEW,
         "Fn map row %d: input usage Insert -> Right Arrow" % ROW),
        (row_off + 1, ROW_ACTION_OLD, ACTION_VOL_UP,
         "Fn map row %d: output Delete -> Volume Up" % ROW),
    ]

    if not chord_only:
        edits.append((fn_off, FN_ID_USAGE_OLD, FN_USAGE,
                      "usage table id 0x%02X: RAlt -> Fn  (that key becomes the Fn key)" % FN_ID))
        edits.append((old_fn_off, OLD_FN_USAGE_OLD, ROW_USAGE_NEW,
                      "usage table id 0x%02X: Fn -> Right Arrow  (that key emits 0x%02X)"
                      % (OLD_FN_ID, ROW_USAGE_NEW)))

    log("")
    log("edits:")
    for off, old, new, why in edits:
        assert img[off] == old, "precondition failed at 0x%05X" % off
        img[off] = new
        log("  0x%05X: %02X -> %02X   %s" % (off, old, new, why))

    # --- verify ----------------------------------------------------------
    patched = bytes(img)
    diff = [o for o in range(len(patched)) if patched[o] != stock[o]]
    assert len(diff) == len(edits), "unexpected diff size: %s" % diff
    assert set(diff) == {e[0] for e in edits}, "diff outside intended offsets"
    assert patched[:SCANMAP] == stock[:SCANMAP], "bytes before the tables changed"
    assert len(patched) == EXPECT_SIZE, "length changed (size gate)"
    assert u16(patched, LAYER0_COUNT_ADDR) == count, "row count changed"

    log("")
    log("verify:")
    log("  differing bytes     : %d at %s" % (len(diff), [hex(o) for o in diff]))
    log("  length              : 0x%X (unchanged -> RCDATA size gate unaffected)" % len(patched))
    log("  first 0x%05X bytes   : identical (version gate words untouched)" % SCANMAP)
    log("  patched sha256      : %s" % hashlib.sha256(patched).hexdigest())

    DST.write_bytes(patched)
    log("")
    log("wrote %s (0x%X bytes)" % (DST, len(patched)))
    log("")
    log("what the patched image does:")
    if chord_only:
        log("  Fn + <key emitting Right Arrow> -> Volume Up")
        log("  everything else: byte-identical to the factory image")
    else:
        log("  <old RAlt key> (id 0x%02X)      -> Fn" % FN_ID)
        log("  <stock Fn key> (id 0x%02X)      -> Right Arrow" % OLD_FN_ID)
        log("  Fn + Right Arrow                 -> Volume Up (consumer 0x00E9)")
        log("  everything else: byte-identical to the factory image")
        log("  no app-side (NVM) remap needed")
    if chord_only:
        log("")
        log("note: --chord-only leaves both keys stock, so Right Arrow has to reach")
        log("      the Fn lookup through the app-side remap (pre-2026-10-24 state).")

    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
