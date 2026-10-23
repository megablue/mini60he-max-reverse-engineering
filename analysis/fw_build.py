#!/usr/bin/env python3
"""fw_build.py - one command: remap requests -> firmware image -> patched updater.

    python analysis/fw_build.py "CapsLock=Esc" "Menu=Left"
    python analysis/fw_build.py "CapsLock=Esc" "Fn+Z=PlayPause"
    python analysis/fw_build.py --list

Outputs (all under analysis/out/, all git-ignored):
    <name>.bin        the patched 0x7E000 image
    <name>.exe        the vendor updater with that image in RT_RCDATA 0xFA0
    <name>.txt        mkflasher's manifest for the exe
    <name>_build.txt  this tool's report (requests, edits, wire behaviour, gates)

Two request kinds, both pure table data:
    KEY=TARGET       what a physical key sends. Edits the per-key CATALOG usage
                     (0x9600 + id*4 + 2) and the matching id<->usage PAIR row
                     (0x16DDA + index*2 + 1), which feeds the reverse lookup.
    Fn+KEY=ACTION    what Fn+KEY does. Edits one row of the Windows Fn overlay
                     (0x16C3E + row*2): input usage -> vendor action enum, whose
                     media half resolves through 0x16BF6.

Model (hardware-verified):
  the emitted usage comes from the catalog, copied by the init loader to RAM
  0x200024AE. The pair table feeds only the reverse lookup (usage -> id, fn
  0x327C) that the Fn path uses, so both are edited in step and never left
  disagreeing.

Why this is the safe lever:
  * an edit is one or two bytes in a table, in place, never a length change,
  * the tool's RCDATA size gate is unaffected (same length),
  * the checksum is computed tool-side from the loaded file, nothing to fix,
  * both tables sit above the version word the chip gate reads.

What a build does not carry: the NVM pages (0xB000/0xB600) where the companion
app stores its own per-key settings. A flash empties them, so this bake becomes
the boot-time truth.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fw_names import display, usage_of  # noqa: E402  (shared vocabulary)

SCRIPT_DIR = Path(__file__).resolve().parent
OUT = SCRIPT_DIR / "out"
IMG = OUT / "rcdata_4000.bin"

IMG_SHA256 = "06A1A47432A6CA7EC060103378E2D984A46F9AFA98F19FCCD99219EAEA4A88E0"
IMG_LEN = 0x7E000
TAIL_MAGIC = 0xAAAA5555

CATALOG = 0x9600          # 4 bytes per id: kind, ?, usage, 0
SENTINEL_AT = 0x16DD8     # sentinel row (0x7D, 0x00) immediately before the pairs
PAIRS = 0x16DDA           # 2 bytes per row: id, usage (120 rows)
PAIR_COUNT = 0x16EC8      # u16 row count
SCAN_GRID = 0x16A96       # 128 bytes of scan position -> id
SENTINEL_ID = 0x7D
LAYER0 = 0x16C3E          # Windows Fn overlay, 51 rows x 2 bytes
LAYER_ROWS = 51

CATALOG_BAND = (CATALOG, 0x9800)
PAIR_BAND = (PAIRS, PAIR_COUNT)
LAYER_BAND = (LAYER0, LAYER0 + LAYER_ROWS * 2)

# Fn-overlay output is a vendor action enum, not a HID usage. Media values
# resolve through the u16 table at 0x16BF6; the OS-switch and BT values were
# verified on hardware (Fn+A/S/D, Fn+W).
ACTIONS: dict[str, int] = {
    "android": 0x9C, "mac": 0xAB, "windows": 0xAC,
    "bt1": 0xA0, "bt2": 0xA1, "bt3": 0xA2, "pair": 0xA3, "bluetooth": 0xA3,
    "next": 0xB0, "prev": 0xB1, "stop": 0xB2, "playpause": 0xB3,
    "volume": 0xB4, "mute": 0xB5, "volup": 0xB9, "voldown": 0xBA,
}
ACTION_NAMES: dict[int, str] = {
    0x9C: "Android", 0xAB: "Mac", 0xAC: "Windows",
    0xA0: "BT1", 0xA1: "BT2", 0xA2: "BT3", 0xA3: "Pair",
    0xB0: "Next", 0xB1: "Prev", 0xB2: "Stop", 0xB3: "PlayPause",
    0xB4: "Volume", 0xB5: "Mute", 0xB9: "VolUp", 0xBA: "VolDown",
}


def pair_index(key_id: int) -> int:
    """Row index of an id: ids are ascending with 0x6F absent from the table."""
    return key_id if key_id < 0x6F else key_id - 1


def catalog_usage_off(key_id: int) -> int:
    return CATALOG + key_id * 4 + 2


def pair_usage_off(key_id: int) -> int:
    return PAIRS + pair_index(key_id) * 2 + 1


def row_off(row: int) -> int:
    return LAYER0 + row * 2


def sha256(data) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def action_of(spec) -> int:
    """Accept an action int, a 0xXX string, or a name from ACTIONS."""
    if isinstance(spec, int):
        return spec
    s = str(spec).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    if s.lower() in ACTIONS:
        return ACTIONS[s.lower()]
    known = ", ".join(sorted(ACTIONS))
    raise SystemExit(f"unknown action {spec!r}; use 0xXX or one of: {known}")


def action_name(value: int) -> str:
    return ACTION_NAMES.get(value, f"enum 0x{value:02X}")


class Tables:
    """The three tables a build touches, read once from the pinned image."""

    def __init__(self, img: bytes):
        count = int.from_bytes(img[PAIR_COUNT:PAIR_COUNT + 2], "little")
        assert count == 120, f"pair-table row count is {count}, expected 120"
        assert (img[SENTINEL_AT], img[SENTINEL_AT + 1]) == (SENTINEL_ID, 0x00), \
            "pair-table sentinel changed"
        self.count = count
        self.pairs = [(img[PAIRS + 2 + 2 * i], img[PAIRS + 3 + 2 * i]) for i in range(count)]
        self.by_id = {key_id: usage for key_id, usage in self.pairs}
        self.physical = {b for b in img[SCAN_GRID:SCAN_GRID + 128] if b != SENTINEL_ID}


def parse_requests(args) -> tuple[list[tuple[int, int, str]], list[tuple[int, int, str]]]:
    remaps: list[tuple[int, int, str]] = []
    fnrows: list[tuple[int, int, str]] = []
    for arg in args:
        if "=" not in arg:
            raise SystemExit(f"bad request {arg!r}; expected KEY=TARGET or Fn+KEY=ACTION")
        left, right = (s.strip() for s in arg.split("=", 1))
        try:
            if left.lower().startswith("fn+"):
                fnrows.append((usage_of(left[3:]), action_of(right), arg))
            else:
                remaps.append((usage_of(left), usage_of(right), arg))
        except SystemExit as exc:
            raise SystemExit(f"{arg}: {exc}") from None
    return remaps, fnrows


def list_map(tables: Tables) -> int:
    print("id   usage  name                     physical")
    for key_id, usage in tables.pairs:
        print(f"{key_id:02X}   {usage:02X}     {display(usage):<24s} "
              f"{'yes' if key_id in tables.physical else '-'}")
    print(f"\n{len({display(u) for _, u in tables.pairs})} names usable on the left of KEY=TARGET,")
    print("plus Fn+KEY=ACTION with " + ", ".join(sorted(ACTION_NAMES.values())))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="build a remapped firmware image and a patched updater",
        epilog='examples: python analysis/fw_build.py "CapsLock=Esc" "Fn+Z=PlayPause"')
    ap.add_argument("requests", nargs="*", metavar="KEY=TARGET",
                    help='KEY=TARGET for a key remap, Fn+KEY=ACTION for a Fn row')
    ap.add_argument("--name", default="fw_custom", help="output stem (default: fw_custom)")
    ap.add_argument("--out-dir", type=Path, default=OUT, help="output directory")
    ap.add_argument("--fn-row", type=int, metavar="N",
                    help="pin the Fn overlay row (0-50) instead of spending the first free one")
    ap.add_argument("--no-exe", action="store_true", help="write the image only")
    ap.add_argument("--dry-run", action="store_true", help="print the plan, write nothing")
    ap.add_argument("--list", action="store_true", help="print the current id map and exit")
    args = ap.parse_args(argv)

    if not IMG.exists():
        return fail(f"{IMG} is missing - run `python analysis/probe_pe.py` first")

    img = IMG.read_bytes()
    if sha256(img) != IMG_SHA256.lower():
        return fail(f"{IMG.name} is not the pinned stock image ({sha256(img)})")
    if len(img) != IMG_LEN:
        return fail(f"image is {len(img)} bytes, expected {IMG_LEN}")
    if int.from_bytes(img[-4:], "little") != TAIL_MAGIC:
        return fail("tail magic 55 55 AA AA is missing - wrong file?")

    tables = Tables(img)
    if args.list:
        return list_map(tables)
    if not args.requests:
        return fail('no requests given; try `--list`, then "CapsLock=Esc" or "Fn+Z=PlayPause"')
    try:
        remaps, fnrows = parse_requests(args.requests)
    except SystemExit as exc:
        return fail(str(exc))

    log: list[str] = []

    def p(*a):
        line = " ".join(str(x) for x in a)
        log.append(line)
        print(line)

    p("fw_build - requests -> image -> updater")
    p("stock    :", IMG.name, len(img), "bytes", sha256(img))
    p("")

    # ------------------------------------------------------- remaps (catalog)
    problems: list[str] = []
    edits: list[tuple[int, int, int, str]] = []      # offset, old, new, why
    requested: list[tuple[int, int]] = []            # (id, new usage)
    edited_ids: set[int] = set()
    for src_usage, dst_usage, raw in remaps:
        p(f"remap    : {raw}   ({display(src_usage)} -> {display(dst_usage)})")
        carriers = [i for i, u in tables.pairs if u == src_usage]
        if not carriers:
            problems.append(f"{raw}: no id sends usage 0x{src_usage:02X} ({display(src_usage)})")
            continue
        physical = sorted(i for i in carriers if i in tables.physical)
        if not physical:
            phantom = ", ".join(f"{i:02X}" for i in carriers)
            problems.append(f"{raw}: usage 0x{src_usage:02X} sits only on ids {phantom}, "
                            "none of which owns a scan position - not a key on this board")
            continue
        key_id = physical[0]
        if len(physical) > 1:
            others = ", ".join(f"{i:02X}" for i in physical[1:])
            p(f"  note   : ids {others} also send it; editing the lowest physical id {key_id:02X}")
        if key_id in edited_ids:
            problems.append(f"{raw}: id {key_id:02X} is already being edited by another request")
            continue
        old_usage = tables.by_id[key_id]
        if old_usage == dst_usage:
            p(f"  skip   : id {key_id:02X} already sends {display(old_usage)}")
            continue
        if dst_usage == 0:
            problems.append(f"{raw}: refusing to make a physical key send usage 0x00 (nothing)")
            continue
        kind = img[CATALOG + key_id * 4]
        if kind != 2:
            problems.append(f"{raw}: catalog id {key_id:02X} is kind {kind}, not a plain usage "
                            "record - inspect it before editing")
            continue
        cat_old = img[catalog_usage_off(key_id)]
        pair_old = img[pair_usage_off(key_id)]
        if not (cat_old == pair_old == old_usage):
            problems.append(f"{raw}: catalog/pair disagree for id {key_id:02X} "
                            f"({cat_old:02X}/{pair_old:02X}/{old_usage:02X}) - build from the stock image")
            continue
        edited_ids.add(key_id)
        requested.append((key_id, dst_usage))
        edits.append((catalog_usage_off(key_id), old_usage, dst_usage,
                      f"catalog id {key_id:02X} ({display(old_usage)}) -> {display(dst_usage)}"))
        edits.append((pair_usage_off(key_id), old_usage, dst_usage,
                      f"pair    id {key_id:02X} ({display(old_usage)}) -> {display(dst_usage)}"))
        p(f"  edit   : id {key_id:02X} ({display(old_usage)}, physical) -> {display(dst_usage)}")

    final = dict(tables.by_id)
    for key_id, dst_usage in requested:
        final[key_id] = dst_usage
    physical_usages = {final[i] for i in tables.physical if i in final}

    # ------------------------------------------------------- Fn rows
    taken_rows: set[int] = set()
    fn_applied: list[tuple[int, int, int]] = []
    for src_usage, action, raw in fnrows:
        p("")
        p(f"fn row   : {raw}   (Fn+{display(src_usage)} -> {action_name(action)})")
        if src_usage == 0xAF:
            problems.append(f"{raw}: Fn+Fn is not a combination the dispatcher can form")
            continue
        if action == 0:
            problems.append(f"{raw}: refusing action enum 0x00")
            continue
        if action < 0x90:
            problems.append(f"{raw}: 0x{action:02X} is below the Fn output space "
                            "(the enum starts at 0x9C) - that would not be an action")
            continue
        if src_usage not in physical_usages:
            problems.append(f"{raw}: no physical key sends {display(src_usage)}; "
                            "remap one to it in the same run, or the combination can never fire")
            continue
        existing = [r for r in range(LAYER_ROWS) if img[row_off(r)] == src_usage]
        if existing:
            row = existing[0]
            if row in taken_rows:
                problems.append(f"{raw}: row {row} is already being written by another request")
                continue
            p(f"  row    : {row} already keyed {display(src_usage)} - updating its output")
        elif args.fn_row is not None:
            if not 0 <= args.fn_row < LAYER_ROWS:
                problems.append(f"{raw}: --fn-row {args.fn_row} is outside 0..{LAYER_ROWS - 1}")
                continue
            row = args.fn_row
            dead = img[row_off(row)] not in physical_usages
            if not dead:
                problems.append(f"{raw}: row {args.fn_row} is live "
                                f"({display(img[row_off(row)])}) - pick another or drop --fn-row")
                continue
            p(f"  row    : {row}, was {display(img[row_off(row)])} -> "
              f"{action_name(img[row_off(row) + 1])}")
        else:
            free = [r for r in range(LAYER_ROWS)
                    if r not in taken_rows and img[row_off(r)] not in physical_usages]
            if not free:
                problems.append(f"{raw}: no free Fn row left (all 51 inputs are live)")
                continue
            row = free[0]
            p(f"  row    : spending row {row} (was "
              f"{display(img[row_off(row)])} -> {action_name(img[row_off(row) + 1])})")
        taken_rows.add(row)
        old_key, old_action = img[row_off(row)], img[row_off(row) + 1]
        if (old_key, old_action) == (src_usage, action):
            p("  skip   : row already says exactly that")
            continue
        if old_key != src_usage:
            edits.append((row_off(row), old_key, src_usage,
                          f"layer0 row {row} input: {display(old_key)} -> {display(src_usage)}"))
        if old_action != action:
            edits.append((row_off(row) + 1, old_action, action,
                          f"layer0 row {row} output: {action_name(old_action)} -> {action_name(action)}"))
        fn_applied.append((row, src_usage, action))
        p(f"  edit   : row {row} ({display(src_usage)}) -> {action_name(action)}")

    # ------------------------------------------------------- duplicate check
    dup = Counter(u for u in final.values() if u)
    for key_id, dst_usage in requested:
        if dup[dst_usage] < 2:
            continue
        carriers = sorted(i for i, u in final.items() if u == dst_usage)
        held_before = [i for i, u in tables.by_id.items() if u == dst_usage]
        if carriers[0] != key_id:
            p(f"  WARNING: {display(dst_usage)} also sits on lower id {carriers[0]:02X}; the Fn-layer "
              "reverse lookup (fn 0x327C, ascending) will attribute it there")
        elif held_before:
            p(f"  note   : {display(dst_usage)} now has two holders "
              f"{', '.join(f'{i:02X}' for i in carriers)} - intended when two keys should do one job")
        else:
            problems.append(f"usage 0x{dst_usage:02X} ({display(dst_usage)}) gains a second holder "
                            f"{', '.join(f'{i:02X}' for i in carriers)}; that duplicate is new")

    if problems:
        p("")
        for problem in problems:
            p("  PROBLEM:", problem)
        p("")
        return fail(f"{len(problems)} problem(s); nothing written")
    if not edits:
        return fail("no edits to make; nothing written")

    # ------------------------------------------------------- apply
    patched = bytearray(img)
    for offset, old, new, _why in edits:
        assert patched[offset] == old, f"byte {offset:#x} does not hold {old:02X}"
        patched[offset] = new

    diff = sorted(i for i in range(len(img)) if img[i] != patched[i])
    assert diff == sorted(off for off, _o, _n, _w in edits), "diff is not the edit set"
    assert bytes(patched[SCAN_GRID:SCAN_GRID + 128]) == bytes(img[SCAN_GRID:SCAN_GRID + 128]), \
        "the scan grid must not change"
    assert len(patched) == IMG_LEN
    for offset, _o, _n, _w in edits:
        inside = [CATALOG_BAND, PAIR_BAND, LAYER_BAND]
        assert any(lo <= offset < hi for lo, hi in inside), \
            f"edit at {offset:#x} is outside every table this tool owns"

    p("")
    p(f"edits    : {len(edits)} bytes / {len(requested)} remap(s) / {len(fn_applied)} Fn row(s)")
    for offset, old, new, why in edits:
        p(f"  0x{offset:05X}  {old:02X} -> {new:02X}   {why}")
    p("")
    p("image    : length unchanged, scan grid unchanged, only the catalog, pair table and Fn overlay touched")
    p("gates    : size gate unaffected (same length); tool-side checksum recomputed from the file;")
    p("           version word far below the lowest edited offset")

    # ------------------------------------------------------- outputs
    out_dir = args.out_dir
    dst_bin = out_dir / f"{args.name}.bin"
    dst_exe = out_dir / f"{args.name}.exe"
    report = out_dir / f"{args.name}_build.txt"

    p("")
    p("expected wire behaviour")
    for key_id, dst_usage in requested:
        p(f"  id {key_id:02X}  was {display(tables.by_id[key_id]):<12s} now {display(dst_usage)}")
    for row, src_usage, action in fn_applied:
        p(f"  Fn+{display(src_usage)} -> {action_name(action)} (row {row}, enum 0x{action:02X})")
    lost = sorted({display(u) for i, u in tables.by_id.items()
                   if i in tables.physical and u not in final.values()})
    if lost:
        p(f"  no physical key sends {', '.join(lost)} any more")
    p("  NVM      : the app's own remaps/settings in 0xB000/0xB600 are NOT in this image;")
    p("             flashing it empties them, so this bake becomes the boot-time truth")

    p("")
    p("out image:", dst_bin.name, len(patched), "bytes", sha256(patched))
    if args.dry_run:
        p("dry run  : nothing written")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    dst_bin.write_bytes(bytes(patched))
    p("written  :", dst_bin)

    if not args.no_exe:
        import mkflasher
        rc = mkflasher.main([str(dst_bin), "--out", str(dst_exe)])
        if rc != 0:
            return fail("mkflasher refused the image; see the message above")
        p("")
        p("out exe  :", dst_exe.name, dst_exe.stat().st_size, "bytes", sha256(dst_exe.read_bytes()))

    report.write_text("\n".join(log) + "\n", encoding="utf-8")
    p("report   :", report)
    if not args.no_exe:
        p("")
        p("flash    : run the updater, pick this exe, Start.")
        p("           One-way write: no readback exists, and every flash empties the NVM pages.")
    return 0


def fail(message: str) -> int:
    print("error:", message, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
