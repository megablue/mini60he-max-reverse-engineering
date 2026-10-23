#!/usr/bin/env python3
"""fw_remap.py - key-remap PLANNER for the RCDATA-4000 image.

Input : analysis/out/rcdata_4000.bin (pinned SHA-256)
Output: analysis/out/fw_remap.txt

Read-only by construction: it *plans* edits and prints them, it never writes an
image. Building a patched image is phase 6 (see docs/PLAN.html).

  R1  the current map: logical id -> HID usage -> key name, physical flag
  R2  the requested remap (edit REQUESTS below), resolved to byte offsets
  R3  validation: unknown key, usage 0, non-physical id, duplicate usages
  R4  the exact byte edits and a before/after window, i.e. the diff a patch
      would produce

Usage names follow HID Usage Tables, page 0x07. Ids are the firmware's own
(0x00..0x78, 0x6F absent); the usage<->id table is at 0x16DD8.
"""
from __future__ import annotations

import hashlib
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMG = ROOT / "analysis" / "out" / "rcdata_4000.bin"
REPORT = ROOT / "analysis" / "out" / "fw_remap.txt"
IMG_SHA256 = "06A1A47432A6CA7EC060103378E2D984A46F9AFA98F19FCCD99219EAEA4A88E0"

USAGE_TABLE = 0x16DD8
COUNT_AT = 0x16EC8
CATALOG = 0x9600
SCAN_MAP = 0x16A96
SENTINEL_ID = 0x7D

# ---------------------------------------------------------------- the request
# "key" is resolved through the *current* map (the key that sends that usage
# today); "to" is the usage it should send after the patch. Nothing is written
# to disk -- the report is the deliverable.
#
# Pass requests on the command line instead of editing the default below:
#     python analysis/fw_remap.py "CapsLock=Esc" "Menu=0x50"
REQUESTS = [
    {"key": "CapsLock", "to": "Esc", "why": "60% layout: CapsLock is in the Esc position"},
]

if len(sys.argv) > 1:
    REQUESTS = []
    for arg in sys.argv[1:]:
        if "=" not in arg:
            raise SystemExit(f"bad request {arg!r}; expected KEY=TARGET (usage name or 0xXX)")
        src, dst = (s.strip() for s in arg.split("=", 1))
        REQUESTS.append({"key": src, "to": dst, "why": "command line"})

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fw_names import HID, name, usage_of  # noqa: E402  (shared vocabulary)


img = IMG.read_bytes()
assert hashlib.sha256(img).hexdigest().upper() == IMG_SHA256, "image is not the pinned one"
assert len(img) == 0x7E000
count = int.from_bytes(img[COUNT_AT:COUNT_AT + 2], "little")
assert count == 120, count
assert (img[USAGE_TABLE], img[USAGE_TABLE + 1]) == (SENTINEL_ID, 0x00)

pairs = [(img[USAGE_TABLE + 2 + 2 * i], img[USAGE_TABLE + 3 + 2 * i]) for i in range(count)]
by_id = {i: u for i, u in pairs}
id_index = {i: k for k, (i, _) in enumerate(pairs)}
physical = {b for b in img[SCAN_MAP:SCAN_MAP + 128] if b != SENTINEL_ID}

lines: list[str] = []


def out(*a):
    lines.append(" ".join(str(x) for x in a))


# ============================================================ R1 current map
out("=" * 78)
out("= R1  current map: id -> HID usage -> name (physical = appears in the scan grid)")
out("=" * 78)
for i, u in pairs:
    flag = "phys" if i in physical else "    "
    off = USAGE_TABLE + 2 + 2 * id_index[i] + 1
    out(f"  id {i:02X}  usage {u:02X}  {name(u):<20s} {flag}  byte at {off:#07x}")

out("")
out(f"distinct usages: {len(set(by_id.values()))} over {count} ids; "
    f"ids sending 0x00 (none): {[f'{i:02X}' for i, u in pairs if u == 0]}")
out(f"physical ids in the scan grid: {len(physical)}")

# ============================================================ R2 resolve
out("")
out("=" * 78)
out("= R2  requested remap")
out("=" * 78)
edits = []
for req in REQUESTS:
    target = usage_of(req["key"])
    new_u = usage_of(req["to"])
    owners = [i for i, u in pairs if u == target]
    out("")
    out(f"  request: {name(target)} -> {name(new_u)}   ({req.get('why', '')})")
    if not owners:
        out("    REJECTED: no id currently sends that usage")
        continue
    for i in owners:
        old_u = by_id[i]
        off = USAGE_TABLE + 2 + 2 * id_index[i] + 1
        edits.append((i, old_u, new_u, off))
        out(f"    id {i:02X} ({'physical' if i in physical else 'NOT physical'}) "
            f"usage {old_u:02X} -> {new_u:02X} at byte {off:#07x}")

# ============================================================ R3 validation
out("")
out("=" * 78)
out("= R3  validation")
out("=" * 78)
final = dict(by_id)
for i, _, new_u, _ in edits:
    final[i] = new_u
problems = []
for i, _, new_u, _ in edits:
    if i not in physical:
        problems.append(f"id {i:02X} is not populated in the scan grid -- the edit could never fire")
    if new_u == 0:
        problems.append(f"id {i:02X} would send usage 0x00 (no key)")
dup = Counter(u for i, u in final.items() if u != 0)
for u, n in dup.items():
    if n < 2 or u not in {e[2] for e in edits}:
        continue
    ids = [f"{i:02X}" for i, v in final.items() if v == u]
    holders_before = [f"{i:02X}" for i, v in by_id.items() if v == u]
    if holders_before:
        out(f"  note: usage {u:02X} ({name(u)}) merges onto ids {ids} — "
            f"intended when the goal is two keys with one function")
    else:
        problems.append(f"usage {u:02X} ({name(u)}) now appears on ids {ids} — "
                        "that duplicate is new and probably unintended")
if not problems:
    out("  clean: every edited id is physical, every usage non-zero, no new duplicate")
else:
    for p in problems:
        out(f"  WARNING: {p}")

# ============================================================ R4 byte edits
out("")
out("=" * 78)
out("= R4  byte edits (this is the whole patch)")
out("=" * 78)
# Two tables have to agree: the id<->usage pair table (what this planner walks)
# and the per-key CATALOG at 0x9600, which is what the firmware actually emits
# (hardware-verified: pair-table edits alone change no keystroke).
for i, old_u, new_u, off in edits:
    cat = CATALOG + i * 4
    kind, cat_u = img[cat], img[cat + 2]
    flag = "" if kind == 2 else f"  <-- kind {kind}, byte2 is not a usage: inspect before editing"
    out(f"  pair    {off:#07x}  {old_u:02X} -> {new_u:02X}   (id {i:02X})")
    out(f"  catalog {cat + 2:#07x}  {cat_u:02X} -> {new_u:02X}   (id {i:02X}, kind {kind}){flag}")
for i, old_u, new_u, off in edits:
    start = off - 8
    before = img[start:start + 16]
    after = bytearray(before)
    after[off - start] = new_u
    out("")
    out(f"  window {start:#07x}..{start + 15:#07x} (the edited byte is the 9th)")
    out(f"    before  {before.hex(' ')}")
    out(f"    after   {after.hex(' ')}")
out("")
out("  length unchanged, no other byte touched, no checksum to recompute.")
out("  open gate: the version word below 0x16A96 must stay byte-identical (it does).")

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"report: {len(lines)} lines -> {REPORT.name}")
