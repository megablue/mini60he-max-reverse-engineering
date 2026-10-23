# Session handoff — Mini60HE Max Firmware Reverse Engineering

Next: `docs/features/index.html` — the feature map. Read only the page for
your area before the code.

**A snapshot, not a source of truth.** This file goes stale by design. If it
disagrees with the code, the code is right. `AGENTS.md` is the process doc,
`docs/features/` is the feature map and `docs/SPEC.md` is the behaviour spec.
This file is the volatile one — it exists so a new session knows *where things
stand*, not *how they work*.

As of 2026-10-24.

## State

There is now one command from "I want this key to do that" to a flashable
installer: `analysis/fw_build.py`. `KEY=TARGET` rewrites the catalog byte that a
key emits plus the pair row the Fn lookup reads; `Fn+KEY=ACTION` spends a free
row of the Windows Fn overlay. It asserts that the finished diff is exactly its
own edit set, and it replays the flashed 12-byte bake byte for byte (image
`617eef7f…`, exe `774bb728…`), which is the acceptance test. The usage
vocabulary shared with the planner moved to `analysis/fw_names.py`. Tier A
entry 1 in [the backlog](docs/PLAN.html#backlog) is closed. Docs: the worked
remap in [Modification surface](docs/features/mod-surface.html#remap-plan) now
shows the two-byte edit and the builder.

One write has happened: the four-byte image was flashed on 2026-10-22. The device
is fine, its settings pages were wiped, the Fn-row byte is live and the two
usage-table bytes changed nothing. The corrected catalog bake (`bake3`) is built
and not flashed. Details: "First flash" below and
[Plan](docs/PLAN.html#first-patch).

Phases 1–2 progressed on disk (2026-10-22): `analysis/probe_pe.py` and
`analysis/decode_fw.py` regenerate every artifact in `analysis/out/` from the
pinned exe (static, exe never executed). Confirmed on the
[Binary evidence](docs/features/binary-evidence.html) and
[Firmware image](docs/features/fw-image.html) pages: the exe is a rebranded
SONiX tool (`EVision 幻彩 V01`, FINDER-signed) targeting the SN34F280 board
`108A` (VID 0x0C45 / PID 0x80A1), and RCDATA 4000 is a real Cortex-M3 firmware
image — vector table validated, "MINI60HE MAX" product strings found
in-firmware, flash region map done. Left open at the time: the in-image
checksum/version fields (no candidate matched) — resolved in phase 3 as
tool-side computation, not image fields.

Phase 3 static walk substantially landed (2026-10-22):
[ISP protocol](docs/features/isp-protocol.html) now documents the transport
wrappers (HidD_SetOutputReport send / HidD_GetFeature read), the full AA 55
command table (rows `01`..`2A` verified at send sites; the 0x2x family is
bare `cmd AA 55`, not 05-prefixed — correction recorded on the page), the
0x4039C0 upload flow, the 0x40D310 want-floor echo gate, the code-option and
finish-floor. The probe `analysis/isp_open.py` (+ `out/isp_open.txt`,
regenerable) closed three of the four open items:

- wire password shape: short pw frame = 8 bytes `02 AA 55 00 <4B payload>`
  from `0x40B740`; payload is one dword deref'd from the flow-controller pw
  pointer member `*(flowCtl+0x1c)`, not the full resource string; echo gate
  (esp-accounting re-derived) returns 5-on-match / 4-on-mismatch comparing the
  device echo `[4..7]` against runtime global `0x5b1d6c` (initial value
  `0xFAFAFAFA` — the only occurrence in the file: a deliberate poison; all 16
  static refs are reads, so its writer is register-indirect); long 64-byte form
  (`0x40BAC0`, used only by the Codeoption-Erase flow) sends zero payload and no
  pw bytes — pw travels only in the short form; RCDATA 4007 `'12345678'`
  (UTF-16LE) lands in dialog CString `+0xEC` via loader fn `0x427120`; which
  conversion becomes the 4-byte wire payload is the one open item (device-side
  bootloader constants are outside this user image by design).
- SZK671F: one member of the chip-name registry (12 names,
  `0x588F7C..0x589074`); five installer sites write per-variant copies into
  globals `0x5BD020..0x5BD41x` — the tool carries five protocol variants and
  gates by device-name match. FN 0x426250 = RCDATA-4011 Settings-zip extractor
  (`%sSettingFiles.zip` → `%sSettingFiles` folder at runtime).
- EVT/I2C unlock: closed as absent — no I2C/EVT code or real strings exist
  in the exe; the earlier 'C&C=IIC' hits were pointer-table byte false
  positives.
- Version/checksum gates story (phase 3): VERIFIED tool-side. Checksums are
  computed at load time — fn `0x40A7D0` (SN8: 32-bit byte-sum), fn `0x40A800`
  (bin/hex: big-endian-16 word-sum per 2-byte pair, truncated 16b) — displayed
  as `'%.4X'` into `[dlg+0x42C]`; nothing checksum-related is embedded in the
  firmware image. Version gate = dispatcher fn `0x401100`: version dword read
  at `fwbuf + (record+9)*2` compared against the device's 4 version bytes;
  mismatch rejects with 'Firmware Version is not for this chip!!' (SN8 variant
  has its own message). Both later feeds: [ISP protocol](docs/features/isp-protocol.html)
  and [Firmware image](docs/features/fw-image.html).

Phase 4 complete (2026-10-22). The pipeline landed:
[Key pipeline & remap surface](docs/features/key-pipeline.html) +
`analysis/fw_keys.py` — id→usage table 0x16DD8 (120 entries, sentinel 0x7D,
count u16 0x16EC8, reverse lookup 0x327C), four 51-row Fn-overlay tables
(0x16C3E/0x16CA6/0x16D0C/0x16D72, stride 0x66, byte1 = output, layer 0 = the
Windows Fn map), actuation constants 0x960/0x640/0xC, change filter 0x5498
(0x1388 hold, 0xA min delta). Sensor front end closed by `analysis/fw_sensor.py` (`out/fw_sensor.txt`): the
0x0FC8 IRQ copies the 16 channel results at `0x40027000` into the raw matrix
`0x2000221E` (8 channels x 16 drive lines, fixed non-linear channel order);
`0x56E4` maps scan position -> logical id through `0x16A96` (61 of 128
populated), clamps at 0x3E8, filters per key via `0x73A8` (24-byte records at
`0x20001330`), then tail-calls `0x32AC`. The physical grid is known: channels
1-5 are keyboard rows and drive lines 0-13 carry keys. One loose end stays on
the page: the indirect writer of the scan row index 0x20000326. The earlier
layout recon is [Keymap & LED tables](docs/features/fw-tables.html): 61-key
universe (0x01–0x3D bijection-verified by `analysis/fw_feat.py`), three
grouping tables, LED-engine tables; the 0xB000-0xBA00 "settings page" is
erased NVM defaults, not padding (the per-key loader reads 0xB000+id*4 and
0xB600+id*8 and synthesizes defaults when zero). A live-capture session would
still close the pw-payload encoding open item. Phase 6 stays closed and
user-gated.

Phase 5 doc sweep done (2026-10-22). [SPEC](docs/SPEC.md) now carries the
verified behavior — identity, typing/layers, actuation + debounce, lighting —
plus the four companion-app settings the loader seeds, and it no longer renders
the template comment. The signer story became regenerable:
`analysis/probe_cert.py` walks the PKCS#7 overlay into `out/cert_info.txt`
(7 certificates, leaf FINDER, EV policy `2.23.140.1.3`, thumbprint
`B2DD667C…`, RFC 3161 genTime `2026-01-21 09:46:42Z`). That corrected the
previously recorded thumbprint (the old `9CCFE9B7…` matched nothing) and the
"2025-06-04 timestamp" reading (that date was the TSA certificate's notBefore).
[Binary evidence](docs/features/binary-evidence.html) retired two stale traps:
identity no longer rests on the file name alone, and the duplicate sibling
folder no longer exists.

Risk & wireless check recorded (2026-10-24; corrected after the first write). No
analysis script has ever touched the device; the only device contact in this
project is the owner's own flash on 2026-10-22. That write makes the exposure
concrete: it succeeded, but it emptied the settings pages and there is still no
recovery path. For the next write the exposure is the write step only: version,
checksum and per-variant size guards exist, but the updater has **no flash-read
command**
([ISP protocol](docs/features/isp-protocol.html), "No flash-read command"), so a
device dump is impossible and an interrupted write is the main brick scenario;
the bootloader sits outside the 0x7E000 app span, but recovery is unverified.
The rule for the next write is the unmodified factory image on a second unit
first, after a recovery path is demonstrated. [Firmware image](docs/features/fw-image.html)
now also records the negative radio evidence, regenerable via
`analysis/probe_radio.py` (`out/probe_radio.txt`): no wireless vocabulary, no
serial bus controller, one HID interface — a 2.4G/BT feature would be a
separate RF SoC with its own firmware and updater, not this MCU image.

OS-mode layer semantics closed (2026-10-24). The four 51-row tables are not a
base layout plus copies: they are per-OS Fn overlays selected by the mode byte
`0x200000AE`, written 0 by Fn+S, 1 by Fn+D and 3 by Fn+A. Those writers decode
the overlay's own extended codes — rows 44/45/46 map A→0x9C, S→0xAB, D→0xAC —
so layer 0 is Windows, 1 is Mac, 3 is Android, and layer 2 (byte-identical to
the Mac output column) has no selector at all. Layers 1–3 share every output
byte and differ from layer 0 only in the F1–F12 and Fn rows, where Windows
emits media/brightness codes and the others pass the usage through. The chain
is live: `0x1456E` calls the dispatcher `0x2FF0`, `0x1457A` the mode setter
`0x2AE4` (also `0x887A`). `analysis/fw_keys.py` now asserts all of it and
[Key pipeline](docs/features/key-pipeline.html) carries the table.

Phase 5 modification surface inventoried (2026-10-24). `analysis/fw_patch.py`
(`out/fw_patch.txt`) turns every candidate mod into an offset, a unit and its
owning code; the new [Modification surface](docs/features/mod-surface.html)
page is the entry point. Three remap hooks (catalog `0x9600` — corrected from the
usage table `0x16DD8` after the first flash — four Fn overlays, scan grid
`0x16A96`), actuation defaults `0x8400`/`0x8500`
(112 x u16 each, uniform — 0x960 / 0x640), the `0x9600` catalog (102 kind-2 +
10 kind-3 records), LED palette `0x17668` / hue ramp `0x17837` / preset run
`0x17A83`, and four code constants (hysteresis `0xC` @0x3764, commit delta
`0xA` @0x54DE, hold timer `0x1388` @0x54A6, reload @0x54BC). Two earlier notes
were corrected: `0x33D0/0x33D8/0x33E0` are initialization (two seeds + a table
base), not threshold compares; and the RCDATA size gate is a chip-record field
test (`0x4272BD`: records with field 0 == 0 cap at `0x8400`, records 9-11 skip
it — `analysis/isp_gate.py`, `out/isp_gate.txt`) that an in-place patch cannot
change. Patched images keep their length, so length, checksum and signature
present no new obstacle; the open gate is the version word, whose image offset
follows from the chip record (`+0x1F -> +0xD`).

Key-remap planning started (2026-10-24, user picked remap first).
`analysis/fw_remap.py` (`out/fw_remap.txt`) is a planner, not a patcher: state a
request like `{"key": "CapsLock", "to": "Esc"}`, it resolves the id through the
current table, validates (physical id, non-zero usage, duplicates only when the
edit creates one) and prints the byte edits plus a before/after window.
Worked example: CapsLock is id `0x30`, its usage byte sits at `0x16E3B`, and
`0x39 -> 0x29` is the whole patch. Ids `0x0D/0x0E/0x0F/0x60/0x71/0x72/0x78`
send usage `0x00` but none is physical, so they are spare rows, not spare keys.
Unverified: whether the companion app rewrites the keymap at runtime.

Patch target locked (2026-10-24). The Fn output byte is not a HID usage but a
vendor enum: `0x16BF6` is indexed `0xB0 + k` into consumer usages. Five tests on
the keyboard fixed it — `Fn+1` = F1, `Fn+W` = BT host 2, `Fn+F7/F8/F9/F10` =
prev / play-pause / next / mute — so `0xB9` = Volume Up (`0x00E9`) and `0xBA` =
Volume Down. Rows 11/12 already map `F11/F12` to those, which makes `Fn+F12` a
free proof of the chain on stock firmware. The user's chord needs no code: of
the 51 Fn rows only 13 are unreachable (rows 1–12 = `F1..F12`, a 60% has no
F-row; row 32 = Insert→Delete, no Insert key), so row 32 becomes Right Arrow →
Volume Up, i.e. `0x16C7E: 4C 49 -> 4F B9`. That alone still depended on the app remap keeping Right Arrow on the key. Fn-held
is keyed on the usage value `0xAF`, proved on hardware: the key at the old RAlt
position already yields `Fn+1` = F1. The first attempt therefore moved the two
roles in the usage table as well (`0x16E83: E6 -> AF` for id `0x54`,
`0x16E85: AF -> 4F` for id `0x55`) — and that is the part the flash disproved:
neither key moved, because output is read from the catalog, not that table. The
corrected bake (`bake3`) carries the same pair at the catalog offsets
`0x9752`/`0x9756`, keeps the usage table consistent for the reverse lookup, and
adds the Fn row; it is built and not flashed. `analysis/fw_volpatch.py` still
builds the four-byte image, `analysis/fw_bake3.py` the catalog one.
[Plan](docs/PLAN.html#first-patch) carries the measured results, ladder and gates;
the four-byte image differs in exactly four bytes (sha256 `ac46b5aa…`) and
`bake3` in twelve (image `617eef7f…`, wrapped exe `774bb728…`). Cost: Right Alt
and the factory Fn position no longer exist as such, and `bake3` also parks
Up/Left/Down on right Shift/Menu/right Ctrl; per-key settings stay put because
ids keep their scan positions.

First flash (2026-10-22; replaces the earlier "planned, not done" entry). The
owner flashed the four-byte image on the daily driver —
`analysis/out/MINI60HE_max_bake.exe`, the vendor installer with only `RCDATA
4000` replaced, started from the tool's own Start button. It completed, the
keyboard rebooted and typed. Measured: the version gate accepted the image (no
mismatch dialog); the app's macro and CapsLock remap were gone, so the NVM pages
`0xB000`/`0xB600` were emptied; the usage-table bytes changed nothing on the
wire — output is read from the catalog at `0x9600 + id*4` (loader `0x5950`),
and `0x16DD8` only feeds the reverse lookup `0x327C`; the Fn-row byte is live —
after re-entering `id 0x54 -> 0xAF` and `id 0x55 -> 0x4F` in the app, `Fn` + old
Fn key produced Volume Up. Interrupted-write recovery is still untested, and
nothing has been written since.

Next write (catalog bake, still gated). `bake3` is built, not flashed. Its
container facts: the dialog filter is `*.hex,*.bin` and the handler at `0x423B90`
matches `L".hex"` then `L".bin"` and stores 1/2 at dialog `+0x428`; the `.bin`
branch memsets the 1 MiB firmware buffer (fill `0xFF` for this chip family) and
reads the file into `[dialog+0x1E44]` — the same pointer the bundled-RCDATA
loader uses and the upload flow reads — so a raw `.bin` reaches the writer and no
Intel-HEX wrapper is needed. The 2026-10-22 run used the wrapped exe rather than
this path. Steps, abort conditions and the two remaining inferences (write span
derived from the image rather than traced to the loop counter; recovery from an
interrupted write still unproven) live in
[the runbook](docs/PLAN.html#flash-runbook).

Backlog recorded (2026-10-24). Asked what else is cheap, the answer is now
written down rather than living in the chat: [Candidate
modifications](docs/PLAN.html#backlog) ranks everything by cost. Tier A needs no
flash — a one-command builder (`fw_build.py`: remap list in, image plus exe out),
a preflight guard that attributes every diff byte to its owning table, and a
generated stock cheat sheet of the built-in Fn combinations. Tier B is one flash
of table data, led by baking the app's settings into the NVM pages `0xB000`/
`0xB600` of the image so a reflash stops wiping them (loader `0x5924`–`0x599C`
confirmed; the one unknown is the `0xB600` validity byte that defaults to `5`),
then a Fn media layer spending the 13 dead rows, the global actuation defaults
`0x8400`/`0x8500` (uniform `0x0996`/`0x0664`), and a lighting recolour. Tier C
is the three key-feel constants. Wireless wake, macros and readback are recorded
as unreachable. Nothing in the backlog is committed work.

Strategy recorded (2026-10-22). Asked whether the firmware could be rebuilt from
source, the answer is no, and it is now written down instead of living in session
memory: 36.1% of main code reached with 177 orphan runs, no SoC register
documentation, no readback or debug path, an unknown device-side bootloader, an
unexamined runtime config protocol, and a wireless module whose firmware is not in
this image. A byte-exact rebuild is unattainable in principle; a behavioural
rewrite would be a different, wired keyboard. The work is therefore patch-only, in
three levels — table or constant, in-place code, and hooks into the roughly
400 KiB of blank flash above `0x18600` — with table edits first and one
falsifiable hypothesis per write.
[Rebuild or patch](docs/features/rebuild-vs-patch.html) holds the measurements and
the constraints; [Plan](docs/PLAN.html#rebuild-or-patch) records the decision.

The second-Fn question was answered on 2026-10-24 without touching hardware, and
it is the first design that needs new code. A second Fn-like modifier is
realistic, but not by table edit: the Fn map is selected by the persistent OS-mode
byte `0x200000AE`, not by which modifier is held. What makes it cheap is what is
already in the image — the dispatcher `0x2FF0` loads all four 51-row layer bases
up front and has a branch for mode 2 (`0x303E` → `0x16D0C`), while `0x2AE4` writes
only 0/1/3, so layer 2 is a wired-but-unreachable second map. The sketched design
is a sentinel usage on the Fn2 key plus a momentary mode override (save the byte,
write 2 while held, restore on release): ~60–120 bytes of Thumb, one RAM byte, no
relocation, with a benign failure mode if a release is missed. The one unresolved
gate is how a physical Fn press sets `0x20000090` — the only immediate-offset
writer found is the macro player's group-`0x30` step, which points at a generic
computed-base store; reading the `[base+4]==0xAF` branch at `0x147C4` and the
clear at `0x233C` should settle it in half a day to a day. Costs and the
level-2-first ladder are in [A second Fn key (Fn2)](docs/features/fn2.html).

## Open threads

- The old misspelled sibling folder was removed on 2026-10-22; only this
  workspace's copy of the binary remains (hash still matches the pin).
- The repository was initialized on 2026-10-22 (branch `main`, local only,
  nothing pushed); `analysis/out/` is ignored and the vendor exe is committed.
- PE strings are empty (ProductName/Company blank) while FileVersion reports
  2.1.2.13 — a likely first RE lead for what kind of build produced this app.
- Whether the physical board carries a 2.4G/Bluetooth SoC cannot be decided
  from this image: [Firmware image](docs/features/fw-image.html) proves only
  that this MCU has no radio vocabulary, no serial bus to a second chip and one
  HID interface. Board markings, the module shield or the vendor spec settle it.
  Nuance (2026-10-24): the Fn enum does carry BT host switching (`0xA0–0xA3`;
  `Fn+W` = host 2, verified on the keyboard), so a host↔radio command channel
  exists somewhere — the negative evidence covers strings and peripherals only.

## Known gaps (volatile; the durable traps live in the feature pages)

- Behavior in `docs/SPEC.md` is sourced from static analysis except for
  [Observed on hardware](docs/SPEC.html#hardware) (the 2026-10-22 write, the NVM
  wipe, the Fn/volume enum, and the Fn table not being the output path); the
  wireless dead window and the OS-mode chords are hardware facts too. The
  companion app's own key-mapping/lighting UI is still not decoded.
- The product name no longer rests on the file name alone (the firmware carries
  the string), but the tool's own branding still splits between SONiX (About
  box, copyright) and `EVision 幻彩` (UI string).

## Local-only state (not on the remote)

The repository is local-only: there is no remote, so nothing has been pushed
anywhere, and there is no clone or tooling.
