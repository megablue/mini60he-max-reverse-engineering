# Session handoff — Mini60HE Max Firmware Reverse Engineering

Next: `docs/features/index.html` — the feature map. Read only the page for
your area before the code.

**A snapshot, not a source of truth.** This file goes stale by design. If it
disagrees with the code, the code is right. `AGENTS.md` is the process doc,
`docs/features/` is the feature map and `docs/SPEC.md` is the behaviour spec.
This file is the volatile one — it exists so a new session knows *where things
stand*, not *how they work*.

As of no git repo — 2026-10-22.

## State

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

Risk & wireless check recorded (2026-10-24). Nothing in this project has ever
touched the device, so current risk is zero. For phase 6 the exposure is the
write step only: version, checksum and per-variant size guards exist, but the
updater has **no flash-read command**
([ISP protocol](docs/features/isp-protocol.html), "No flash-read command"), so a
device dump is impossible and an interrupted write is the main brick scenario;
the bootloader sits outside the 0x7E000 app span, but recovery is unverified.
The first flash should be the unmodified factory image on a second unit, after
a recovery path is demonstrated. [Firmware image](docs/features/fw-image.html)
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
page is the entry point. Three remap hooks (usage table `0x16DD8`, four Fn
overlays, scan grid `0x16A96`), actuation defaults `0x8400`/`0x8500`
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
Volume Up, i.e. `0x16C7E: 4C 49 -> 4F B9`. That alone still depended on the app
remap keeping Right Arrow on the key, and a flash erases the NVM pages
`0xB000`/`0xB600` where the app's remaps live — so the bake now moves the two
roles in the usage table as well: `0x16E83: E6 -> AF` (id `0x54`, the old RAlt
position, becomes Fn) and `0x16E85: AF -> 4F` (id `0x55`, the stock Fn position,
becomes Right Arrow). Fn-held is keyed on the usage value `0xAF`, proved on
hardware: the key at the old RAlt position already yields `Fn+1` = F1.
[Plan](docs/PLAN.html#first-patch) carries the test ladder and gates;
`analysis/fw_volpatch.py` builds `out/fw_volplus.bin` — exactly four bytes
differ (`0x16C7E`, `0x16C7F`, `0x16E83`, `0x16E85`), length and the version words
are untouched (sha256 `ac46b5aa…`), and `--chord-only` still builds the two-byte
variant. Cost: Right Alt and the factory Fn position no longer exist as such;
per-key settings stay put because ids keep their scan positions.

Flash go recorded (2026-10-24). The user chose the second-unit path, so the run
is planned but nothing has been written to a device. Two artifacts are staged
side by side: `analysis/out/fw_stock.bin` (factory `RCDATA 4000`, sha256
`06a1a474…`) to prove the write path first, and `analysis/out/fw_volplus.bin`
(the bake, `ac46b5aa…`) to try second. New fact from the tool's file dialog:
the filter is `*.hex,*.bin` and the handler at `0x423B90` matches `L".hex"` then
`L".bin"` and stores 1/2 at dialog `+0x428`; the `.bin` branch memsets the 1 MiB
firmware buffer (fill `0xFF` for this chip family) and reads the file into
`[dialog+0x1E44]` — the same pointer the bundled-RCDATA loader uses and the
upload flow reads — so a raw `.bin` reaches the writer and no Intel-HEX wrapper
is needed. Steps, abort conditions and the two remaining inferences (write span
derived from the image rather than traced to the loop counter; recovery from an
interrupted write still unproven) live in
[the runbook](docs/PLAN.html#flash-runbook).

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

## Open threads

- The old misspelled sibling folder was removed on 2026-10-22; only this
  workspace's copy of the binary remains (hash still matches the pin).
- `git init` deliberately deferred (user chose this, 2026-10-22): commit
  rules in `AGENTS.md` stay dormant until then; when a repo is initialized,
  this scaffold is the first commit.
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

- Behavior in `docs/SPEC.md` is sourced from static analysis except where a row
  says it was keyboard-verified (the Fn/volume enum, the OS-mode chords and the
  wireless dead window are hardware facts now); the companion app's own
  key-mapping/lighting UI is still not decoded.
- The product name no longer rests on the file name alone (the firmware carries
  the string), but the tool's own branding still splits between SONiX (About
  box, copyright) and `EVision 幻彩` (UI string).

## Local-only state (not on the remote)

No repo exists, so every file is local-only — nothing has been pushed
anywhere, and there is no clone or tooling.
