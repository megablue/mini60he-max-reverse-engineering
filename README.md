# Mini60HE Max Firmware Reverse Engineering

Static reverse engineering of the **Mini60HE Max** vendor updater (`SONiX` ISP tool, rebranded)
and of the firmware image embedded inside it, so that keyboard behaviour - key layout, Fn layer,
lighting - can be changed at the firmware level instead of through the vendor app.

Everything here is **file analysis**. No script in this repository opens a HID device, and the
updater executable is **never executed** by the tooling. Flashing is a manual step that belongs to
the keyboard's owner (see [Fences](#fences)).

---

## Status

| | |
|---|---|
| Updater analysed | `bin/MINI 60 HE MAX_V1.52.exe`, PE `2.1.2.13`, EV-signed, built 2026-01-21 |
| Firmware extracted | RCDATA `0xFA0` at file `0x1BAA4C`, `0x7E000` bytes, SHA-256 `06a1a474…a88e0` |
| Device | SONiX **SN34F280**, USB HID `0C45:80A1`, wired only |
| First flash | 4-byte bake written to the keyboard, booted fine, Fn layer edit confirmed live |
| Current bake | `analysis/out/MINI60HE_max_bake3.exe` - **built, not yet flashed** |
| Side finding | an ISP write blanks the NVM settings pages, so app-side remaps and macros must be re-entered after every flash |

What works today: remapping any physical key to any usage, adding Fn-layer chords, changing
per-key actuation tuning, retuning LED tables. What does not: reading flash back from the device
(the protocol has no dump command), and anything wireless - the radio is not in this image.

---

## The two artifacts

### `bin/MINI 60 HE MAX_V1.52.exe` (the target)

```
size       2,386,384 bytes
SHA-256    958A39951D2F908A7FE925E0FA598C321924CB235239BF37484AE7C8213512D6
PE         FileVersion / ProductVersion 2.1.2.13  (About box says 2.1.2.7)
signer     Chinese FINDER (Dongguan) Technology Co., Ltd., Sectigo EV, RFC3161 2026-01-21T09:46Z
imports    19 DLLs / 599 functions; device-facing surface is HID feature reports + setupapi enum
resources  RT_RCDATA x10, RT_STRING x14, 7 dialogs, bitmaps/icons/cursors
overlay    Authenticode PKCS#7, 0x243800..EOF
```

MFC/C++ x86, VS2008 toolset, not packed, no .NET. The UI is a one-click production flasher: there
is no file picker, the firmware is a resource, `Start` writes it to the first matching `0C45:80A1`.

### RCDATA `0xFA0` (the firmware)

```
file offset 0x1BAA4C        length 0x7E000 (516,096 bytes)      end dword 0xAAAA5555
SHA-256     06A1A47432A6CA7EC060103378E2D984A46F9AFA98F19FCCD99219EAEA4A88E0
core        Cortex-M3 Thumb, vector table = SP 0x200076F8 / reset 0x204, main code 0x0..0x980F
strings     'MINI60HE MAX', 'HID Interface', descriptor templates at 0x18044
silence     no radio/BLE/2.4G strings, no UART/SPI/I2C controller in the peripheral set
```

The image carries no checksum field and no stored version: the tool computes checksums itself and
compares a chip-version word at flash time (see [Gates](#gates)).

---

## Repository layout

```
bin/                    the pinned vendor updater (never modified in place)
analysis/               one script per question, all regenerable, all offline
analysis/out/           generated evidence (git-ignored): transcripts, resources, built binaries
docs/features/          the feature map - one HTML page per area
docs/SPEC.html          user-visible behaviour of the device and the updater
docs/PLAN.html          phases, fences, and the first-patch write-up
HANDOFF.md              session state: what was just done, what is next
AGENTS.html             process rules for agents working in this tree (AGENTS.md is a pointer)
LICENSE, NOTICE         MIT for this work; the vendor binary in bin/ is not covered
```

`analysis/out/` is deliberately untracked: it is where the extracted firmware, the
transcripts and the built installers land, and every one of them is reproducible from
`bin/` in seconds. Nothing in `docs/` depends on it.

### Analysis scripts

| Script | Answers |
|---|---|
| `probe_pe.py` | PE census: sections, imports, resources, strings, overlay |
| `probe_cert.py` | parses the Authenticode PKCS#7 as data (signer chain, timestamp, policies) |
| `decode_fw.py` | first decode of RCDATA 4000: sections, entropy, strings, vector table |
| `probe_radio.py` | negative evidence: no radio/companion-chip vocabulary, no serial peripheral |
| `fw_code.py` | recursive-descent Thumb function map + literal/peripheral access tracking |
| `fw_fn.py`, `fw_find.py` | annotated disassembly of a range / regex search over linear disasm |
| `fw_feat.py` | the `0x16E00..0x185E8` band: key universe, layout groups, LED ramps/palettes |
| `fw_sensor.py` | the Hall front end: scan IRQ, analog block, position map, adaptive filter |
| `fw_keys.py` | key pipeline: scan grid, usage table, Fn overlays, actuation, mode byte |
| `fw_patch.py` | patch-target inventory: tables, code constants, gates |
| `fw_remap.py` | remap **planner**: resolves `key -> key`, validates, prints both byte edits (pair table + catalog) |
| `fw_bake3.py` | builds the current bake: applies the edit list, asserts anchors, wraps the exe |
| `mkflasher.py` | generic wrapper: any `0x7E000` image -> patched updater + manifest |
| `isp_*.py` | ISP protocol: frame format, `AA 55` command table, password payload, upload flow, gates |

`analysis/out/` holds the transcripts these print (`fw_keys.txt`, `fw_sensor.txt`, `fw_bake3.txt`, …)
plus the extracted resources (`rcdata_4000.bin`, small RCDATA ids), the ISP transcripts
(`isp_walk.txt`, `isp_gate.txt`, `pw7_out.txt`) and the built binaries.

Requirements: Python 3.10+, `pefile`, `capstone` (tested on 3.14 / pefile 2024.8.26 / capstone 5.0.7).
Every script is standalone: `python analysis/fw_keys.py`.

### First run after cloning

```powershell
pip install pefile capstone
python analysis/probe_pe.py     # checks the pinned exe, extracts RCDATA 4000 -> analysis/out/
```

That one step creates `analysis/out/rcdata_4000.bin`, which every other script reads and
SHA-256-checks before it does anything. If the vendor exe does not match the pin, `probe_pe.py`
exits without writing and says so - the analysis is only valid for that exact build.

---

## Documentation map

The feature map is the entry point: **`docs/features/index.html`**.

| Page | Read when |
|---|---|
| `binary-evidence.html` | the stock binary, SHA-256 pin, PE version, verifying a claim |
| `fw-image.html` | the embedded image: vector table, regions, strings, checksum hunt, wireless absence |
| `isp-protocol.html` | frame format, command table, upload flow, password/erase gates |
| `fw-tables.html` | the layout/LED band: key universe, grouping tables, ramps, palettes |
| `key-pipeline.html` | scan IRQ -> position map -> usage -> Fn overlay -> mode byte, actuation |
| `mod-surface.html` | choosing a mod, computing an offset, the three remap hooks, the action enum |

`docs/SPEC.html` states behaviour (typing, actuation, lighting, settings, updating);
`docs/PLAN.html` holds the phases, the fences and the first-patch recipe.
Those pages are HTML; a `.md` file next to one is a pointer stub, not the document.
This README is the exception - it stays Markdown so a repository host can render it.

---

## How a key becomes a keystroke

```
Hall channels -> scan IRQ 0x0FC8 -> raw matrix 16ch x 8 lines
      -> position map 0x16A96[128]      (channel + 8*drive_line -> key id, 0x7D = empty)
      -> per-key output record 0x9600 + id*4   {kind, ?, usage, 0}
             kind 2 = HID usage, kind 3 = vendor action (consumer/system page)
      -> if Fn is held (usage 0xAF): overlay row 0x16C3E + mode*0x68, input usage -> action code
      -> action code >= 0xB0 -> consumer usage via u16 table 0x16BF6 (0xB9 = Volume Up)
      -> HID report
```

Coordinate table (offsets are image offsets):

| What | Where | Notes |
|---|---|---|
| scan position -> key id | `0x16A96`, 128 B | 61 populated positions, `0x7D` empty |
| key id -> usage | `0x16DDA`, 120 rows, count `u16 @0x16EC8` | feeds the reverse lookup only |
| per-key output record | `0x9600`, 112 x 4 B | **the real output path**; usage at `+2` |
| Fn overlays | `0x16C3E`, `0x16CA6`, `0x16D0C`, `0x16D72` | 51 rows x 2 B: input usage -> action |
| action enum -> consumer usage | `0x16BF6`, u16 | `0xB0+k`; `0xB9` = Volume Up, `0xBA` = Volume Down |
| WASD virtual codes | `0x16BE6` | `0xF8..0xFF` -> W/A/S/D and the arrow keys |
| Fn detection | `cmp r0,#0xAF @0x147B6` | Fn is state only, it emits nothing |
| per-OS mode byte | RAM `0x200000AE` | Fn+D = Windows, Fn+S = Mac, Fn+A = Android; layer 2 unused |
| actuation | SM at `0x32AC` | hysteresis `0x3764`, commit delta `0x54DE`, hold timer `0x54A6` |
| NVM settings | `0xB000 + id*4`, `0xB600 + id*8` | blank in the factory image, **erased by any flash** |
| LED | palette `0x17668`, hue ramp `0x17837`, presets `0x17A83` | |

Consequences worth knowing before patching:

* editing `0x16DDA` alone changes nothing visible - it is a lookup table, not the emitter;
* the catalog at `0x9600` is the emitter, and the NVM page overrides it per key when non-zero;
* per-key actuation and lighting are **id-indexed**, so moving a key's id moves its tuning;
* ids `0x58/0x59/0x5A/0x5B` (Left/Down/Up/Right) exist in both tables but own no scan position -
  they are only reachable through a remap.

---

## Gates

Any image you write has to survive four checks:

1. **Chip-version gate** - the tool reads one dword of the image (`fwbuf[idx*2]`, index from the
   chip record) and compares it with the device's version bytes; mismatch shows
   *"Firmware Version is not for this chip!!"* and returns **before** erase/program. It is a
   pre-write check, so a rejection costs nothing. The exact index is not pinned (see open items).
2. **RCDATA size gate** - records with `field0 == 0` cap the blob at `0x8400`; the shipped image is
   `0x7E000`, which passes only because the chip record actually used has `field0 != 0`.
   Patching in place never changes the length, so this verdict is unchanged.
3. **Checksum** - computed tool-side from the loaded bytes (`Bin File Check Sum : %.4X`,
   big-endian 16-bit word sum), nothing is stored in the image. No image edit can desync it.
4. **Authenticode** - covers the exe only; the upload path verifies nothing. A patched copy is
   simply unsigned, and the tool runs anyway.

**There is no flash-read command.** The `AA 55` set covers version, password, encryption, erase,
program, checksum, code option and page writes; the only reads are echo/status gates and per-page
verify. A stock device backup is therefore impossible with this tool - the stock firmware exists
only as the copy inside the vendor exe.

---

## Building a modification

```powershell
# 1. plan a remap (read-only; prints the exact bytes for BOTH tables it must touch)
python analysis/fw_remap.py "CapsLock=Esc" "Menu=Left"

# 2. bake edits into the image and wrap them into a flasher copy
python analysis/fw_bake3.py                 # current edit list -> analysis/out/fw_bake3.bin + ..._bake3.exe

# 3. or wrap any image you already have
python analysis/mkflasher.py analysis/out/fw_bake3.bin --out analysis/out/my_mod.exe
```

`mkflasher.py` locates RCDATA `0xFA0` by walking the resource tree (currently file `0x1BAA4C`),
requires the replacement to be exactly `0x7E000` bytes, re-parses the result, verifies that every
changed byte falls inside the slot, and writes a manifest with both SHA-256 values.
Re-wrapping `fw_bake3.bin` reproduces `774bb728…` byte for byte.

### Current bake

| offset | edit | effect |
|---|---|---|
| `0x9752` | `E6 -> AF` | catalog id `0x54` (old right Alt) = Fn |
| `0x9756` | `AF -> 4F` | catalog id `0x55` (old Fn) = Right Arrow |
| `0x972E` | `E5 -> 52` | catalog id `0x4B` (right Shift) = Up Arrow |
| `0x975A` | `65 -> 50` | catalog id `0x56` (Menu) = Left Arrow |
| `0x975E` | `E4 -> 51` | catalog id `0x57` (right Ctrl) = Down Arrow |
| `0x16E71/83/85/87/89` | same usages | id<->usage pair table kept in step |
| `0x16C7E/7F` | `4C 49 -> 4F B9` | Fn row 32: Right Arrow -> Volume Up |

`analysis/out/MINI60HE_max_bake3.exe` - 2,386,384 B, SHA-256 `774BB728…5FE9A9`, 12 bytes changed.

### Flashing (owner action)

Close the config app, connect the keyboard by wire, run the patched updater, press `Start`, and do
not touch the device until it reports done. Revert = run the **original** `bin/…V1.52.exe`, whose
embedded image is stock.

---

## Fences

* The vendor exe is **never executed** by any script in this repository; all evidence is static.
* `bin/MINI 60 HE MAX_V1.52.exe` is treated as immutable - patches are built into copies.
* No script opens, enumerates or writes to a HID device.
* Writing to the keyboard is a deliberate manual step. Its only irreversible failure mode is an
  **interrupted write**; recovery from a half-written image is unverified (the bootloader lives
  outside the `0x7E000` app span, but that has not been tested).
* An ISP write erases the NVM settings pages, so macros and app-side remaps are lost and must be
  re-entered. Anything that should survive belongs in a baked image.

---

## Open items

* The chip-version gate's dword index is not pinned. Everything patched so far sits in table data
  and has passed on hardware, and a mismatch refuses the flash rather than bricking.
* The wireless path is outside this image: the dead-window symptom on wireless wake (keys
  unresponsive for a few seconds) is RF link establishment, not MCU boot - wired replug is instant.
  The firmware can still *command* the module (Fn+W sends Bluetooth host 2), so a host<->module
  channel exists even though no radio strings or serial peripheral are in the image.
* `0x174B9` cell records (16-byte stride, per-key LED geometry) are only partly decoded.
* The per-key LED gradient tables and the `0x17CC0` driver-init block are documented but untested
  against hardware.
* `analysis/out/` is intentionally untracked: it holds the extracted firmware and the built
  installers, none of which belong in git history. Regenerate with `analysis/probe_pe.py`.

---

## License

Scripts, documentation and the findings written in them are MIT licensed - see `LICENSE`.
`bin/MINI 60 HE MAX_V1.52.exe` is a third-party vendor binary and is **not** covered: it stays in
the tree because the scripts verify its hash and read the firmware out of it. See `NOTICE`.
No flashing automation is distributed, and no script in this repository touches a device.
