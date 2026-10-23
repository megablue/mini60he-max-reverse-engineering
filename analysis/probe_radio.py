#!/usr/bin/env python3
"""probe_radio.py - negative evidence for a radio or companion chip in RCDATA 4000.

Input : analysis/out/rcdata_4000.bin (516,096 B, SHA-256 pinned below)
        analysis/out/fw_code.txt      (peripheral histogram printed by fw_code.py)
Output: analysis/out/probe_radio.txt

Read-only. No device, no exe run. Everything here is a byte scan of the
firmware image plus a summary of the peripheral words fw_code.py already
reached; the script asserts that both negative claims still hold.

Claims pinned:
  - zero ASCII and zero UTF-16LE hits for the wireless vocabulary below
  - no UART / USART / SPI / I2C controller base in the reached peripheral set
  - the only peripheral blocks are USB device, LED driver, Hall AFE, four GPIO
    banks, one clock/config word and the flash/EEPROM controller
  - control strings that prove the scan reads real content are present
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMG = ROOT / "analysis" / "out" / "rcdata_4000.bin"
CODE = ROOT / "analysis" / "out" / "fw_code.txt"
REPORT = ROOT / "analysis" / "out" / "probe_radio.txt"

IMG_SHA256 = "06A1A47432A6CA7EC060103378E2D984A46F9AFA98F19FCCD99219EAEA4A88E0"
img = IMG.read_bytes()
assert len(img) == 0x7E000, f"image size {len(img):#x}"
assert hashlib.sha256(img).hexdigest().upper() == IMG_SHA256, "rcdata_4000.bin is not the pinned image"

lines: list[str] = []


def out(*a):
    s = " ".join(str(x) for x in a)
    lines.append(s)
    print(s)


TOKENS = [
    "Bluetooth",
    "BLE",
    "2.4G",
    "2.4GHz",
    "2G4",
    "Wireless",
    "PAIR",
    "PAIRING",
    "DONGLE",
    "nRF",
    "ESP32",
    "RADIO",
    "UART",
    "USART",
    "SPI",
    "I2C",
    "IIC",
]

# peripheral words reached by fw_code.py; every block the image touches
ALLOWED_PREFIXES = (
    "0x4001B",  # LED driver
    "0x4001F",  # USB device controller (0x4001F0xx / 0x4001F8xx)
    "0x40021",  # clock/config (one write, 0x4002103C)
    "0x40027",  # hall sensor AFE
    "0x40037",  # GPIO bank
    "0x40038",  # GPIO bank
    "0x40039",  # GPIO bank
    "0x4003A",  # GPIO bank
    "0x40057",  # flash / EEPROM controller
)

out("probe_radio - radio / companion-chip negative evidence")
out("image:", IMG.relative_to(ROOT), f"{len(img)} bytes", "sha256", IMG_SHA256)
out()

out("== control strings (the scan reads real content) ==")
for needle in ("MINI60HE MAX", "HID Interface"):
    n_ascii = img.count(needle.encode("ascii"))
    n_utf16 = img.count(needle.encode("utf-16-le"))
    out(f"  {needle!r:18} ascii={n_ascii} utf16={n_utf16}")
assert img.count(b"MINI60HE MAX") == 2
assert img.count(b"HID Interface") >= 1
out()

out("== wireless / serial vocabulary (case-insensitive, ASCII + UTF-16LE) ==")
total = 0
for tok in TOKENS:
    a = img.lower().count(tok.lower().encode("ascii"))
    u = img.lower().count(tok.lower().encode("utf-16-le"))
    total += a + u
    out(f"  {tok:10} ascii={a} utf16={u}")
assert total == 0, "wireless/serial vocabulary appeared - the negative claim needs re-checking"
out("  result: 0 hits for every token, in both encodings")
out()

out("== peripheral words reached by fw_code.py ==")
hist = CODE.read_text(encoding="utf-8", errors="replace")
periph = sorted(set(re.findall(r"^\s+(0x4[0-9A-F]{7})\s+x\d+", hist, re.M)))
assert periph, "no peripheral histogram in fw_code.txt"
bad = [p for p in periph if not p.startswith(ALLOWED_PREFIXES)]
groups: dict[str, list[str]] = {}
for p in periph:
    groups.setdefault(p[:7], []).append(p)
for prefix in sorted(groups):
    out(f"  {prefix}xx  {len(groups[prefix])} distinct word(s): {', '.join(groups[prefix])}")
assert not bad, f"unexpected peripheral block(s): {bad}"
out("  result: no UART/USART/SPI/I2C controller base anywhere in the reached set")
out()

out("== verdict ==")
out("  The image is wired-USB only: no radio vocabulary, no serial bus controller,")
out("  one HID interface. A 2.4G/BT feature would be a separate RF SoC with its own")
out("  firmware and updater; this MCU image has no path to drive one. Negative")
out("  evidence about the image, not a statement about the PCB.")

REPORT.parent.mkdir(parents=True, exist_ok=True)
REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"\nwrote {REPORT.relative_to(ROOT)}")
