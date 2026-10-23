"""fw_names.py - one shared HID usage vocabulary for the analysis scripts.

The firmware's id<->usage table is at 0x16DD8 and carries raw HID usage IDs from
page 0x07 (plus the vendor value 0xAF, which the dispatcher treats as the Fn
modifier). Everything that has to print or parse a key name imports this module,
so `fw_remap.py` (planner) and `fw_build.py` (builder) can never disagree about
what "Menu" or "Fn" means.

Names come from the HID Usage Tables; aliases cover the spellings people
actually type (RightArrow, Escape, Caps, Bksp, PgUp, Fn, ...).
"""
from __future__ import annotations

HID: dict[int, str] = {0x00: "(none)"}
for i, name_ in enumerate("abcdefghijklmnopqrstuvwxyz"):
    HID[0x04 + i] = name_
for i in range(10):
    HID[0x1E + i] = str((i + 1) % 10)
HID.update({
    0x28: "Enter", 0x29: "Esc", 0x2A: "Backspace", 0x2B: "Tab", 0x2C: "Space",
    0x2D: "-", 0x2E: "=", 0x2F: "[", 0x30: "]", 0x31: "\\", 0x32: "NonUS#",
    0x33: ";", 0x34: "'", 0x35: "`", 0x36: ",", 0x37: ".", 0x38: "/",
    0x39: "CapsLock", 0x46: "PrintScreen", 0x47: "ScrollLock", 0x48: "Pause",
    0x49: "Insert", 0x4A: "Home", 0x4B: "PageUp", 0x4C: "Delete", 0x4D: "End",
    0x4E: "PageDown", 0x4F: "Right", 0x50: "Left", 0x51: "Down", 0x52: "Up",
    0x53: "NumLock", 0x54: "KP/", 0x55: "KP*", 0x56: "KP-", 0x57: "KP+",
    0x58: "KPEnter", 0x62: "KP0", 0x63: "KP.", 0x64: "NonUS\\", 0x65: "Menu",
    0x66: "Power", 0x67: "KP=", 0x74: "Execute", 0x75: "Help", 0x76: "Menu",
    0x77: "Select", 0x78: "Stop", 0x79: "Again", 0x7A: "Undo", 0x7B: "Cut",
    0x7C: "Copy", 0x7D: "Paste", 0x7E: "Find", 0x7F: "Mute", 0x80: "VolUp",
    0x81: "VolDown", 0x82: "LockCaps", 0x83: "LockNum", 0x84: "LockScroll",
    0x85: "KPComma", 0x86: "KP=AS400", 0x87: "Intl1", 0x88: "Intl2",
    0x89: "Intl3", 0x8A: "Intl4", 0x8B: "Intl5", 0x8C: "Intl6", 0x8D: "Intl7",
    0x8E: "Intl8", 0x8F: "Intl9", 0x90: "Lang1", 0x91: "Lang2",
    0xAF: "vendor 0xAF (media?)",
    0xE0: "LCtrl", 0xE1: "LShift", 0xE2: "LAlt", 0xE3: "LGui",
    0xE4: "RCtrl", 0xE5: "RShift", 0xE6: "RAlt", 0xE7: "RGui",
})
for i in range(12):
    HID[0x3A + i] = f"F{i + 1}"
for i in range(9):
    HID[0x59 + i] = f"KP{i + 1}"
for i in range(12):
    HID[0x68 + i] = f"F{i + 13}"

# spellings people type that are not already canonical names; the canonical
# table wins first, so these only add synonyms
ALIASES: dict[str, int] = {
    "fn": 0xAF,
    "rightarrow": 0x4F, "leftarrow": 0x50, "uparrow": 0x52, "downarrow": 0x51,
    "escape": 0x29, "return": 0x28, "bksp": 0x2A, "spacebar": 0x2C,
    "caps": 0x39, "capslock": 0x39, "del": 0x4C, "ins": 0x49,
    "pgup": 0x4B, "pgdn": 0x4E, "prtsc": 0x46, "scrlk": 0x47,
    "win": 0xE3, "super": 0xE3, "lwin": 0xE3, "lgui": 0xE3,
    "rwin": 0xE7, "rgui": 0xE7,
    "apps": 0x65, "application": 0x65, "contextmenu": 0x65,
    "none": 0x00,
}


def name(usage: int) -> str:
    return HID.get(usage, f"usage 0x{usage:02X}")


def display(usage: int) -> str:
    """Name for reports: 0xAF reads as 'Fn', everything else as HID."""
    return "Fn" if usage == 0xAF else name(usage)


def usage_of(spec) -> int:
    """Accept a usage int, a 0xXX string, a HID name, or an alias."""
    if isinstance(spec, int):
        return spec
    s = str(spec).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    for usage, nm in HID.items():
        if nm.lower() == s.lower():
            return usage
    if s.lower() in ALIASES:
        return ALIASES[s.lower()]
    raise SystemExit(f"unknown usage name: {spec!r} (try --list, or 0xXX)")


def key_names() -> list[str]:
    """Every spelling a request may use, for help text."""
    seen = {n.lower() for n in HID.values()}
    return sorted(seen | set(ALIASES))
