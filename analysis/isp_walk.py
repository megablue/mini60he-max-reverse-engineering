#!/usr/bin/env python3
"""isp_walk.py - phase-3 static walk of ISP_Command / CSN8F2250_ISPDlg inside
the pinned Mini60 HE Max updater exe (SONiX USB MCU ISP Tool).

Read-only by design: the exe is opened as bytes (pinned SHA-256 enforced)
and disassembled with capstone (x86, 32-bit). The exe is never executed and
no HID device is opened or enumerated — every claim here is static bytes.

    python analysis/isp_walk.py                # full report -> out/isp_walk.txt
    python analysis/isp_walk.py func 0x4XXXXX  # dump one function to stdout

Artifacts: analysis/out/isp_walk.txt
"""
from __future__ import annotations

import hashlib
import re
import struct
import sys
from pathlib import Path

import capstone
import pefile

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "bin" / "MINI 60 HE MAX_V1.52.exe"
OUT = ROOT / "analysis" / "out"
REPORT = OUT / "isp_walk.txt"

SHA256_PIN = "958A39951D2F908A7FE925E0FA598C321924CB235239BF37484AE7C8213512D6"

STRINGS = {
    "enter_isp":        "Enter ISP Mode (0x20)",
    "pwd02":            "Compare ISP Password (0x02)",
    "pwd22":            "Compare ISP Password (0x22)",
    "enc03":            "Set Encryption Algorithm (0x03)",
    "enc23":            "Set Encryption Algorithm (0x23)",
    "check_bootloader": "CheckBootLoaderID",
    "check_checksum":   "Check CheckSum",
    "check_sonix":      "Check if connected device is SONiX ISP",
    "ver_match_sn8":    "Check if the firmware version in SN8 matches device",
    "ver_hw_sn8f2250":  "Check if this high word of firmware version matches SN8F2250",
    "ver_sw_mm1":       "FW Version in SN8 does not match that of USB Device.",
    "ver_sw_mm2":       "FW Version is not for this chip.",
    "ver_file_dev":     "Firmware Version in SN8 file does not match that of USB Device!",
    "ver_chip":         "Firmware Version does not match this chip !!",
    "sn8_checksum":     "SN8 Check Sum : %.4X",
    "bin_checksum":     "Bin File Check Sum : %.4X",
    "dev_version":      "Device Version :",
    "checksum_label":   "Checksum :",
    "enable_enc":       "Enable Encryption",
    "write_password":   "Write down the password and verify if it is valid",
    "wrong_password":   "Wrong Password Format!!",
    "check_pwd_format": "Check ISP Password format",
    "no_hid":           "Can't Find USB HID Device!!",
    "sonix_dev":        "SONiX ISP Device",
    "snx_find":         "SNX_Find_HID = VID:%04x, PID:%04x ",
    "find_device":      "Find Device-> VID:%04x, PID:%04x ",
    "hid_iface":        "hid#vid_%04x&pid_%04x",
    "vid_pid_row":      "----VID: %.4X  PID: %.4X-----  No. %.3d",
    "feature_len":      "FeatureReportByteLength : %d ",
    "sn8_not_attached": "SN8 File is not for the attached device!!",
    "check_sn8":        "Check SN8 File",
    "hex_ckpt_err":     "The checksum in hex file is error!! Line number(%d)",
    "hex_special_err":  "The format of hex file for special VID %s, PID %s is wrong!",
    "codesec_special":  "The code security setting of special VID %s, PID %s is wrong.",
    "ver_not_supported": "This FW Version. is not supported.",
    "ver_unsupported":  "This firmware version is not supported!!",
    "sec_cs3":          "Security = CS3, Unsupport  ISP Download !!",
    "sec_changed":      "Device security level has been changed, unsupport ISP Download !!",
}
RTTI_NAMES = {
    "ISP_Command":      ".?AVISP_Command@@",
    "CSN8F2250_ISPDlg": ".?AVCSN8F2250_ISPDlg@@",
    "CSN8F2250_ISPApp": ".?AVCSN8F2250_ISPApp@@",
}
RCDATA_IDS = (4000, 4007, 4008, 4009, 4010, 4011, 4013, 4014, 4016)
CMD_IMMS = {0x02, 0x03, 0x04, 0x05, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
            0x27, 0x28, 0x30, 0x31, 0x32, 0x33, 0x35, 0x3A, 0x3B, 0x40, 0x44,
            0x7A}
IMPORTS_OF_INTEREST = [
    "HidD_SetFeature", "HidD_GetFeature", "HidD_GetAttributes",
    "HidD_GetPreparsedData", "HidP_GetCaps", "HidP_GetSpecificValueCaps",
    "HidD_GetProductString", "HidD_FreePreparsedData",
    "SetupDiGetClassDevsW", "SetupDiEnumDeviceInterfaces",
    "SetupDiGetDeviceInterfaceDetailW", "SetupDiDestroyDeviceInfoList",
    "CreateFileW", "CloseHandle", "FindResourceW", "LoadResource",
    "LockResource", "SizeofResource", "FreeResource", "wsprintfW",
    "lstrlenW", "lstrcpyW", "lstrcmpW", "MultiByteToWideChar",
    "WideCharToMultiByte", "wcstoul", "wcstol", "swscanf",
]

lines: list[str] = []


def out(*a):
    lines.append(" ".join(str(x) for x in a))


def hx(v: int) -> str:
    return f"0x{v:X}"


def find_all(blob: bytes, pat: bytes):
    i, res = blob.find(pat), []
    while i != -1:
        res.append(i)
        i = blob.find(pat, i + 1)
    return res


class World:
    def __init__(self):
        self.raw = EXE.read_bytes()
        self.sha = hashlib.sha256(self.raw).hexdigest()
        if self.sha.upper() != SHA256_PIN:
            raise SystemExit(f"pin mismatch: {self.sha}; refusing to analyze")
        self.pe = pefile.PE(data=self.raw)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.ranges = []  # (off0, off1, va0, va1, name)
        for sec in self.pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("latin-1")
            self.ranges.append((sec.PointerToRawData,
                                sec.PointerToRawData + sec.SizeOfRawData,
                                self.base + sec.VirtualAddress,
                                self.base + sec.VirtualAddress + sec.SizeOfRawData,
                                name))

    def va_bytes(self, va: int):
        """(bytes-at-va, off-in-range, section) for a VA inside a raw section."""
        for off0, off1, va0, va1, name in self.ranges:
            if va0 <= va < va1:
                return self.raw[off0:off1], va - va0, name
        return None, None, None

    def off_va(self, off: int):
        for off0, off1, va0, va1, name in self.ranges:
            if off0 <= off < off1:
                return va0 + (off - off0), name
        return None, None

    def section_of(self, va: int):
        for off0, off1, va0, va1, name in self.ranges:
            if va0 <= va < va1:
                return name
        return None


def md_new():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False
    md.skipdata = True
    return md


def prologues(text: bytes, textva: int):
    """byte positions of 55 8B EC / 8B FF 55 8B EC inside text"""
    p = set()
    for i in find_all(text, b"\x8b\xff\x55\x8b\xec"):
        p.add(i)
    for i in find_all(text, b"\x55\x8b\xec"):
        p.add(i)
    return {textva + i for i in p}


def dump_func(w: World, md, start: int, known_starts, str_by_va, iat_by_va,
              rcdata_by_imm, max_lines=700):
    blob, off, secn = w.va_bytes(start)
    if blob is None:
        return [f"{hx(start)} not in any mapped section"], secn
    res = []
    res.append(f"--- function {hx(start)} ({secn}) ---")
    prev_m, skip_run = "", 0
    try:
        for insn in md.disasm(blob[off:], start):
            if skip_run > 60:
                res.append("... (60+ invalid/skipped bytes, giving up)")
                break
            if insn.bytes.hex() == "cc" and prev_m in ("int3", "ret"):
                res.append(f"{insn.address:08X}  <int3 padding, end>")
                break
            notes = []
            for tok in re.findall(r"0x[0-9A-Fa-f]+", insn.op_str):
                v = int(tok, 16)
                if v in str_by_va:
                    notes.append(f"STR:{str_by_va[v]}")
                if v in iat_by_va:
                    notes.append(f"IMP:{iat_by_va[v]}")
                if insn.mnemonic.startswith("call") and v in known_starts:
                    notes.append(f"FUN:{hx(v)}")
                if v in rcdata_by_imm:
                    notes.append(f"RCDATA:{rcdata_by_imm[v]}")
                if v in CMD_IMMS:
                    notes.append(f"cmd?=0x{v:02X}")
            b = insn.bytes.hex()
            res.append(f"{insn.address:08X}  {b:<22s} {insn.mnemonic:8s} "
                       f"{insn.op_str}{'   ; ' + ' '.join(notes) if notes else ''}")
            skip_run = skip_run + 1 if insn.mnemonic == "(bad)" or not b else 0
            prev_m = insn.mnemonic
            if len(res) > max_lines:
                res.append(f"... truncated at {max_lines} lines")
                break
    except Exception as e:  # noqa: BLE001
        res.append(f"disasm error: {e}")
    res.append("--- end ---")
    return res, secn


def containing_fn(starts_sorted, site: int):
    import bisect
    i = bisect.bisect_right(starts_sorted, site) - 1
    return starts_sorted[i] if i >= 0 else None


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "report"
    w = World()
    md = md_new()
    text_ranges = [r for r in w.ranges if r[4] == ".text"]
    tr = text_ranges[0]
    text = w.raw[tr[0]:tr[1]]
    textva = tr[2]

    # --- IAT slots of interest -------------------------------------------
    iat: dict[str, int] = {}
    for entry in w.pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name and imp.name.decode() in IMPORTS_OF_INTEREST:
                iat[imp.name.decode()] = imp.address
    iat_by_va = {v: k for k, v in iat.items()}

    # --- string constant hunting (UTF-16 in mapped sections) --------------
    str_by_va: dict[int, str] = {}
    str_sites: dict[str, list[int]] = {}
    for key, s in STRINGS.items():
        vlist = []
        for cand in (s, s.rstrip()):
            utf16 = cand.encode("utf-16-le") + b"\x00\x00"
            for r in w.ranges:
                blob = w.raw[r[0]:r[1]]
                for i in find_all(blob, utf16):
                    va, _ = w.off_va(r[0] + i)
                    if va is not None and va not in vlist:
                        vlist.append(va)
            if vlist:
                break
        for va in vlist:
            str_by_va.setdefault(va, key)
        str_sites[key] = sorted(vlist)

    # --- string xref byte-scan in .text -----------------------------------
    str_xref: dict[str, list[int]] = {}
    for key, vas in str_sites.items():
        sites = []
        for va in vas:
            for i in find_all(text, struct.pack("<I", va)):
                sites.append(textva + i)
        str_xref[key] = sorted(set(sites))

    # --- E8 call scan ------------------------------------------------------
    e8 = []
    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            rel = int.from_bytes(text[i + 1:i + 5], "little", signed=True)
            tgt = textva + i + 5 + rel
            if tr[2] <= tgt < tr[3]:
                e8.append((textva + i, tgt))
    callers = {}
    for site, tgt in e8:
        callers.setdefault(tgt, []).append(site)

    # --- prologues and function candidates --------------------------------
    pro = prologues(text, textva)
    pro_sorted = sorted(pro)
    known = set(pro)
    known |= {t for _, t in e8}
    known.add(w.base + w.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    known_sorted = sorted(known)

    def fn_of(site: int):
        best = None
        for p in pro_sorted:
            if p <= site:
                best = p
            else:
                break
        return best

    def uniq_fns(sites):
        fs = {fn_of(s) for s in sites}
        fs.discard(None)
        return sorted(fs)

    # --- FF 15 indirect IAT call sites -------------------------------------
    io_sites = {}
    for i in range(len(text) - 6):
        if text[i] == 0xFF and text[i + 1] == 0x15:
            tgt = int.from_bytes(text[i + 2:i + 6], "little")
            if tgt in iat_by_va:
                io_sites.setdefault(iat_by_va[tgt], []).append(textva + i)

    # --- RCDATA id immediate scan in .text ---------------------------------
    rcdata_by_imm = {}
    immsites = {}
    for rid in RCDATA_IDS:
        sites = [textva + i for i in find_all(text, struct.pack("<I", rid))]
        immsites[rid] = sites
        rcdata_by_imm[rid] = rid

    # --- interesting functions: containing the hunted evidence ------------
    interesting = set()
    for key, sites in str_xref.items():
        for s in sites:
            f = fn_of(s)
            if f:
                interesting.add(f)
    for name, sites in io_sites.items():
        for s in sites:
            f = fn_of(s)
            if f:
                interesting.add(f)
    function_evidence = {}
    for key, sites in str_xref.items():
        for s in sites:
            function_evidence.setdefault(fn_of(s), {}).setdefault(key, []).append(s)

    if mode == "scan":
        va = int(sys.argv[2], 0)
        pat = struct.pack("<I", va)
        for r in w.ranges:
            blob = w.raw[r[0]:r[1]]
            for i in find_all(blob, pat):
                site_va, _ = w.off_va(r[0] + i)
                lo = max(0, i - 6)
                ctx = blob[lo:i + 8].hex(" ")
                print(f"{r[4]:6s} site {hx(site_va)}  ctx[{ctx}]")
        return 0
    if mode == "callers":
        va = int(sys.argv[2], 0)
        text2 = w.raw[tr[0]:tr[1]]
        n = 0
        for i in range(len(text2) - 5):
            if text2[i] == 0xE8:
                rel = int.from_bytes(text2[i + 1:i + 5], "little", signed=True)
                if textva + i + 5 + rel == va:
                    print(f"call site {hx(textva + i)}")
                    n += 1
        print(f"{n} direct E8 callers of {hx(va)}")
        return 0
    if mode == "dis":
        va = int(sys.argv[2], 0)
        n = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x200
        blob, off, secn = w.va_bytes(va)
        count = 0
        for insn in md.disasm(blob[off:off + n], va):
            b = insn.bytes.hex()
            print(f"{insn.address:08X}  {b:<20s} {insn.mnemonic:8s} {insn.op_str}")
            count += 1
            if insn.mnemonic == "ret":
                pass
        if not count:
            print("no decode")
        return 0
    if mode == "io":
        buf_lines = []
        wr = {}
        for name, target in (("SET", 0x428680), ("GETFN", 0x428930)):
            sites = []
            for i in range(len(text) - 5):
                if text[i] == 0xE8:
                    rel = int.from_bytes(text[i + 1:i + 5], "little", signed=True)
                    if textva + i + 5 + rel == target:
                        sites.append(textva + i)
            wr[name] = sites
        for name, sites in wr.items():
            buf_lines.append(f"### {name} wrapper callers ({len(sites)})")
            for s in sites:
                lo = max(0, s - 0x90)
                seg = text[lo - textva: s - textva + 0x10]
                buf_lines.append(f"--- {name} site 0x{s:X} ---")
                for insn in md.disasm(seg, lo):
                    b = insn.bytes.hex()
                    notes = ""
                    for tok in re.findall(r"0x[0-9A-Fa-f]+", insn.op_str):
                        v = int(tok, 16)
                        if v == 0x5b6d48:
                            notes += " STATE"
                        if v in (0x55b1f4, 0x55b1f8):
                            notes += " HID_IAT"
                    if insn.mnemonic != "(bad)" or insn.bytes[0] != 0:
                        buf_lines.append(
                            f"{insn.address:08X}  {b:<20s} {insn.mnemonic:8s} "
                            f"{insn.op_str}{notes}")
                buf_lines.append("")
        (OUT / "io_sites.txt").write_text(
            "\n".join(buf_lines) + "\n", encoding="ascii", errors="replace")
        print(f"io sites -> {OUT / 'io_sites.txt'} ({len(buf_lines)} lines)")
        return 0
    if mode != "report":
        va = int(sys.argv[2], 0)
        start = fn_of(va) or va
        dump, _ = dump_func(w, md, start, known, str_by_va, iat_by_va,
                            rcdata_by_imm, max_lines=4000)
        print("\n".join(dump))
        return 0

    # ================= report =============================================
    out(f"target : {EXE.name}  {len(w.raw):,} bytes")
    out(f"sha256 : {w.sha}  (pin match ok)")
    for off0, off1, va0, va1, name in w.ranges:
        out(f"section: {name:8s} va {hx(va0)}..{hx(va1)} raw {off0:#x}..{off1:#x}")
    out(f"entry  : {hx(w.base + w.pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
    out("")
    out("== hunted imports (IAT slot VAs) ==")
    for k in IMPORTS_OF_INTEREST:
        if k in iat:
            out(f"  {k:34s} {hx(iat[k])}")
    for k in [k for k in IMPORTS_OF_INTEREST if k not in iat]:
        out(f"  {k:34s} (not imported)")
    out("")

    out("== string constants (UTF-16) -> VAs ==")
    for key in sorted(str_sites):
        if str_sites[key]:
            out(f"  {key:18s} " + " ".join(hx(v) for v in str_sites[key]))
        else:
            out(f"  {key:18s} (not found)")
    out("")
    out("== string xrefs in .text (byte sites of the VAs) ==")
    for key in sorted(str_xref):
        n = len(str_xref[key])
        fns = uniq_fns(str_xref[key])
        out(f"  {key:18s} sites {n:2d}  fns: " + " ".join(hx(f) for f in fns))
    out("")
    out("== indirect HID/setupapi/... call sites per import ==")
    for name in sorted(io_sites):
        sites = io_sites[name]
        out(f"  {name:34s} {len(sites):2d} sites: {hx(sites[0])}..{hx(sites[-1])}"
            + (" (more)" if len(sites) > 2 else ""))
    out("")
    out("== RTTI walk ==")
    for cls, name in RTTI_NAMES.items():
        pat = name.encode()
        td_vas = []
        for r in w.ranges:
            blob = w.raw[r[0]:r[1]]
            for i in find_all(blob, pat):
                va, _ = w.off_va(r[0] + i)
                if va:
                    td_vas.append(va - 8)  # name sits at +8 in TypeDescriptor
        out(f"  {cls}: typedesc {sorted(td_vas)}")
        for td in td_vas:
            cols = []
            for r in w.ranges:
                blob = w.raw[r[0]:r[1]]
                for i in range(0, len(blob) - 4, 4):
                    if int.from_bytes(blob[i:i + 4], "little") == td:
                        va, secn = w.off_va(r[0] + i)
                        if va:
                            cols.append((va - 12, secn))
            out(f"    COL candidates: {[(hx(c), s) for c, s in cols]}")
            for col, _ in cols:
                vfts = []
                for r in w.ranges:
                    blob = w.raw[r[0]:r[1]]
                    for i in range(0, len(blob) - 4, 4):
                        if int.from_bytes(blob[i:i + 4], "little") == col:
                            va, secn = w.off_va(r[0] + i)
                            if va:
                                vfts.append((va + 4, secn))
                out(f"    vftable candidates @ COL {hx(col)}: "
                    + ", ".join(hx(v) for v, _ in vfts))
                for vft, _ in vfts:
                    blob, off, secn = w.va_bytes(vft)
                    if blob is None:
                        continue
                    ptrs = []
                    for j in range(0, len(blob) - off, 4):
                        p = int.from_bytes(blob[off + j:off + j + 4], "little")
                        if w.section_of(p) == ".text":
                            ptrs.append(p)
                        else:
                            break
                    out(f"    vftable {hx(vft)}: {len(ptrs)} slots -> "
                        + " ".join(hx(p) for p in ptrs[:40]))
                    interesting |= set(ptrs[:40])
    out("")

    out("== RCDATA-id immediate sites in .text ==")
    for rid in RCDATA_IDS:
        fns = uniq_fns(immsites[rid])
        out(f"  id {rid}  sites {len(immsites[rid]):2d}  fns: "
            + " ".join(hx(f) for f in fns[:12]))
    out("")

    out("== interesting function set (string/HID/RCDATA/vtable evidence) ==")
    for f in sorted(interesting):
        ev = function_evidence.get(f, {})
        bits = "; ".join(f"{k}:{len(v)}" for k, v in sorted(ev.items()))
        ncall = len(callers.get(f, []))
        out(f"  {hx(f)}  callers:{ncall:3d}  str:sites {bits}")
    out("")

    out("== function dumps (evidence set, VA ascending) ==")
    for f in sorted(interesting):
        dump, _ = dump_func(w, md, f, known, str_by_va, iat_by_va,
                            rcdata_by_imm, max_lines=700)
        out("")
        lines.extend(dump)
    out("")

    # callers of each interesting function (one level)
    out("== direct callers of interesting functions ==")
    for f in sorted(interesting):
        c = callers.get(f, [])
        fns = uniq_fns(c)
        out(f"  {hx(f)}: sites {len(c)} from fns " + " ".join(hx(x) for x in fns[:16]))
    out("")

    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"rapport: {len(lines)} lines -> {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
