#!/usr/bin/env python3
"""
Extract WMPF flue.dll Frida offsets for addresses.{version}.json

Usage:
  python extract_wmpf_offsets.py --version 25047
  python extract_wmpf_offsets.py --version 25047 --dll path/to/flue.dll
  python extract_wmpf_offsets.py --version 25047 --output addresses.25047.json
  python extract_wmpf_offsets.py --version 25047 --write --config-dir ./frida/config
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path

try:
    import pefile
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
except ImportError:
    print("Missing deps: pip install pefile capstone", file=sys.stderr)
    sys.exit(1)

IMAGE_BASE = 0x180000000
DEFAULT_DLL = (
    Path.home()
    / "AppData/Roaming/Tencent/xwechat/xplugin/Plugins/RadiumWMPF/{version}/extracted/runtime/flue.dll"
)


def load_pdata(pe: pefile.PE) -> list[tuple[int, int, int]]:
    entries: list[tuple[int, int, int]] = []
    for sec in pe.sections:
        if b".pdata" not in sec.Name:
            continue
        blob = sec.get_data()
        for i in range(0, len(blob), 12):
            if i + 12 > len(blob):
                break
            begin, end, unwind = struct.unpack_from("<III", blob, i)
            if begin:
                entries.append((begin, end, unwind))
    return entries


def func_for_addr(entries: list[tuple[int, int, int]], addr: int) -> tuple[int, int] | None:
    for begin, end, _ in entries:
        if begin <= addr < end:
            return begin, end
    return None


def scan_lea_xrefs(pe: pefile.PE, data: bytes, target_rva: int) -> list[int]:
    hits: list[int] = []
    for sec in pe.sections:
        if not sec.Characteristics & 0x20000000:
            continue
        base = sec.VirtualAddress
        blob = sec.get_data()
        for i in range(len(blob) - 7):
            if blob[i + 1] != 0x8D or blob[i] not in (0x48, 0x4C):
                continue
            disp = struct.unpack_from("<i", blob, i + 3)[0]
            insn = base + i
            if insn + 7 + disp == target_rva:
                hits.append(insn)
    return hits


def parse_e8(data: bytes, pe: pefile.PE, ea: int) -> int | None:
    off = pe.get_offset_from_rva(ea)
    if data[off] != 0xE8:
        return None
    rel = struct.unpack_from("<i", data, off + 1)[0]
    return ea + 5 + rel


def cstr_at(pe: pefile.PE, data: bytes, rva: int, n: int = 200) -> bytes:
    try:
        off = pe.get_offset_from_rva(rva)
    except pefile.PEFormatError:
        return b""
    return data[off : off + n].split(b"\x00")[0]


def lea_rip_targets(blob: bytes, base: int) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for i in range(len(blob) - 7):
        if blob[i] not in (0x48, 0x4C) or blob[i + 1] != 0x8D:
            continue
        disp = struct.unpack_from("<i", blob, i + 3)[0]
        insn = base + i
        out.append((insn, insn + 7 + disp))
    return out


def find_cdp_offset(pe: pefile.PE, data: bytes, pdata: list[tuple[int, int, int]]) -> int:
    idx = data.find(b"SendToClientFilter")
    if idx < 0:
        raise RuntimeError("SendToClientFilter string not found")
    str_rva = pe.get_rva_from_offset(idx)
    xrefs = scan_lea_xrefs(pe, data, str_rva)
    if not xrefs:
        raise RuntimeError("No code xref to SendToClientFilter")
    xref = xrefs[0]
    func = func_for_addr(pdata, xref)
    if not func:
        raise RuntimeError(f"No .pdata function for SendToClientFilter xref {xref:#x}")
    begin, _ = func
    off = pe.get_offset_from_rva(begin)
    for i in range(min(0x600, len(data) - off)):
        if data[off + i] == 0xE8:
            tgt = parse_e8(data, pe, begin + i)
            if tgt is not None:
                return tgt
    raise RuntimeError("No E8 call at start of CDP parent function")


def find_loadstart_offset(
    pe: pefile.PE, data: bytes, pdata: list[tuple[int, int, int]]
) -> int:
    needle_cc = b"applet_index_container.cc"
    needle_fn = b"AppletIndexContainer::OnLoadStart(bool"
    for begin, end, _ in pdata:
        if end - begin > 0x8000:
            continue
        off = pe.get_offset_from_rva(begin)
        blob = data[off : off + (end - begin)]
        has_cc = False
        has_fn = False
        for _, tgt in lea_rip_targets(blob, begin):
            s = cstr_at(pe, data, tgt)
            if needle_cc in s:
                has_cc = True
            if needle_fn in s:
                has_fn = True
        if has_cc and has_fn:
            return begin
    raise RuntimeError("AppletIndexContainer::OnLoadStart pdata function not found")


def find_scene_offsets(
    pe: pefile.PE, data: bytes, md: Cs, loadstart: int, loadend: int
) -> list[int]:
    off = pe.get_offset_from_rva(loadstart)
    blob = data[off : off + (loadend - loadstart)]
    insns = list(md.disasm(blob, IMAGE_BASE + loadstart))

    off0 = 0x40
    off1 = None
    callee = None

    for i, ins in enumerate(insns):
        m = re.search(r"\[rsi \+ (0x[0-9a-f]+)\]", ins.op_str, re.I)
        if ins.mnemonic != "mov" or not m or int(m.group(1), 16) != off0:
            continue
        local_off1 = None
        local_callee = None
        for ins2 in insns[i + 1 : i + 30]:
            m2 = re.search(r"\[rax \+ (0x[0-9a-f]+)\]", ins2.op_str, re.I)
            if ins2.mnemonic == "mov" and m2:
                local_off1 = int(m2.group(1), 16)
                break
        for ins2 in insns[i + 1 : i + 40]:
            if ins2.mnemonic != "call" or not ins2.op_str.startswith("0x"):
                continue
            cand = int(ins2.op_str, 16) - IMAGE_BASE
            coff = pe.get_offset_from_rva(cand)
            head = data[coff : coff + 0x40]
            matched = (
                b"\x81\xb9\xc8\x01\x00\x00" in head
                or b"\x83\xb9\xc8\x01\x00\x00" in head
                or b"\x83\xb8\xc8\x01\x00\x00" in head
            )
            if not matched:
                for ci in md.disasm(head, IMAGE_BASE + cand):
                    if ci.mnemonic == "cmp" and "0x1c8" in ci.op_str and "0x44d" in ci.op_str.lower():
                        matched = True
                        break
            if matched:
                local_callee = cand
                break
        if local_off1 is not None and local_callee is not None:
            off1 = local_off1
            callee = local_callee

    if off1 is None or callee is None:
        raise RuntimeError("Could not parse OnLoadStart tail call pattern")

    coff = pe.get_offset_from_rva(callee)
    callee_blob = data[coff : coff + 0x200]

    off2 = off3 = off4 = off5 = None
    if callee_blob.find(bytes([0x48, 0x8B, 0x41, 0x08])) >= 0:
        off2 = 8
    m = re.search(bytes([0x48, 0x8B, 0x88]) + rb"(.{4})", callee_blob, re.DOTALL)
    if m:
        off3 = struct.unpack("<I", m.group(1))[0]
    if callee_blob.find(bytes([0x48, 0x8B, 0x49, 0x10])) >= 0:
        off4 = 0x10
    m5 = re.search(
        bytes([0x81, 0xB9]) + rb"(.{4})" + bytes([0x4D, 0x04, 0x00, 0x00]),
        callee_blob,
        re.DOTALL,
    )
    if not m5:
        m5 = re.search(bytes([0x83, 0xB9]) + rb"(.{4})" + bytes([0x4D]), callee_blob, re.DOTALL)
    if m5:
        off5 = struct.unpack("<I", m5.group(1))[0]

    if None in (off2, off3, off4, off5):
        raise RuntimeError(
            f"Incomplete scene chain in callee {callee:#x}: "
            f"{off2=}, {off3=}, {off4=}, {off5=}"
        )
    return [off0, off1, off2, off3, off4, off5]


def extract(version: int, dll_path: Path) -> dict:
    if not dll_path.is_file():
        raise FileNotFoundError(f"flue.dll not found: {dll_path}")

    pe = pefile.PE(str(dll_path))
    data = dll_path.read_bytes()
    pdata = load_pdata(pe)
    if not pdata:
        raise RuntimeError(".pdata not found — not a valid x64 Windows DLL?")

    md = Cs(CS_ARCH_X86, CS_MODE_64)

    cdp = find_cdp_offset(pe, data, pdata)
    loadstart = find_loadstart_offset(pe, data, pdata)
    func = func_for_addr(pdata, loadstart)
    if not func:
        raise RuntimeError("LoadStart function missing from .pdata")
    _, loadend = func
    scene = find_scene_offsets(pe, data, md, loadstart, loadend)

    return {
        "Version": version,
        "LoadStartHookOffset": hex(loadstart),
        "CDPFilterHookOffset": hex(cdp),
        "SceneOffsets": scene,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract WMPF flue.dll Frida offsets")
    parser.add_argument("--version", type=int, required=True, help="WMPF version number")
    parser.add_argument("--dll", type=Path, help="Path to flue.dll")
    parser.add_argument("--output", "-o", type=Path, help="Write JSON to this file")
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write addresses.{version}.json (use with --config-dir)",
    )
    parser.add_argument(
        "--config-dir",
        type=Path,
        action="append",
        help="Config directory for --write (repeatable)",
    )
    args = parser.parse_args()

    dll = args.dll or Path(str(DEFAULT_DLL).format(version=args.version))
    result = extract(args.version, dll)

    text = json.dumps(result, indent=4) + "\n"
    print(text)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {args.output}", file=sys.stderr)

    if args.write:
        dirs = args.config_dir or [Path("frida/config")]
        for d in dirs:
            out = d / f"addresses.{args.version}.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text, encoding="utf-8")
            print(f"Wrote {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
