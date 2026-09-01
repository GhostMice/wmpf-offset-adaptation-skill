#!/usr/bin/env python3
"""
Extract WMPF WeChatAppEx Framework (darwin arm64) Frida offsets.

Usage:
  python extract_wmpf_offsets_darwin.py
  python extract_wmpf_offsets_darwin.py --version 6.25529 -o addresses.6.25529.json
"""

from __future__ import annotations

import argparse
import bisect
import json
import plistlib
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

IMM_RE = re.compile(r"#(?:0x)?([0-9a-f]+)", re.I)

try:
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
except ImportError:
    print("Missing deps: pip install capstone", file=sys.stderr)
    sys.exit(1)

DEFAULT_FRAMEWORK = Path(
    "/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Frameworks/"
    "WeChatAppEx Framework.framework/Versions/C/WeChatAppEx Framework"
)
DEFAULT_INFO_PLIST = Path(
    "/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Info.plist"
)


def ensure_arm64_binary(framework: Path) -> tuple[Path, tempfile.TemporaryDirectory | None]:
    if not framework.is_file():
        raise FileNotFoundError(f"WeChatAppEx Framework not found: {framework}")
    tmp = tempfile.TemporaryDirectory(prefix="wmpf-arm64-")
    out = Path(tmp.name) / "WeChatAppEx_arm64.dylib"
    subprocess.run(
        ["lipo", "-thin", "arm64", "-output", str(out), str(framework)],
        check=True,
        capture_output=True,
    )
    return out, tmp


def get_wmpf_version(plist_path: Path) -> float:
    with plist_path.open("rb") as f:
        info = plistlib.load(f)
    return float(info["CFBundleVersion"])


def scan_prologues(text: bytes, text_base: int) -> list[int]:
    prologues: list[int] = []
    for i in range(0, len(text), 4):
        insn, = struct.unpack_from("<I", text, i)
        if (insn & 0xFFC07FFF) == 0xA9007BFD or (insn & 0xFFE07FFF) == 0xA9807BFD:
            prologues.append(text_base + i)
    return prologues


def func_for_addr(prologues: list[int], text_end: int, addr: int) -> tuple[int, int] | None:
    i = bisect.bisect_right(prologues, addr) - 1
    if i < 0:
        return None
    start = prologues[i]
    end = prologues[i + 1] if i + 1 < len(prologues) else text_end
    if start <= addr < end:
        return start, end
    return None


def scan_adrp_add_xrefs(text: bytes, text_base: int, target: int) -> list[int]:
    hits: list[int] = []
    for i in range(0, len(text) - 8, 4):
        insn1, insn2 = struct.unpack_from("<II", text, i)
        if (insn1 & 0x9F000000) != 0x90000000:
            continue
        if (insn2 & 0xFFC00000) != 0x91000000:
            continue
        rd1 = insn1 & 0x1F
        rd2 = insn2 & 0x1F
        rn2 = (insn2 >> 5) & 0x1F
        if rd1 != rd2 or rn2 != rd1:
            continue
        pc = text_base + i
        immhi = (insn1 >> 5) & 0x7FFFF
        immlo = (insn1 >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        page = (pc & ~0xFFF) + (imm << 12)
        add_imm = (insn2 >> 10) & 0xFFF
        if page + add_imm == target:
            hits.append(pc)
    return hits


def parse_bl_target(text: bytes, text_base: int, ea: int) -> int | None:
    off = ea - text_base
    if off < 0 or off + 4 > len(text):
        return None
    insn, = struct.unpack_from("<I", text, off)
    if (insn & 0xFC000000) != 0x94000000:
        return None
    imm = insn & 0x03FFFFFF
    if imm & (1 << 25):
        imm -= 1 << 26
    return ea + (imm << 2)


def parse_bl_addr(op: str) -> int:
    op = op.strip().lstrip("#")
    return int(op, 16) if op.startswith("0x") else int(op, 16)


def find_cdp_offset(
    data: bytes, text: bytes, text_base: int, prologues: list[int], text_end: int
) -> int:
    idx = data.find(b"SendToClientFilter")
    if idx < 0:
        raise RuntimeError("SendToClientFilter string not found")
    xrefs = scan_adrp_add_xrefs(text, text_base, idx)
    if not xrefs:
        raise RuntimeError("No code xref to SendToClientFilter")

    func = func_for_addr(prologues, text_end, xrefs[0])
    if not func:
        raise RuntimeError("No function for SendToClientFilter xref")
    begin, _ = func

    for i in range(0, 0x600, 4):
        tgt = parse_bl_target(text, text_base, begin + i)
        if tgt is not None:
            return tgt
    raise RuntimeError("No BL call at start of CDP parent function")


def find_loadstart_offset(
    data: bytes, text: bytes, text_base: int, prologues: list[int], text_end: int
) -> tuple[int, int]:
    needle_cc = b"applet_index_container.cc"
    needle_fn = b"AppletIndexContainer::OnLoadStart(bool"
    func_flags: dict[tuple[int, int], set[str]] = {}

    for i in range(0, len(text) - 8, 4):
        insn1, insn2 = struct.unpack_from("<II", text, i)
        if (insn1 & 0x9F000000) != 0x90000000:
            continue
        if (insn2 & 0xFFC00000) != 0x91000000:
            continue
        rd1 = insn1 & 0x1F
        rd2 = insn2 & 0x1F
        rn2 = (insn2 >> 5) & 0x1F
        if rd1 != rd2 or rn2 != rd1:
            continue
        pc = text_base + i
        immhi = (insn1 >> 5) & 0x7FFFF
        immlo = (insn1 >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        page = (pc & ~0xFFF) + (imm << 12)
        add_imm = (insn2 >> 10) & 0xFFF
        s = data[page + add_imm : page + add_imm + 160].split(b"\x00")[0]
        has_cc = needle_cc in s
        has_fn = needle_fn in s
        if not (has_cc or has_fn):
            continue
        func = func_for_addr(prologues, text_end, pc)
        if not func:
            continue
        flags = func_flags.setdefault(func, set())
        if has_cc:
            flags.add("cc")
        if has_fn:
            flags.add("fn")

    for (begin, end), flags in func_flags.items():
        if flags == {"cc", "fn"} and end - begin < 0x8000:
            return begin, end
    raise RuntimeError("AppletIndexContainer::OnLoadStart function not found")


def find_scene_offsets(
    data: bytes, text: bytes, text_base: int, md: Cs, loadstart: int, loadend: int
) -> list[int]:
    blob = text[loadstart - text_base : loadend - text_base]
    insns = list(md.disasm(blob, loadstart))

    off0 = 0x38
    off1 = None
    callee = None

    for i, ins in enumerate(insns):
        if ins.mnemonic != "ldp":
            continue
        m = IMM_RE.search(ins.op_str)
        if not m or int(m.group(1), 16) != off0:
            continue
        local_off1 = None
        local_callee = None
        for ins2 in insns[i + 1 : i + 20]:
            m2 = IMM_RE.search(ins2.op_str)
            if ins2.mnemonic == "ldr" and m2:
                local_off1 = int(m2.group(1), 16)
                break
        for ins2 in insns[i + 1 : i + 20]:
            if ins2.mnemonic != "bl":
                continue
            cand = parse_bl_addr(ins2.op_str)
            head = data[cand : cand + 0x40]
            matched = any(
                ci.mnemonic == "cmp" and "0x44d" in ci.op_str.lower()
                for ci in md.disasm(head, cand)
            )
            if matched:
                local_callee = cand
                break
        if local_off1 is not None and local_callee is not None:
            off1 = local_off1
            callee = local_callee

    if off1 is None or callee is None:
        raise RuntimeError("Could not parse OnLoadStart scene call pattern")

    callee_blob = data[callee : callee + 0x40]
    imm_offsets: list[int] = []
    for ci in md.disasm(callee_blob, callee):
        m = IMM_RE.search(ci.op_str)
        if ci.mnemonic == "ldr" and m:
            imm_offsets.append(int(m.group(1), 16))
        if len(imm_offsets) >= 4:
            break
    if len(imm_offsets) < 4:
        raise RuntimeError(f"Incomplete scene chain in callee {callee:#x}: {imm_offsets=}")
    off2, off3, off4, off5 = imm_offsets[0], imm_offsets[1], imm_offsets[2], imm_offsets[3]
    return [off0, off1, off2, off3, off4, off5]


def parse_text_section(data: bytes) -> tuple[int, int, int]:
    ncmds, = struct.unpack_from("<I", data, 16)
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            nsects, = struct.unpack_from("<I", data, off + 64)
            soff = off + 72
            for _ in range(nsects):
                sname = data[soff : soff + 16].split(b"\x00")[0].decode()
                if sname == "__text":
                    addr, size, fileoff = struct.unpack_from("<QQI", data, soff + 32)
                    return addr, fileoff, size
                soff += 80
        off += cmdsize
    raise RuntimeError("__text section not found")


def extract(version: float, binary: Path) -> dict:
    data = binary.read_bytes()
    text_base, text_off, text_size = parse_text_section(data)
    text = data[text_off : text_off + text_size]
    text_end = text_base + text_size

    prologues = scan_prologues(text, text_base)
    if not prologues:
        raise RuntimeError("No function prologues found in __text")

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    cdp = find_cdp_offset(data, text, text_base, prologues, text_end)
    loadstart, loadend = find_loadstart_offset(data, text, text_base, prologues, text_end)
    scene = find_scene_offsets(data, text, text_base, md, loadstart, loadend)

    return {
        "Version": version,
        "LoadStartHookOffset": hex(loadstart),
        "CDPFilterHookOffset": hex(cdp),
        "SceneOffsets": scene,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract WMPF darwin arm64 Frida offsets")
    parser.add_argument("--version", type=float, help="WMPF version (CFBundleVersion)")
    parser.add_argument("--binary", type=Path, help="arm64 Mach-O binary path")
    parser.add_argument("--framework", type=Path, default=DEFAULT_FRAMEWORK)
    parser.add_argument("--info-plist", type=Path, default=DEFAULT_INFO_PLIST)
    parser.add_argument("--output", "-o", type=Path, help="Write JSON to this file")
    args = parser.parse_args()

    version = args.version if args.version is not None else get_wmpf_version(args.info_plist)

    tmp: tempfile.TemporaryDirectory | None = None
    if args.binary:
        binary = args.binary
    else:
        binary, tmp = ensure_arm64_binary(args.framework)

    try:
        result = extract(version, binary)
    finally:
        if tmp:
            tmp.cleanup()

    text = json.dumps(result, indent=4) + "\n"
    print(text)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
