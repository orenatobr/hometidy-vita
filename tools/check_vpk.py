#!/usr/bin/env python3
"""Checks a built VPK against the rules the Vita installer enforces. Usage: check_vpk.py file.vpk

Fails (exit 1) when:
- the title id is not four capital letters plus five digits (error 0x80101130), or
- a PNG in sce_sys is not 8-bit indexed and non-interlaced (error 0x8010113D), or
- the version in param.sfo does not match the VERSION file (1.2.3 is stored as 01.23).
"""
import re
import struct
import sys
import zipfile
from pathlib import Path


def sfo_value(sfo: bytes, key: bytes) -> bytes | None:
    """Returns the raw value of a key in a param.sfo, or None."""
    if sfo[:4] != b"\x00PSF":
        return None
    key_off, data_off, count = struct.unpack("<III", sfo[8:20])
    for i in range(count):
        k, _fmt, length, _max, d = struct.unpack("<HHIII", sfo[20 + 16 * i : 36 + 16 * i])
        name = sfo[key_off + k : sfo.index(b"\x00", key_off + k)]
        if name == key:
            return sfo[data_off + d : data_off + d + length].rstrip(b"\x00")
    return None


def expected_app_ver() -> str:
    major, minor, patch = Path(__file__).resolve().parent.parent.joinpath("VERSION").read_text().strip().split(".")
    return f"{int(major):02d}.{minor}{patch}"


def main(path: str) -> int:
    errors = []
    z = zipfile.ZipFile(path)
    names = z.namelist()
    for required in ("sce_sys/param.sfo", "eboot.bin"):
        if required not in names:
            errors.append(f"missing {required}")

    sfo = z.read("sce_sys/param.sfo") if "sce_sys/param.sfo" in names else b""
    ids = set(re.findall(rb"[A-Z]{4}\d{5}", sfo))
    title = re.search(rb"([A-Z]{4}\d{5})\x00", sfo)
    if not title:
        errors.append("param.sfo has no title id of the form XXXX00000")

    app_ver = sfo_value(sfo, b"APP_VER")
    want = expected_app_ver()
    if app_ver is None or app_ver.decode() != want:
        errors.append(f"param.sfo APP_VER is {app_ver!r}, VERSION file says {want}")

    for name in names:
        if name.startswith("sce_sys/") and name.endswith(".png"):
            data = z.read(name)
            if data[:8] != b"\x89PNG\r\n\x1a\n":
                errors.append(f"{name}: not a PNG")
                continue
            width, height, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", data[16:29])
            if (depth, ctype, interlace) != (8, 3, 0):
                errors.append(f"{name}: bit depth {depth}, color type {ctype}, interlace {interlace} (need 8, 3, 0)")

    for e in errors:
        print("FAIL:", e)
    if not errors:
        print(f"OK: {path} ({len(names)} files, title id {title.group(1).decode() if title else '?'}, version {want})")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]) if len(sys.argv) == 2 else 2)
