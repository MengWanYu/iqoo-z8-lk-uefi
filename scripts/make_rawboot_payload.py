#!/usr/bin/env python3
"""Wrap BootShim + UEFI FD in the RAWBOOT header consumed by the LK payload.

Usage:
  python3 scripts/make_rawboot_payload.py <BootShim.bin> <UEFI.fd> <out.img>

Header (little-endian, 0x28 bytes):
  "RAWBOOT!"  magic
  u64 load_addr  0 = execute in place (payload right after the header)
  u64 entry      0 = payload start (LK computes base + 0x28)
  u64 dtb_addr   passed to ATF as x2 (0 if unused)
  u64 payload_size
"""
import argparse
import hashlib
import struct
from pathlib import Path

MAGIC = b"RAWBOOT!"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("shim")
    ap.add_argument("fd")
    ap.add_argument("out")
    ap.add_argument("--pad", type=lambda s: int(s, 0), default=0,
                    help="pad image to at least N bytes (platform-tools boot needs a minimum)")
    ap.add_argument("--load", type=lambda s: int(s, 0), default=0,
                    help="PA to copy payload to before the ATF SMC (0 = in place)")
    ap.add_argument("--dtb", type=lambda s: int(s, 0), default=0,
                    help="DTB PA passed to the ATF SMC")
    a = ap.parse_args()

    shim = Path(a.shim).read_bytes()
    fd = Path(a.fd).read_bytes()
    payload = shim + fd
    hdr = MAGIC + struct.pack("<QQQQ", a.load, 0, a.dtb, len(payload))
    out = hdr + payload
    if a.pad and len(out) < a.pad:
        out += b"\0" * (a.pad - len(out))
    Path(a.out).write_bytes(out)
    print(f"payload : {len(payload)} bytes (shim {len(shim)} + FD {len(fd)}); load={a.load:#x} dtb={a.dtb:#x}")
    print(f"image   : {len(out)} bytes -> {a.out}")
    print(f"sha256  : {hashlib.sha256(out).hexdigest()}")


if __name__ == "__main__":
    main()
