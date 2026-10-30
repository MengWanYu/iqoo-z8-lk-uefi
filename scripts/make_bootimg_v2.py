#!/usr/bin/env python3
"""Build a self-contained v2 Android boot image for the LK normal boot path.

kernel = gzip(BootShim + UEFI FD)   (LK decompresses to kernel_addr)
dtb    = lk_main_dtb.bin            (LK copies to dtb_addr)
name   = "RAWBOOT-UEFI"             (handler marker)

Usage:
  python3 scripts/make_bootimg_v2.py <BootShim.bin> <UEFI.fd> <dtb> <out.img> [--dtb-gap N]

--dtb-gap inserts N zero bytes between the kernel and the DTB.  LK's v2
loader adds one page for each zero-sized ramdisk/recovery_dtbo section, so
a 0x1000 gap makes 0x26 (the base FDT pointer in boot_linux_fdt) land on
the DTB without the v3f overlay hook.
"""
import argparse
import gzip
import hashlib
import struct
from pathlib import Path

PAGE = 2048
HEADER_SIZE = 0x67C
KERNEL_ADDR = 0x40000000  # LK v2 path: mb_kernel is allocated at this exact address
DTB_ADDR = 0x47C80000
RAMDISK_ADDR = 0x51000000  # LK asserts ramdisk_target_addr != 0; size stays 0
NAME = b"RAWBOOT-UEFI"


def align(data, page=PAGE):
    rem = len(data) % page
    return data if rem == 0 else data + b"\0" * (page - rem)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("shim")
    ap.add_argument("fd")
    ap.add_argument("dtb")
    ap.add_argument("out")
    ap.add_argument("--dtb-gap", type=lambda v: int(v, 0), default=0)
    ap.add_argument("--kernel-addr", type=lambda v: int(v, 0), default=KERNEL_ADDR)
    args = ap.parse_args()

    shim = Path(args.shim).read_bytes()
    fd = Path(args.fd).read_bytes()
    dtb = Path(args.dtb).read_bytes()
    out_path = Path(args.out)

    kernel = gzip.compress(shim + fd, compresslevel=9, mtime=0)
    hdr = bytearray(HEADER_SIZE)
    hdr[0:8] = b"ANDROID!"
    struct.pack_into("<IIIIIIII", hdr, 0x08,
                     len(kernel), args.kernel_addr, 0, RAMDISK_ADDR, 0, 0,
                     DTB_ADDR, PAGE)
    struct.pack_into("<II", hdr, 0x28, 2, 0)     # header_version=2, os_version=0
    hdr[0x30:0x30 + len(NAME)] = NAME
    struct.pack_into("<I", hdr, 0x66C, HEADER_SIZE)
    struct.pack_into("<I", hdr, 0x670, len(dtb))
    struct.pack_into("<Q", hdr, 0x674, DTB_ADDR)

    image = align(bytes(hdr)) + align(kernel) + align(b"\0" * args.dtb_gap) + align(dtb)
    out_path.write_bytes(image)
    print(f"kernel gz : {len(kernel)} bytes (raw {len(shim) + len(fd)})")
    print(f"dtb       : {len(dtb)} bytes @ 0x{DTB_ADDR:x} (gap 0x{args.dtb_gap:x})")
    print(f"boot image: {len(image)} bytes -> {out_path}")
    print(f"sha256    : {hashlib.sha256(image).hexdigest()}")


if __name__ == "__main__":
    main()
