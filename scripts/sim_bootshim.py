#!/usr/bin/env python3
"""Run the UEFI BootShim under Unicorn and verify the FD handoff.

Usage:
  python3 scripts/sim_bootshim.py <BootShim.bin> <UEFI.fd>

BootShim is placed at LOAD_ADDR (0x40080000), copies UEFI_SIZE bytes from
right after itself to UEFI_BASE (0x50000000), then branches to UEFI_BASE.
The simulation stops at the PrePi entry encoded in the FD's branch stub.
"""
import struct
import sys
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_PROT_ALL
from unicorn.arm64_const import UC_ARM64_REG_PC

LOAD_ADDR = 0x40080000
UEFI_BASE = 0x50000000
UEFI_SIZE = 0x700000
MAP_SIZE = 0x1000000


def fd_entry(fd):
    word = struct.unpack_from("<I", fd, 0)[0]
    if word >> 26 != 0x5:
        raise SystemExit(f"FD base is not a B instruction: {word:#x}")
    imm = word & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return UEFI_BASE + imm * 4


def main():
    shim = Path(sys.argv[1]).read_bytes()
    fd = Path(sys.argv[2]).read_bytes()
    if len(fd) != UEFI_SIZE:
        raise SystemExit(f"FD size {len(fd):#x} != {UEFI_SIZE:#x}")
    entry = fd_entry(fd)

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x40000000, MAP_SIZE, UC_PROT_ALL)
    uc.mem_map(0xFE20F000, 0x200000, UC_PROT_ALL)
    uc.mem_map(UEFI_BASE, MAP_SIZE, UC_PROT_ALL)
    uc.mem_write(LOAD_ADDR, shim + fd)

    state = {"entered": False}

    def on_code(uc_, address, size, _):
        if address == UEFI_BASE and not state["entered"]:
            state["entered"] = True
            got = bytes(uc_.mem_read(UEFI_BASE, 8))
            want = fd[:8]
            if got != want:
                raise SystemExit(
                    f"FD copy mismatch at {UEFI_BASE:#x}: {got.hex()} != {want.hex()}"
                )
            print(f"copied FD to {UEFI_BASE:#x}: head={got.hex()}")
        if address == entry:
            print(f"reached PrePi entry {entry:#x}")
            uc_.emu_stop()

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.emu_start(LOAD_ADDR, entry, count=0x400000)

    pc = uc.reg_read(UC_ARM64_REG_PC)
    print(f"final PC={pc:#x}")
    if pc != entry:
        raise SystemExit("simulation did not reach PrePi entry")


if __name__ == "__main__":
    main()
