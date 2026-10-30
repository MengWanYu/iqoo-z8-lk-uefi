#!/usr/bin/env python3
"""End-to-end simulation of the actual RAWBOOT UEFI image (no ATF).

Executes the injected LK handler from build/payload.bin with the real
RAWBOOT image in the fastboot download buffer, models LK 0x1CA10's SMC
handoff by entering the payload at download_base+0x28, then runs BootShim
until the PrePi entry in the FD.

Usage:
  python3 scripts/sim_rawboot_uefi.py <rawboot.img> <UEFI.fd>
"""
import struct
import sys
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_PROT_ALL, UC_HOOK_CODE
from unicorn.arm64_const import (
    UC_ARM64_REG_PC, UC_ARM64_REG_LR, UC_ARM64_REG_SP,
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
)

REPO = Path(__file__).resolve().parent.parent
PAYLOAD = REPO / "build" / "payload.bin"
MAP = REPO / "build" / "payload.map"

BASE = 0x0
MEM_SIZE = 0x3000000
STACK = 0x2F00000
SENTINEL = 0x2E00000
DL_BUF = 0x1000000
FD_BASE = 0x50000000
FD_MAP_SIZE = 0x800000

FASTBOOT_REGISTER = 0x4BE8
LPRINTF = 0x6B570
CLEAN_CACHE = 0x3790
BOOT_JUMP = 0x1CA10
LK_MEMCPY = 0x6BEEC
VMM_GET_VA = 0x6849C
RAW_HEADER = 0x28
LOAD_PA = 0x40080000
LOAD_VA = 0xFFFF000040080000


def fd_entry(fd):
    word = struct.unpack_from("<I", fd, 0)[0]
    if word >> 26 != 0x5:
        raise SystemExit(f"FD base is not a B instruction: {word:#x}")
    imm = word & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return FD_BASE + imm * 4


def load_symbols():
    syms = {}
    for line in MAP.read_text().splitlines():
        p = line.split()
        if len(p) == 3:
            syms[p[2]] = int(p[0], 16)
    return syms


def wrap_boot_image(kernel, page=0x800):
    """Mirror platform-tools `fastboot boot <kernel>` (legacy boot image)."""
    hdr = bytearray(page)
    hdr[0:8] = b"ANDROID!"
    struct.pack_into("<I", hdr, 0x08, len(kernel))
    struct.pack_into("<I", hdr, 0x24, page)
    return bytes(hdr) + kernel


def main():
    argv = sys.argv[1:]
    raw_mode = "--raw" in argv
    if raw_mode:
        argv.remove("--raw")
    rawboot = Path(argv[0]).read_bytes()
    fd = Path(argv[1]).read_bytes()
    payload = PAYLOAD.read_bytes()
    syms = load_symbols()
    prepi_entry = fd_entry(fd)
    page = 0x800
    image = rawboot if raw_mode else wrap_boot_image(rawboot, page)

    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(BASE, MEM_SIZE, UC_PROT_ALL)
    uc.mem_map(FD_BASE, FD_MAP_SIZE, UC_PROT_ALL)
    uc.mem_map(0xFE20F000, 0x200000, UC_PROT_ALL)
    uc.mem_map(LOAD_PA, FD_MAP_SIZE, UC_PROT_ALL)
    uc.mem_map(LOAD_VA, FD_MAP_SIZE, UC_PROT_ALL)
    uc.mem_write(BASE + syms["payload_base"], payload)
    uc.mem_write(SENTINEL, struct.pack("<I", 0xD65F03C0))
    uc.mem_write(DL_BUF, image)

    state = {"boot_args": None}

    def hook_ret(uc_, address, size, _):
        uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))

    def hook_vmm_get_va(uc_, address, size, _):
        # Model "no LK mapping": fall back to the low identity VA.
        uc_.reg_write(UC_ARM64_REG_X0, 0)
        uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))

    def hook_memcpy(uc_, address, size, _):
        dst = uc_.reg_read(UC_ARM64_REG_X0)
        src = uc_.reg_read(UC_ARM64_REG_X1)
        n = uc_.reg_read(UC_ARM64_REG_X2)
        data = bytes(uc_.mem_read(src, n))
        uc_.mem_write(dst, data)
        if dst == LOAD_VA:
            # ATF jumps to the PA with MMU off; mirror it for this model.
            uc_.mem_write(LOAD_PA, data)
        uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))

    def hook_boot_jump(uc_, address, size, _):
        args = tuple(uc_.reg_read(r) for r in
                     (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                      UC_ARM64_REG_X3, UC_ARM64_REG_X4))
        state["boot_args"] = args
        # Model ATF eret to the payload entry with MMU/caches off.
        uc_.reg_write(UC_ARM64_REG_PC, args[2])

    for addr in (FASTBOOT_REGISTER, LPRINTF, CLEAN_CACHE):
        uc.hook_add(UC_HOOK_CODE, hook_ret, begin=addr, end=addr)
    uc.hook_add(UC_HOOK_CODE, hook_memcpy, begin=LK_MEMCPY, end=LK_MEMCPY)
    uc.hook_add(UC_HOOK_CODE, hook_vmm_get_va, begin=VMM_GET_VA, end=VMM_GET_VA)
    uc.hook_add(UC_HOOK_CODE, hook_boot_jump, begin=BOOT_JUMP, end=BOOT_JUMP)

    uc.reg_write(UC_ARM64_REG_SP, STACK)
    uc.reg_write(UC_ARM64_REG_LR, SENTINEL)
    uc.reg_write(UC_ARM64_REG_X1, DL_BUF)
    uc.reg_write(UC_ARM64_REG_X2, len(image))
    uc.reg_write(UC_ARM64_REG_PC, syms["boot_handler"])
    uc.emu_start(syms["boot_handler"], prepi_entry, count=4000000)

    args = state["boot_args"]
    assert args is not None, "boot_jump was not called"
    x0, x1, x2, x3, x4 = args
    assert x0 == 0xD0C8, hex(x0)          # LK_base=0 in this model
    assert x1 == 0xC2000115, hex(x1)
    load_pa = struct.unpack_from("<Q", rawboot, 8)[0]
    if load_pa:
        assert x2 == load_pa, hex(x2)
    else:
        entry_off = RAW_HEADER if raw_mode else page + RAW_HEADER
        assert x2 == DL_BUF + entry_off, hex(x2)
    assert x3 == 0 and x4 == 0, args
    print("mode=%s" % ("raw" if raw_mode else "wrapped boot.img page=0x800"))
    print("SMC handoff args: x0=0x%x x1=0x%x x2=0x%x x3=0x%x x4=0x%x" % args)

    copied = bytes(uc.mem_read(FD_BASE, 0x1000))
    assert copied == fd[:0x1000], "FD copy mismatch at 0x50000000"
    pc = uc.reg_read(UC_ARM64_REG_PC)
    assert pc == prepi_entry, hex(pc)
    print(f"FD copied to {FD_BASE:#x}; reached PrePi entry {prepi_entry:#x}")
    print("RAWBOOT UEFI SIMULATION PASSED")


if __name__ == "__main__":
    main()
