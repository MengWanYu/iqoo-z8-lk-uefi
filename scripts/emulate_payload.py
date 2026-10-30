#!/usr/bin/env python3
"""
Emulate the injected AArch64 RAWBOOT payload with Unicorn.

LK functions are intercepted; their arguments are checked:

  * stub: displaced "ultraflash:" registration, then "boot" (flags 1,0);
  * load_wrapper: always tail-calls the stock storage image loader (normal
    boot is unaffected);
  * boot_handler: validates the RAWBOOT header, cleans the download range,
    and calls LK 0x1CA10 with the SMC 0xC2000115 handoff arguments
    (x0=SMC stub VA, x1=SIP, x2=entry PA, x3=DTB, x4=0).

Run: python3 scripts/emulate_payload.py
"""
import struct
import sys
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_PROT_ALL, UC_HOOK_CODE
from unicorn.arm64_const import (
    UC_ARM64_REG_PC, UC_ARM64_REG_LR, UC_ARM64_REG_SP,
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_W0,
    UC_ARM64_REG_W2, UC_ARM64_REG_W3,
)

REPO = Path(__file__).resolve().parent.parent
PAYLOAD = REPO / "build" / "payload.bin"
MAP = REPO / "build" / "payload.map"

BASE = 0x0
MEM_SIZE = 0x3000000
STACK = 0x2F00000
SENTINEL = 0x2E00000
DL_BUF = 0x1000000
DL_SIZE = 0x2000

FASTBOOT_REGISTER = 0x4BE8
LPRINTF = 0x6B570
STORAGE_LOADER = 0x51A04
CLEAN_CACHE = 0x3790
BOOT_JUMP = 0x1CA10
LK_MEMCPY = 0x6BEEC
VMM_GET_VA = 0x6849C
LOAD_BOOTINFO = 0x9D00
SET_IMAGE = 0xA6EC
BOOT_FROM_STORAGE = 0xD0D4
BOOTCONFIG_APPEND = 0xADD4
G_BOOT_INFO = 0xF2828
G_BOOT_MODE = 0xF3718
MAGIC_ADDR = 0xF3100  # vendor_boot copy +0x258 (not g_boot_info+0x668: that clobbered dtb_size)

RAW_MAGIC = b"RAWBOOT!"
SMC_STUB_OFF = 0xD0C8
SIP_KERNEL_BOOT = 0xC2000115


def load_symbols():
    syms = {}
    for line in MAP.read_text().splitlines():
        p = line.split()
        if len(p) == 3:
            syms[p[2]] = int(p[0], 16)
    return syms


def rdstr(uc, addr, n=128):
    try:
        data = bytes(uc.mem_read(addr, n))
    except Exception:
        return ""
    return data.split(b"\0")[0].decode("latin1", "replace")


class Emu:
    def __init__(self, payload, syms):
        self.payload = payload
        self.syms = syms
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
        self.uc.mem_map(BASE, MEM_SIZE, UC_PROT_ALL)
        self.uc.mem_write(BASE + syms["payload_base"], payload)
        self.uc.mem_write(SENTINEL, struct.pack("<I", 0xD65F03C0))
        self.calls = []
        self.vmm_va = 0
        self._install_hooks()

    def _hook(self, addr, name):
        def cb(uc, address, size, user_data):
            if name == "fastboot_register":
                self.calls.append(("fastboot_register",
                                   uc.reg_read(UC_ARM64_REG_X0),
                                   uc.reg_read(UC_ARM64_REG_X1),
                                   uc.reg_read(UC_ARM64_REG_W2) & 0xFFFFFFFF,
                                   uc.reg_read(UC_ARM64_REG_W3) & 0xFFFFFFFF))
                self._ret(uc)
            elif name == "printf":
                fmt = rdstr(uc, uc.reg_read(UC_ARM64_REG_X0))
                args = [uc.reg_read(reg) for reg in (UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                                     UC_ARM64_REG_X3, UC_ARM64_REG_X4,
                                                     UC_ARM64_REG_X5)]
                self.calls.append(("printf", fmt, args))
                self._ret(uc)
            elif name == "storage_loader":
                self.calls.append(("storage_loader", uc.reg_read(UC_ARM64_REG_W0) & 0xFFFFFFFF))
                self._set_x0(uc, 0)
                self._ret(uc)
            elif name == "clean_cache":
                self.calls.append(("clean_cache", uc.reg_read(UC_ARM64_REG_X0),
                                   uc.reg_read(UC_ARM64_REG_X1)))
                self._ret(uc)
            elif name == "lk_memcpy":
                dst = uc.reg_read(UC_ARM64_REG_X0)
                src = uc.reg_read(UC_ARM64_REG_X1)
                size = uc.reg_read(UC_ARM64_REG_X2)
                self.calls.append(("lk_memcpy", dst, src, size))
                uc.mem_write(dst, bytes(uc.mem_read(src, size)))
                self._ret(uc)
            elif name == "vmm_get_va":
                self.calls.append(("vmm_get_va", uc.reg_read(UC_ARM64_REG_X0), self.vmm_va))
                self._set_x0(uc, self.vmm_va)
                self._ret(uc)
            elif name == "load_bootinfo":
                self.calls.append(("load_bootinfo", uc.reg_read(UC_ARM64_REG_X0)))
                self._set_x0(uc, 0)
                self._ret(uc)
            elif name == "set_image":
                self.calls.append(("set_image", uc.reg_read(UC_ARM64_REG_X0),
                                   uc.reg_read(UC_ARM64_REG_X1)))
                self._ret(uc)
            elif name == "boot_from_storage":
                magic = bytes(uc.mem_read(MAGIC_ADDR, 16))
                mode = bytes(uc.mem_read(G_BOOT_MODE, 1))[0]
                self.calls.append(("boot_from_storage", magic, mode))
                self._set_x0(uc, 0)
                self._ret(uc)
            elif name == "bootconfig":
                self.calls.append(("bootconfig", uc.reg_read(UC_ARM64_REG_X0),
                                   uc.reg_read(UC_ARM64_REG_X1)))
                self._set_x0(uc, 0x188)
                self._ret(uc)
            elif name == "boot_jump":
                self.calls.append(("boot_jump",
                                   uc.reg_read(UC_ARM64_REG_X0),
                                   uc.reg_read(UC_ARM64_REG_X1),
                                   uc.reg_read(UC_ARM64_REG_X2),
                                   uc.reg_read(UC_ARM64_REG_X3),
                                   uc.reg_read(UC_ARM64_REG_X4)))
                # LK's final boot path does not return on success.
                uc.reg_write(UC_ARM64_REG_PC, SENTINEL)
        self.uc.hook_add(UC_HOOK_CODE, cb, begin=addr, end=addr)

    @staticmethod
    def _set_x0(uc, val):
        uc.reg_write(UC_ARM64_REG_X0, val)

    @staticmethod
    def _ret(uc):
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    def _install_hooks(self):
        self._hook(FASTBOOT_REGISTER, "fastboot_register")
        self._hook(LPRINTF, "printf")
        self._hook(STORAGE_LOADER, "storage_loader")
        self._hook(CLEAN_CACHE, "clean_cache")
        self._hook(BOOT_JUMP, "boot_jump")
        self._hook(LK_MEMCPY, "lk_memcpy")
        self._hook(VMM_GET_VA, "vmm_get_va")
        self._hook(LOAD_BOOTINFO, "load_bootinfo")
        self._hook(SET_IMAGE, "set_image")
        self._hook(BOOT_FROM_STORAGE, "boot_from_storage")
        self._hook(BOOTCONFIG_APPEND, "bootconfig")

    def reset(self):
        self.calls.clear()
        self.uc.reg_write(UC_ARM64_REG_SP, STACK)
        self.uc.reg_write(UC_ARM64_REG_LR, SENTINEL)

    def run(self, start):
        self.uc.reg_write(UC_ARM64_REG_PC, BASE + start)
        try:
            self.uc.emu_start(BASE + start, SENTINEL, count=200000)
        except Exception as e:
            raise SystemExit("emulation fault at PC=0x%x: %s" %
                             (self.uc.reg_read(UC_ARM64_REG_PC), e))


def make_header(payload_size, dtb=0, magic=RAW_MAGIC):
    hdr = bytearray(0x28)
    hdr[0:8] = magic
    struct.pack_into("<QQQQ", hdr, 8, 0, 0, dtb, payload_size)
    return bytes(hdr)


def main():
    payload = PAYLOAD.read_bytes()
    syms = load_symbols()
    emu = Emu(payload, syms)
    lk_base = syms["payload_base"] - 0x1880

    # ---- stub test ----
    emu.reset()
    emu.uc.reg_write(UC_ARM64_REG_X0, 0x87361)
    emu.uc.reg_write(UC_ARM64_REG_X1, 0x89D4)
    emu.uc.reg_write(UC_ARM64_REG_W2, 1)
    emu.uc.reg_write(UC_ARM64_REG_W3, 1)
    emu.run(syms["stub"])
    regs = [c for c in emu.calls if c[0] == "fastboot_register"]
    assert len(regs) == 2, regs
    assert regs[0][1:] == (0x87361, 0x89D4, 1, 1), regs[0]
    assert regs[1][1] == syms["boot_cmd"], (hex(regs[1][1]), hex(syms["boot_cmd"]))
    assert regs[1][2] == syms["boot_handler"], regs[1]
    assert regs[1][3:] == (1, 0), regs[1]
    assert rdstr(emu.uc, regs[1][1]) == "boot"
    print("stub: OK, registrations:", regs)

    # ---- wrapper: no magic -> storage loader; magic -> skip ----
    emu.reset()
    emu.uc.mem_write(MAGIC_ADDR, b"\0" * 16)
    emu.run(syms["load_wrapper"])
    assert any(c[0] == "storage_loader" for c in emu.calls), emu.calls
    emu.reset()
    magic16 = payload[syms["magic"] - syms["payload_base"]:syms["magic"] - syms["payload_base"] + 16]
    emu.uc.mem_write(MAGIC_ADDR, magic16)
    emu.run(syms["load_wrapper"])
    assert not any(c[0] == "storage_loader" for c in emu.calls), emu.calls
    assert any(c[0] == "printf" and "skip storage loader" in c[1] for c in emu.calls)
    print("wrapper: OK, magic skips storage loader")

    # ---- handler: valid RAWBOOT header ----
    emu.reset()
    body = bytes(0x200)
    hdr = make_header(len(body), dtb=0x12340000)
    emu.uc.mem_write(DL_BUF, hdr + body)
    emu.uc.reg_write(UC_ARM64_REG_X1, DL_BUF)
    emu.uc.reg_write(UC_ARM64_REG_X2, len(hdr) + len(body))
    emu.run(syms["boot_handler"])

    names = [c[0] for c in emu.calls]
    assert "clean_cache" in names, names
    cc = [c for c in emu.calls if c[0] == "clean_cache"][0]
    assert cc[1:] == (DL_BUF, len(hdr) + len(body)), cc
    bj = [c for c in emu.calls if c[0] == "boot_jump"]
    assert len(bj) == 1, bj
    assert bj[0][1] == lk_base + SMC_STUB_OFF, (hex(bj[0][1]), hex(lk_base + SMC_STUB_OFF))
    assert bj[0][2] == SIP_KERNEL_BOOT, hex(bj[0][2])
    assert bj[0][3] == DL_BUF + len(hdr), hex(bj[0][3])
    assert bj[0][4] == 0x12340000, hex(bj[0][4])
    assert bj[0][5] == 0, bj[0][5]
    logs = [c for c in emu.calls if c[0] == "printf"]
    assert any("kaeru-rawboot: payload=" in c[1] for c in logs), logs
    print("handler: OK, boot_jump args:", [hex(x) for x in bj[0][1:]])

    # ---- handler: platform-tools wrapped boot.img (ANDROID!, page 0x800) ----
    emu.reset()
    page = 0x800
    body = bytes(0x200)
    raw = make_header(len(body), dtb=0x12340000) + body
    boot = bytearray(page)
    boot[0:8] = b"ANDROID!"
    struct.pack_into("<I", boot, 0x08, len(raw))
    struct.pack_into("<I", boot, 0x24, page)
    wrapped = bytes(boot) + raw
    emu.uc.mem_write(DL_BUF, wrapped)
    emu.uc.reg_write(UC_ARM64_REG_X1, DL_BUF)
    emu.uc.reg_write(UC_ARM64_REG_X2, len(wrapped))
    emu.run(syms["boot_handler"])
    logs = [c for c in emu.calls if c[0] == "printf"]
    assert any("host boot.img page=0x%x" in c[1] and c[2][0] == 0x800 for c in logs), logs
    bj = [c for c in emu.calls if c[0] == "boot_jump"]
    assert len(bj) == 1, bj
    assert bj[0][3] == DL_BUF + page + 0x28, hex(bj[0][3])
    assert bj[0][4] == 0x12340000, hex(bj[0][4])
    cc = [c for c in emu.calls if c[0] == "clean_cache"][0]
    assert cc[1] == DL_BUF + page, hex(cc[1])
    assert cc[2] == len(raw), hex(cc[2])
    print("handler(wrapped boot.img): OK, entry=0x%x" % bj[0][3])

    # ---- handler: our v2 boot image (name RAWBOOT-UEFI) ----
    emu.reset()
    page = 0x800
    boot = bytearray(page)
    boot[0:8] = b"ANDROID!"
    boot[0x30:0x3C] = b"RAWBOOT-UEFI\0\0\0"
    struct.pack_into("<I", boot, 0x08, 0x100)
    struct.pack_into("<I", boot, 0x24, page)
    struct.pack_into("<I", boot, 0x28, 2)
    emu.uc.mem_write(DL_BUF, bytes(boot) + bytes(0x100))
    emu.uc.mem_write(MAGIC_ADDR, b"\0" * 16)
    emu.uc.reg_write(UC_ARM64_REG_X1, DL_BUF)
    emu.uc.reg_write(UC_ARM64_REG_X2, page + 0x100)
    emu.run(syms["boot_handler"])
    names = [c[0] for c in emu.calls]
    assert "load_bootinfo" in names, names
    assert any(c[0] == "load_bootinfo" and c[1] == DL_BUF for c in emu.calls)
    assert any(c[0] == "set_image" and c[1] == DL_BUF and c[2] == 0 for c in emu.calls)
    bfs = [c for c in emu.calls if c[0] == "boot_from_storage"]
    assert len(bfs) == 1, bfs
    assert bfs[0][1] == magic16, bfs[0]
    assert bfs[0][2] == 0, bfs[0][2]
    assert bytes(emu.uc.mem_read(MAGIC_ADDR, 16)) == b"\0" * 16
    logs = [c for c in emu.calls if c[0] == "printf"]
    assert any("bootimg -> boot_linux_from_storage" in c[1] for c in logs), logs
    assert any("returned" in c[1] for c in logs), logs
    print("handler(v2 bootimg): OK")

    # ---- bootconfig hook: magic off -> stock appender; magic on -> skip ----
    emu.reset()
    emu.uc.mem_write(MAGIC_ADDR, b"\0" * 16)
    emu.uc.reg_write(UC_ARM64_REG_X0, 0x11110000)
    emu.uc.reg_write(UC_ARM64_REG_X1, 0x22220000)
    emu.run(syms["bootconfig_hook"])
    bc = [c for c in emu.calls if c[0] == "bootconfig"]
    assert len(bc) == 1 and bc[0][1:] == (0x11110000, 0x22220000), bc
    emu.reset()
    emu.uc.mem_write(MAGIC_ADDR, magic16)
    emu.uc.reg_write(UC_ARM64_REG_X0, 0x11110000)
    emu.uc.reg_write(UC_ARM64_REG_X1, 0x22220000)
    emu.run(syms["bootconfig_hook"])
    assert not [c for c in emu.calls if c[0] == "bootconfig"], emu.calls
    assert (emu.uc.reg_read(UC_ARM64_REG_W0) & 0xFFFFFFFF) == 0, emu.calls
    logs = [c for c in emu.calls if c[0] == "printf"]
    assert any("bootconfig skipped" in c[1] for c in logs), logs
    print("bootconfig hook: OK (normal passes through, magic skips)")

    # ---- handler: load_addr=0x40080000, vmm_get_va=0 -> low identity ----
    emu.reset()
    emu.vmm_va = 0
    emu.uc.mem_map(0x40080000, 0x1000, UC_PROT_ALL)
    body = bytes([0xAA]) * 0x200
    hdr = bytearray(0x28)
    hdr[0:8] = b"RAWBOOT!"
    struct.pack_into("<QQQQ", hdr, 8, 0x40080000, 0, 0x12340000, len(body))
    emu.uc.mem_write(DL_BUF, bytes(hdr) + body)
    emu.uc.reg_write(UC_ARM64_REG_X1, DL_BUF)
    emu.uc.reg_write(UC_ARM64_REG_X2, len(hdr) + len(body))
    emu.run(syms["boot_handler"])
    mc = [c for c in emu.calls if c[0] == "lk_memcpy"]
    assert len(mc) == 1 and mc[0][1] == 0x40080000, mc
    assert mc[0][2] == DL_BUF + 0x28, hex(mc[0][2])
    assert mc[0][3] == len(body), hex(mc[0][3])
    assert bytes(emu.uc.mem_read(0x40080000, len(body))) == body
    bj = [c for c in emu.calls if c[0] == "boot_jump"]
    assert len(bj) == 1 and bj[0][3] == 0x40080000, bj
    assert bj[0][4] == 0x12340000, hex(bj[0][4])
    cc = [c for c in emu.calls if c[0] == "clean_cache"][0]
    assert cc[1] == 0x40080000 and cc[2] == len(body), cc
    assert any(c[0] == "vmm_get_va" for c in emu.calls)
    logs = [c for c in emu.calls if c[0] == "printf"]
    assert any("copy payload pa=0x%x" in c[1] for c in logs), logs
    print("handler(copy low identity): OK")

    # ---- handler: vmm_get_va returns a high VA ----
    emu.reset()
    emu.vmm_va = 0xFFFF000040080000
    emu.uc.mem_map(0xFFFF000040080000, 0x1000, UC_PROT_ALL)
    emu.uc.mem_write(DL_BUF, bytes(hdr) + body)
    emu.uc.reg_write(UC_ARM64_REG_X1, DL_BUF)
    emu.uc.reg_write(UC_ARM64_REG_X2, len(hdr) + len(body))
    emu.run(syms["boot_handler"])
    mc = [c for c in emu.calls if c[0] == "lk_memcpy"]
    assert len(mc) == 1 and mc[0][1] == 0xFFFF000040080000, mc
    bj = [c for c in emu.calls if c[0] == "boot_jump"]
    assert len(bj) == 1 and bj[0][3] == 0x40080000, bj
    cc = [c for c in emu.calls if c[0] == "clean_cache"][0]
    assert cc[1] == 0xFFFF000040080000, cc
    print("handler(copy via vmm VA): OK")

    # ---- handler: bad magic ----
    emu.reset()
    bad = make_header(0x100, magic=b"NOTRAW!!")
    emu.uc.mem_write(DL_BUF, bad + bytes(0x100))
    emu.uc.reg_write(UC_ARM64_REG_X1, DL_BUF)
    emu.uc.reg_write(UC_ARM64_REG_X2, len(bad) + 0x100)
    emu.run(syms["boot_handler"])
    logs = [c for c in emu.calls if c[0] == "printf"]
    assert any("bad magic" in c[1] for c in logs), logs
    assert not any(c[0] == "boot_jump" for c in emu.calls)
    print("handler(bad magic): OK, returned without jump")

    # ---- handler: payload larger than download ----
    emu.reset()
    hdr = make_header(0x400)
    emu.uc.mem_write(DL_BUF, hdr + bytes(0x100))
    emu.uc.reg_write(UC_ARM64_REG_X1, DL_BUF)
    emu.uc.reg_write(UC_ARM64_REG_X2, len(hdr) + 0x100)
    emu.run(syms["boot_handler"])
    logs = [c for c in emu.calls if c[0] == "printf"]
    assert any("bad size" in c[1] for c in logs), logs
    assert not any(c[0] == "boot_jump" for c in emu.calls)
    print("handler(bad size): OK, returned without jump")

    print("\nALL RAWBOOT EMULATION CHECKS PASSED")


if __name__ == "__main__":
    main()
