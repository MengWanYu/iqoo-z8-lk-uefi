#!/usr/bin/env python3
"""
Assembly-level LK smoke simulator with LK-like RX/RW permissions.

Why this exists
---------------
The first emulator mapped every page as read/write/execute, so it could not
catch the real-device failure: v1 put the payload at 0xcef90 (LK data tail)
and LK later fetched it with execute-never, giving:

    instruction abort: PC at 0xffff0000800cef90

This simulator models the observed LK mapping:

    [0x000000, 0x0b1000)  RX   (entry, vectors at 0x1000, code, rodata)
    [0x0b1000, 0x1000000) RW   (reloc table, data, BSS, 0xcef90 tail -> NX)
    [0x1000000, 0x1200000) RW  (fastboot download buffer)
    [0x2e00000, 0x3000000) RW  (stack + sentinel)

It then executes the **actual bytes from the produced image**:

  1. real LK registration function 0x8120 (patched tail 0x81d8 -> stub)
  2. the stub at 0x1880, wrapper at 0x18a8, handler at 0x18f8
  3. negative fixture reproducing v1: branch to 0xcef90 must raise
     UC_ERR_FETCH_PROT

Only LK service functions are intercepted; the payload itself is real code.

Run: python3 scripts/lk_sim.py
"""
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from unicorn import (
    Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN,
    UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
    UC_HOOK_CODE, UcError, UC_ERR_FETCH_PROT,
)
from unicorn.arm64_const import (
    UC_ARM64_REG_PC, UC_ARM64_REG_LR, UC_ARM64_REG_SP,
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X19,
    UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22,
    UC_ARM64_REG_W0, UC_ARM64_REG_W1, UC_ARM64_REG_W2, UC_ARM64_REG_W3,
)

REPO = Path(__file__).resolve().parent.parent
PROJECT = REPO.parent
TOOL = PROJECT / "tools" / "lk-patcher-master"
sys.path.insert(0, str(TOOL))
from mtk_img import parse_part_headers  # noqa: E402

OUT_IMG = REPO / "dist" / "lk.img"
PAYLOAD = REPO / "build" / "payload.bin"
PAYLOAD_MAP = REPO / "build" / "payload.map"

# LK-like memory model (evidence: v1 fault at 0xcef90, VBAR=0x1000)
RX_END = 0x0B1000
RW_END = 0x1000000
DL_BUF = 0x1000000
DL_SIZE = 0x200000
STACK = 0x2F00000
SENTINEL = 0x2E00000

REG_FN = 0x8120
FASTBOOT_REGISTER = 0x4BE8
STORAGE_LOADER = 0x51A04
LOAD_BOOTINFO = 0x9D00
SET_IMAGE = 0xA6EC
BOOT_FROM_STORAGE = 0xD0D4
LPRINTF = 0x6B570
CLEAN_CACHE = 0x3790
BOOT_JUMP = 0x1CA10
GET_VERSION = 0x9EE8
GET_KADDR = 0x9F94
GET_RADDR = 0xA240
GET_RSIZE = 0xA5F4
GET_DTB = 0xA68C

G_BOOT_INFO = 0xF2828
G_VENDOR_BASE = 0xF3710
G_BOOT_MODE = 0xF3718
MAGIC_ADDR = 0xF3100  # vendor_boot copy +0x258 (not g_boot_info+0x668: that clobbered dtb_size)


def load_symbols():
    syms = {}
    for line in PAYLOAD_MAP.read_text().splitlines():
        p = line.split()
        if len(p) == 3:
            syms[p[2]] = int(p[0], 16)
    return syms


def branch_word(src, dst, is_bl=False):
    off = (dst - src) >> 2
    op = 0x94000000 if is_bl else 0x14000000
    return op | (off & 0x03FFFFFF)


def load_lk_data():
    data = OUT_IMG.read_bytes()
    parts = parse_part_headers(data)
    for idx, off, data_off, next_off, hdr in parts:
        if hdr.name == "lk":
            return data[data_off:data_off + hdr.dsize], hdr.dsize
    raise SystemExit("lk part not found in %s" % OUT_IMG)


def read_cstr(uc, addr, n=128):
    try:
        raw = bytes(uc.mem_read(addr, n))
    except Exception:
        return ""
    return raw.split(b"\0")[0].decode("latin1", "replace")


class LkSim:
    def __init__(self, lk, payload):
        self.lk = lk
        self.payload = payload
        self.calls = []
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
        self.uc.mem_map(0, RW_END, UC_PROT_ALL)
        self.uc.mem_map(DL_BUF, DL_SIZE, UC_PROT_ALL)
        self.uc.mem_map(SENTINEL, 0x200000, UC_PROT_ALL)
        self.uc.mem_write(0, lk)
        # LK-like permissions: RX for text/rodata, RW for data/BSS/tail.
        self.uc.mem_protect(0, RX_END, UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_protect(RX_END, RW_END - RX_END, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_protect(DL_BUF, DL_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_protect(SENTINEL, 0x200000, UC_PROT_READ | UC_PROT_WRITE)
        self._install_hooks()

    def reset_regs(self):
        self.uc.reg_write(UC_ARM64_REG_SP, STACK)
        self.uc.reg_write(UC_ARM64_REG_LR, SENTINEL)

    @staticmethod
    def _reg(uc, reg, w=False):
        v = uc.reg_read(reg)
        return v & 0xFFFFFFFF if w else v

    @staticmethod
    def _set_x0(uc, v):
        uc.reg_write(UC_ARM64_REG_X0, v)

    @staticmethod
    def _ret(uc):
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    def _hook(self, addr, name):
        def cb(uc, address, size, user_data):
            if name == "fastboot_register":
                self.calls.append(("fastboot_register",
                                   self._reg(uc, UC_ARM64_REG_X0),
                                   self._reg(uc, UC_ARM64_REG_X1),
                                   self._reg(uc, UC_ARM64_REG_W2, True),
                                   self._reg(uc, UC_ARM64_REG_W3, True)))
                self._ret(uc)
            elif name == "printf":
                fmt = read_cstr(uc, self._reg(uc, UC_ARM64_REG_X0))
                args = [self._reg(uc, r) for r in (
                    UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                    UC_ARM64_REG_X4, UC_ARM64_REG_X5)]
                self.calls.append(("printf", fmt, args))
                self._ret(uc)
            elif name == "storage_loader":
                self.calls.append(("storage_loader", self._reg(uc, UC_ARM64_REG_W0, True)))
                self._set_x0(uc, 0)
                self._ret(uc)
            elif name == "load_bootinfo":
                self.calls.append(("load_bootinfo", self._reg(uc, UC_ARM64_REG_X0)))
                self._set_x0(uc, 0)
                self._ret(uc)
            elif name == "set_image":
                self.calls.append(("set_image", self._reg(uc, UC_ARM64_REG_X0),
                                   self._reg(uc, UC_ARM64_REG_X1)))
                self._ret(uc)
            elif name == "get_version":
                self._set_x0(uc, 4)
                self._ret(uc)
            elif name == "get_kaddr":
                self._set_x0(uc, 0x40080000)
                self._ret(uc)
            elif name == "get_raddr":
                self._set_x0(uc, 0x50000000)
                self._ret(uc)
            elif name == "get_rsize":
                self._set_x0(uc, 0x2000)
                self._ret(uc)
            elif name == "get_dtb":
                self._set_x0(uc, 0x48000000)
                self._ret(uc)
            elif name == "boot_from_storage":
                self.calls.append(("boot_from_storage", self._reg(uc, UC_ARM64_REG_X0)))
                self._set_x0(uc, 0)
                self._ret(uc)
            elif name == "clean_cache":
                self.calls.append(("clean_cache", self._reg(uc, UC_ARM64_REG_X0),
                                   self._reg(uc, UC_ARM64_REG_X1)))
                self._ret(uc)
            elif name == "boot_jump":
                self.calls.append(("boot_jump", self._reg(uc, UC_ARM64_REG_X0),
                                   self._reg(uc, UC_ARM64_REG_X1),
                                   self._reg(uc, UC_ARM64_REG_X2),
                                   self._reg(uc, UC_ARM64_REG_X3),
                                   self._reg(uc, UC_ARM64_REG_X4)))
                # LK's final boot path does not return on success.
                uc.reg_write(UC_ARM64_REG_PC, SENTINEL)
        self.uc.hook_add(UC_HOOK_CODE, cb, begin=addr, end=addr)

    def _install_hooks(self):
        self._hook(FASTBOOT_REGISTER, "fastboot_register")
        self._hook(LPRINTF, "printf")
        self._hook(STORAGE_LOADER, "storage_loader")
        self._hook(LOAD_BOOTINFO, "load_bootinfo")
        self._hook(SET_IMAGE, "set_image")
        self._hook(GET_VERSION, "get_version")
        self._hook(GET_KADDR, "get_kaddr")
        self._hook(GET_RADDR, "get_raddr")
        self._hook(GET_RSIZE, "get_rsize")
        self._hook(GET_DTB, "get_dtb")
        self._hook(BOOT_FROM_STORAGE, "boot_from_storage")
        self._hook(CLEAN_CACHE, "clean_cache")
        self._hook(BOOT_JUMP, "boot_jump")

    def run(self, start, until=SENTINEL):
        self.calls.clear()
        self.reset_regs()
        self.uc.reg_write(UC_ARM64_REG_PC, start)
        self.uc.emu_start(start, until, count=500000)


def check_disassembly(lk, syms):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    base = syms["payload_base"]
    end = base + len(PAYLOAD.read_bytes())
    assert end <= RX_END, "payload is outside modeled RX range"
    print("payload RX range: 0x%x..0x%x (model RX end 0x%x)" % (base, end, RX_END))
    first = list(md.disasm(lk[base:base + 24], base))
    print("payload entry:", " | ".join("%s %s" % (i.mnemonic, i.op_str) for i in first[:4]))
    # static branch/patch checks
    w = struct.unpack_from("<I", lk, 0x81D8)[0]
    imm = w & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    assert (0x81D8 + imm * 4) == base, "0x81d8 branch target mismatch"
    for off in (0xD12C, 0xD15C):
        w = struct.unpack_from("<I", lk, off)[0]
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        assert (off + imm * 4) == syms["load_wrapper"], "loader wrapper target mismatch"
    w = struct.unpack_from("<I", lk, 0xC3F0)[0]
    imm = w & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    assert (0xC3F0 + imm * 4) == syms["overlay_hook"], "overlay hook target mismatch"
    w = struct.unpack_from("<I", lk, 0xCB7C)[0]
    imm = w & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    assert (0xCB7C + imm * 4) == syms["bootconfig_hook"], "bootconfig hook target mismatch"
    assert lk[0x1880:0x1880 + len(PAYLOAD.read_bytes())].count(0) != len(PAYLOAD.read_bytes())
    print("patch/branch static checks: OK")


def main():
    lk, dsize = load_lk_data()
    payload = PAYLOAD.read_bytes()
    syms = load_symbols()
    assert len(lk) == dsize
    print("lk data: 0x%x bytes; output: %s" % (dsize, OUT_IMG))
    check_disassembly(lk, syms)

    sim = LkSim(lk, payload)

    # ---- 1. positive: real 0x8120 -> patched 0x81d8 -> payload stub ----
    sim.run(REG_FN)
    regs = [c for c in sim.calls if c[0] == "fastboot_register"]
    assert len(regs) == 7, regs
    assert regs[0][1:] == (0x8734C, 0x81DC, 1, 0), regs[0]   # download:
    assert regs[5][1:] == (0x87361, 0x89D4, 1, 1), regs[5]   # ultraflash:
    assert regs[6][0] == "fastboot_register"
    assert regs[6][1] == syms["boot_cmd"], regs[6]
    assert regs[6][2] == syms["boot_handler"], regs[6]
    assert regs[6][3:] == (1, 0), regs[6]
    assert read_cstr(sim.uc, regs[6][1]) == "boot"
    print("positive registration: OK, 7 commands, boot handler 0x%x" % regs[6][2])

    # ---- 2. negative v1: branch to 0xcef90, in the RW/NX data region ----
    lk_v1 = bytearray(lk)
    struct.pack_into("<I", lk_v1, 0x81D8, branch_word(0x81D8, 0xCEF90, False))
    sim_v1 = LkSim(bytes(lk_v1), payload)
    # write payload at the old tail; 0xcef90 is in RW, so write is allowed
    sim_v1.uc.mem_write(0xCEF90, payload)
    fault = None
    try:
        sim_v1.run(REG_FN)
    except UcError as e:
        fault = e
    assert fault is not None, "negative v1 did not fault (NX emulation broken)"
    assert fault.errno == UC_ERR_FETCH_PROT, (fault.errno, fault)
    pc = sim_v1.uc.reg_read(UC_ARM64_REG_PC)
    print("negative v1: OK, UC_ERR_FETCH_PROT at PC 0x%x (matches expdb 0x…cef90)" % pc)
    assert 0xCEF90 <= pc < 0xCF000, hex(pc)

    # ---- 3. wrapper: normal boot always tail-calls the storage loader ----
    sim.calls.clear()
    sim.reset_regs()
    sim.run(syms["load_wrapper"])
    assert any(c[0] == "storage_loader" for c in sim.calls), sim.calls
    print("wrapper RX/RW: OK (tail-call storage loader)")

    # ---- 4. handler: RAWBOOT header -> clean cache -> SMC handoff ----
    sim.calls.clear()
    sim.reset_regs()
    body = bytes(0x200)
    hdr = bytearray(0x28)
    hdr[0:8] = b"RAWBOOT!"
    struct.pack_into("<QQQQ", hdr, 8, 0, 0, 0x12340000, len(body))
    sim.uc.mem_write(DL_BUF, bytes(hdr) + body)
    sim.uc.reg_write(UC_ARM64_REG_X1, DL_BUF)
    sim.uc.reg_write(UC_ARM64_REG_X2, len(hdr) + len(body))
    sim.run(syms["boot_handler"])

    names = [c[0] for c in sim.calls]
    cc = [c for c in sim.calls if c[0] == "clean_cache"]
    assert len(cc) == 1 and cc[0][1:] == (DL_BUF, len(hdr) + len(body)), cc
    bj = [c for c in sim.calls if c[0] == "boot_jump"]
    assert len(bj) == 1, bj
    assert bj[0][1] == 0xD0C8, hex(bj[0][1])   # LK_base=0 in this model
    assert bj[0][2] == 0xC2000115, hex(bj[0][2])
    assert bj[0][3] == DL_BUF + len(hdr), hex(bj[0][3])
    assert bj[0][4] == 0x12340000, hex(bj[0][4])
    assert bj[0][5] == 0, bj[0][5]
    logs = [c for c in sim.calls if c[0] == "printf"]
    assert any("kaeru-rawboot: payload=" in c[1] for c in logs), logs
    print("handler RX/RW: OK, calls=%s" % names)
    print("handler logs:", [c[1].strip() for c in logs])

    # ---- 5. handler: platform-tools wrapped boot.img (ANDROID!, page 0x800) ----
    sim.calls.clear()
    sim.reset_regs()
    page = 0x800
    body = bytes(0x200)
    rawhdr = bytearray(0x28)
    rawhdr[0:8] = b"RAWBOOT!"
    struct.pack_into("<QQQQ", rawhdr, 8, 0, 0, 0x12340000, len(body))
    raw = bytes(rawhdr) + body
    boot = bytearray(page)
    boot[0:8] = b"ANDROID!"
    struct.pack_into("<I", boot, 0x08, len(raw))
    struct.pack_into("<I", boot, 0x24, page)
    wrapped = bytes(boot) + raw
    sim.uc.mem_write(DL_BUF, wrapped)
    sim.uc.reg_write(UC_ARM64_REG_X1, DL_BUF)
    sim.uc.reg_write(UC_ARM64_REG_X2, len(wrapped))
    sim.run(syms["boot_handler"])

    cc = [c for c in sim.calls if c[0] == "clean_cache"]
    assert len(cc) == 1 and cc[0][1:] == (DL_BUF + page, len(raw)), cc
    bj = [c for c in sim.calls if c[0] == "boot_jump"]
    assert len(bj) == 1, bj
    assert bj[0][3] == DL_BUF + page + 0x28, hex(bj[0][3])
    assert bj[0][4] == 0x12340000, hex(bj[0][4])
    logs = [c for c in sim.calls if c[0] == "printf"]
    assert any("host boot.img page=0x%x" in c[1] and c[2][0] == 0x800 for c in logs), logs
    print("handler(wrapped): OK, entry=0x%x" % bj[0][3])

    print("\nASSEMBLY-LEVEL LK SMOKE TEST PASSED (RX/RW enforced; v1 NX caught)")


if __name__ == "__main__":
    main()
