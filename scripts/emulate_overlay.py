#!/usr/bin/env python3
"""
Emulate LK's dtbo overlay call site (0xc3dc..0xc3f4) with the v3f hook.

Real LK bytes from dist/lk.img execute at the call site; the stock overlay
wrapper (0x72700) is intercepted so the test can force success/failure and
inspect the arguments the hook passes.

Cases:
  * normal boot (magic clear): hook must tail-call 0x72700 with the
    original base/size/overlay/out arguments;
  * RAWBOOT-UEFI with LK's base pointer 0x1000 past the FDT: hook must find
    the real FDT, overlay it, and leave the merged pointer in *out;
  * overlay failure: hook must copy the FDT into LK's original pointer slot
    (so the caller's free() stays valid), set *out, and return success;
  * no FDT in range: hook must skip the overlay and return success;
  * real dist/uefi.img: parse its v2 header, compute LK's (wrong) base
    pointer, and verify the hook recovers the embedded stock DTB.

Run: python3 scripts/emulate_overlay.py
"""
import struct
import sys
from pathlib import Path

from unicorn import (
    Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN,
    UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
    UC_HOOK_CODE,
)
from unicorn.arm64_const import (
    UC_ARM64_REG_PC, UC_ARM64_REG_LR, UC_ARM64_REG_SP,
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X26, UC_ARM64_REG_W0, UC_ARM64_REG_W1,
    UC_ARM64_REG_W3, UC_ARM64_REG_W27,
)

REPO = Path(__file__).resolve().parent.parent
PROJECT = REPO.parent
TOOL = PROJECT / "tools" / "lk-patcher-master"
sys.path.insert(0, str(TOOL))
from mtk_img import parse_part_headers  # noqa: E402

LK_IMG = REPO / "dist" / "lk.img"
UEFI_IMG = REPO / "dist" / "uefi.img"  # DTB right after the kernel, at LK's x26

RX_END = 0x0B1000
RW_END = 0x1000000
DL_BUF = 0x1000000
DL_SIZE = 0x200000
STACK = 0x2F00000
SENTINEL = 0x2E00000

CALL_SITE = 0xC3DC           # ldr x2,[sp,#160] ... bl overlay
CALL_RET = 0xC3F4            # cbz w0, 0xc448
OVERLAY = 0x72700
LPRINTF = 0x6B570
G_BOOT_INFO = 0xF2828
MAGIC_ADDR = 0xF3100  # vendor_boot copy +0x258 (not g_boot_info+0x668: that clobbered dtb_size)

OUT_SLOT = 0x90              # boot_linux_fdt sp+0x90
DTBO_PTR_SLOT = 0xA0
DTBO_SIZE_SLOT = 0x9C

MERGED_SENTINEL = 0x01ABCDE0


def load_symbols():
    syms = {}
    for line in (REPO / "build" / "payload.map").read_text().splitlines():
        p = line.split()
        if len(p) == 3:
            syms[p[2]] = int(p[0], 16)
    return syms


def load_lk_data():
    data = LK_IMG.read_bytes()
    for _idx, _off, data_off, _next, hdr in parse_part_headers(data):
        if hdr.name == "lk":
            return data[data_off:data_off + hdr.dsize]
    raise SystemExit("lk part not found in %s" % LK_IMG)


def read_cstr(uc, addr, n=128):
    try:
        raw = bytes(uc.mem_read(addr, n))
    except Exception:
        return ""
    return raw.split(b"\0")[0].decode("latin1", "replace")


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def align_up(v, a):
    return (v + a - 1) // a * a


def make_fdt(size, fill=0x41):
    blob = bytearray([fill]) * size
    blob[0:4] = b"\xd0\x0d\xfe\xed"
    struct.pack_into(">I", blob, 4, size)
    return bytes(blob)


class OverlaySim:
    def __init__(self, lk, syms):
        self.syms = syms
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
        self.uc.mem_map(0, RW_END, UC_PROT_ALL)
        self.uc.mem_map(DL_BUF, DL_SIZE, UC_PROT_ALL)
        self.uc.mem_map(SENTINEL, 0x200000, UC_PROT_ALL)
        self.uc.mem_write(0, lk)
        self.uc.mem_protect(0, RX_END, UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_protect(RX_END, RW_END - RX_END, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_protect(DL_BUF, DL_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_protect(SENTINEL, 0x200000, UC_PROT_READ | UC_PROT_WRITE)
        self.overlay_calls = []
        self.logs = []
        self.overlay_result = 0
        self._hook(LPRINTF, self._on_printf)
        self._hook(OVERLAY, self._on_overlay)

    def _hook(self, addr, cb):
        self.uc.hook_add(UC_HOOK_CODE, lambda uc, a, s, u: cb(uc), begin=addr, end=addr)

    def _ret(self):
        self.uc.reg_write(UC_ARM64_REG_PC, self.uc.reg_read(UC_ARM64_REG_LR))

    def _on_printf(self, uc):
        fmt = read_cstr(uc, uc.reg_read(UC_ARM64_REG_X0))
        self.logs.append(fmt)
        self._ret()

    def _on_overlay(self, uc):
        args = (
            uc.reg_read(UC_ARM64_REG_X0),
            uc.reg_read(UC_ARM64_REG_W1) & 0xFFFFFFFF,
            uc.reg_read(UC_ARM64_REG_X2),
            uc.reg_read(UC_ARM64_REG_W3) & 0xFFFFFFFF,
            uc.reg_read(UC_ARM64_REG_X4),
        )
        self.overlay_calls.append(args)
        if self.overlay_result == 0:
            uc.mem_write(args[4], struct.pack("<Q", MERGED_SENTINEL))
        uc.reg_write(UC_ARM64_REG_X0, self.overlay_result & 0xFFFFFFFF)
        self._ret()

    def set_magic(self, on):
        self.uc.mem_write(MAGIC_ADDR, self._magic_bytes if on else b"\0" * 16)

    def load_payload_magic(self):
        payload = (REPO / "build" / "payload.bin").read_bytes()
        off = self.syms["magic"] - self.syms["payload_base"]
        self._magic_bytes = payload[off:off + 16]

    def run_call_site(self, base, size, dtbo_ptr, dtbo_size):
        uc = self.uc
        uc.reg_write(UC_ARM64_REG_SP, STACK)
        uc.mem_write(STACK + OUT_SLOT, b"\0" * 8)
        uc.mem_write(STACK + DTBO_PTR_SLOT, struct.pack("<Q", dtbo_ptr))
        uc.mem_write(STACK + DTBO_SIZE_SLOT, struct.pack("<I", dtbo_size))
        uc.reg_write(UC_ARM64_REG_X26, base)
        uc.reg_write(UC_ARM64_REG_W27, size)
        uc.reg_write(UC_ARM64_REG_LR, SENTINEL)
        uc.emu_start(CALL_SITE, CALL_RET, count=200000)
        w0 = uc.reg_read(UC_ARM64_REG_W0) & 0xFFFFFFFF
        out = struct.unpack("<Q", bytes(uc.mem_read(STACK + OUT_SLOT, 8)))[0]
        return w0, out


def case_normal(sim):
    blob = make_fdt(0x1000)
    base = DL_BUF + 0x800
    sim.uc.mem_write(base, blob)
    sim.set_magic(False)
    sim.overlay_result = 0
    w0, out = sim.run_call_site(base, len(blob), DL_BUF + 0x7000, 0x300)
    assert w0 == 0, hex(w0)
    assert out == MERGED_SENTINEL, hex(out)
    assert len(sim.overlay_calls) == 1, sim.overlay_calls
    args = sim.overlay_calls[0]
    assert args[0] == base and args[1] == len(blob), args
    assert args[2] == DL_BUF + 0x7000 and args[3] == 0x300, args
    assert args[4] == STACK + OUT_SLOT, hex(args[4])
    print("normal boot: OK (stock wrapper called, args untouched)")


def case_magic_fix(sim):
    blob = make_fdt(0x2000)
    real = DL_BUF + 0x1800
    base = real + 0x1000           # LK's pointer, one page past the FDT
    sim.uc.mem_write(real, blob)
    sim.set_magic(True)
    sim.overlay_result = 0
    sim.overlay_calls.clear()
    sim.logs.clear()
    w0, out = sim.run_call_site(base, len(blob), DL_BUF + 0x8000, 0x400)
    assert len(sim.overlay_calls) == 1, sim.overlay_calls
    args = sim.overlay_calls[0]
    assert args[0] == real, (hex(args[0]), hex(real))
    assert args[1] == len(blob), args
    assert w0 == 0 and out == MERGED_SENTINEL, (hex(w0), hex(out))
    assert any("overlay base=0x" in s for s in sim.logs), sim.logs
    print("magic + bad base: OK (FDT found at -0x1000, stock overlay used)")


def case_overlay_fail(sim):
    blob = make_fdt(0x2000, fill=0x5A)
    real = DL_BUF + 0x1800
    base = real + 0x1000
    sim.uc.mem_write(real, blob)
    sim.set_magic(True)
    sim.overlay_result = -8
    sim.overlay_calls.clear()
    sim.logs.clear()
    w0, out = sim.run_call_site(base, len(blob), DL_BUF + 0x8000, 0x400)
    assert len(sim.overlay_calls) == 1, sim.overlay_calls
    assert w0 == 0, hex(w0)
    assert out == base, (hex(out), hex(base))
    copied = bytes(sim.uc.mem_read(base, len(blob)))
    assert copied == blob, "fallback copy mismatch"
    assert any("overlay failed" in s for s in sim.logs), sim.logs
    print("magic + overlay failure: OK (FDT copied to LK slot, boot continues)")


def case_no_fdt(sim):
    sim.set_magic(True)
    sim.overlay_calls.clear()
    sim.logs.clear()
    base = DL_BUF + 0x9000
    sim.uc.mem_write(base - 0x4000, b"\0" * 0x4000)
    w0, out = sim.run_call_site(base, 0x100, DL_BUF + 0x8000, 0x400)
    assert not sim.overlay_calls, sim.overlay_calls
    assert w0 == 0 and out == base, (hex(w0), hex(out))
    assert any("no fdt" in s for s in sim.logs), sim.logs
    print("magic + no FDT: OK (overlay skipped, caller pointer kept)")


def case_real_uefi(sim):
    if not UEFI_IMG.exists():
        print("real uefi.img: SKIP (file missing)")
        return
    img = UEFI_IMG.read_bytes()
    assert img[:8] == b"ANDROID!", img[:8]
    page = u32(img, 0x24)
    ksize = u32(img, 0x08)
    kaddr = u32(img, 0x0C)
    dtb_size = u32(img, 0x670)
    # Device evidence (v4 run): x26 = img + page + align(kernel), i.e. the
    # DTB starts right after the kernel.
    base_off = page + align_up(ksize, page)
    assert kaddr == 0x40000000, hex(kaddr)
    assert img[base_off:base_off + 4] == b"\xd0\x0d\xfe\xed", hex(base_off)
    assert struct.unpack_from(">I", img, base_off + 4)[0] == dtb_size
    sim.uc.mem_write(DL_BUF, img)
    sim.set_magic(True)
    sim.overlay_result = 0
    sim.overlay_calls.clear()
    sim.logs.clear()
    w0, out = sim.run_call_site(DL_BUF + base_off, dtb_size, DL_BUF + 0x8000, 0x3785F)
    assert len(sim.overlay_calls) == 1, sim.overlay_calls
    args = sim.overlay_calls[0]
    assert args[0] == DL_BUF + base_off, (hex(args[0]), hex(base_off))
    assert w0 == 0 and out == MERGED_SENTINEL, (hex(w0), hex(out))
    print("uefi.img: OK (kernel_addr=0x40000000, x26=DTB at 0x%x)" % base_off)


def main():
    # Regression guard: the old magic slot g_boot_info+0x668 clobbered the
    # v2 header dtb_size at +0x670 ("-BOO" = 0x4F4F422D), which made every
    # overlay fail with Bad fdt size.
    assert not (G_BOOT_INFO <= MAGIC_ADDR < G_BOOT_INFO + 0x67C), \
        "magic overlaps g_boot_info header fields"
    assert 0xF2EA8 <= MAGIC_ADDR < 0xF36F8, "magic should live in the vendor header copy"
    lk = load_lk_data()
    syms = load_symbols()
    sim = OverlaySim(lk, syms)
    sim.load_payload_magic()
    for case in (case_normal, case_magic_fix, case_overlay_fail, case_no_fdt,
                 case_real_uefi):
        case(sim)
    print("\nOVERLAY HOOK EMULATION PASSED")


if __name__ == "__main__":
    main()
