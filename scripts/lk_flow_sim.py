#!/usr/bin/env python3
"""
LK runtime smoke simulator.

Part 1 (real LK code, Unicorn):
    Execute the patched registration function at LK offset 0x8120 from the
    produced 16MB image.  fastboot_register (0x4be8) is intercepted; the
    actual stub at 0x81d8 -> payload 0x1880 is executed.  This validates the
    real LK registration flow and the displaced "ultraflash:" call.

Part 2 (dispatcher model):
    Rebuild the command list with the real node layout/flags and apply the
    dispatcher gating decoded from 0xd? (w2 = allowed_when_security_on,
    w3 = forbidden_when_lock_on, vivo state 1=locked / 3=unlocked).

Part 3 (RAWBOOT model):
    Check that `boot` is reachable in locked+secured fastboot and that the
    in-place RAWBOOT payload (magic/size/entry=base+0x28) is well formed.

Run: python3 scripts/lk_flow_sim.py
"""
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_PROT_ALL, UC_HOOK_CODE
from unicorn.arm64_const import (
    UC_ARM64_REG_PC, UC_ARM64_REG_LR, UC_ARM64_REG_SP,
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_W2, UC_ARM64_REG_W3,
)

REPO = Path(__file__).resolve().parent.parent
PROJECT = REPO.parent
TOOL = PROJECT / "tools" / "lk-patcher-master"
sys.path.insert(0, str(TOOL))
from mtk_img import parse_part_headers  # noqa: E402

OUT_IMG = REPO / "dist" / "lk.img"

BASE = 0x0
MEM_SIZE = 0x3000000
STACK = 0x2F00000
SENTINEL = 0x2E00000
REG_FN = 0x8120
FASTBOOT_REGISTER = 0x4BE8
def _load_map():
    syms = {}
    for line in (REPO / "build" / "payload.map").read_text().splitlines():
        p = line.split()
        if len(p) == 3:
            syms[p[2]] = int(p[0], 16)
    return syms


_PAY_SYMS = _load_map()
BOOT_CMD = _PAY_SYMS["boot_cmd"]
BOOT_HANDLER = _PAY_SYMS["boot_handler"]

VIVO_LOCKED = 1
VIVO_UNLOCKED = 3

# Original registrations from LK 0x8120 (before our patch).
ORIGINAL = [
    ("download:", 0x81DC, 1, 0),
    ("flash:", 0x8294, 1, 1),
    ("erase:", 0x8908, 1, 1),
    ("oem ultraflash:", 0x89D4, 1, 1),
    ("oem ultraflash_en", 0x8B78, 1, 1),
    ("ultraflash:", 0x89D4, 1, 1),
]


@dataclass
class Cmd:
    name: str
    handler: int
    flag1: int
    flag2: int
    next: "Cmd | None" = None


def load_lk_data():
    data = OUT_IMG.read_bytes()
    parts = parse_part_headers(data)
    lk = next(p for p in parts if p[4].name == "lk")
    _, off, data_off, _, hdr = lk
    return data[data_off:data_off + hdr.dsize]


def read_cstr(uc, addr, n=128):
    try:
        raw = bytes(uc.mem_read(addr, n))
    except Exception:
        return ""
    return raw.split(b"\0")[0].decode("latin1", "replace")


def emulate_registration(lk):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(BASE, MEM_SIZE, UC_PROT_ALL)
    uc.mem_write(BASE, lk)
    uc.mem_write(SENTINEL, struct.pack("<I", 0xD65F03C0))  # ret
    calls = []

    def hook(uc, address, size, user_data):
        name = read_cstr(uc, uc.reg_read(UC_ARM64_REG_X0))
        handler = uc.reg_read(UC_ARM64_REG_X1)
        f1 = uc.reg_read(UC_ARM64_REG_W2) & 0xFFFFFFFF
        f2 = uc.reg_read(UC_ARM64_REG_W3) & 0xFFFFFFFF
        calls.append((name, handler, f1, f2))
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook, begin=FASTBOOT_REGISTER, end=FASTBOOT_REGISTER)
    uc.reg_write(UC_ARM64_REG_SP, STACK)
    uc.reg_write(UC_ARM64_REG_LR, SENTINEL)
    uc.reg_write(UC_ARM64_REG_PC, BASE + REG_FN)
    try:
        uc.emu_start(BASE + REG_FN, SENTINEL, count=200000)
    except Exception as e:
        raise SystemExit("registration emulation fault at PC=0x%x: %s" %
                         (uc.reg_read(UC_ARM64_REG_PC), e))
    return calls


def build_list(calls):
    head = None
    for name, handler, f1, f2 in calls:
        head = Cmd(name, handler, f1, f2, head)  # fastboot_register inserts at head
    return head


def walk(head):
    out = []
    while head:
        out.append(head)
        head = head.next
    return out


def lookup(head, command):
    node = head
    while node:
        if command.startswith(node.name):
            return node
        node = node.next
    return None


def gate(node, state, security_on=True):
    """Decoded dispatcher gating.  state: 1 locked, 3 unlocked."""
    if node is None:
        return False, "no match"
    if security_on:
        if node.flag1 == 0:
            return (state == VIVO_UNLOCKED), "flag1=0 -> state gate"
        if node.flag2 == 0:
            return True, "flag1=1, flag2=0 -> allow"
        return (state == VIVO_UNLOCKED), "flag1=1, flag2=1 -> locked gate"
    else:
        if node.flag2 == 0:
            return True, "security off, flag2=0 -> allow"
        return (state == VIVO_UNLOCKED), "security off, flag2=1 -> state gate"


def rawboot_flow(magic_ok, dl_size, payload_size):
    """In-place RAWBOOT: entry = download_base + 0x28."""
    if not magic_ok:
        return False, "bad RAWBOOT! magic"
    if dl_size < 0x28:
        return False, "download smaller than 0x28-byte header"
    if payload_size == 0:
        return False, "empty payload"
    if payload_size > dl_size - 0x28:
        return False, "payload exceeds download size"
    return True, "entry = download_base + 0x28 (executed in place)"


def main():
    lk = load_lk_data()
    calls = emulate_registration(lk)
    print("Real LK 0x8120 registrations:")
    for c in calls:
        print("  %-22s handler=0x%06x f1=%d f2=%d" % c)

    assert len(calls) == 7, calls
    # First six = original order; last = ultraflash (displaced) + boot.
    for got, exp in zip(calls[:5], ORIGINAL[:5]):
        assert got[:4] == exp, (got, exp)
    assert calls[5][:4] == ORIGINAL[5], (calls[5], ORIGINAL[5])
    assert calls[6][0] == "boot", calls[6]
    assert calls[6][1] == BOOT_HANDLER, calls[6]
    assert calls[6][2:] == (1, 0), calls[6]
    print("registration emulation: OK (original six preserved + boot)")

    head = build_list(calls)
    nodes = walk(head)
    print("Command list (head insertion order):", [n.name for n in nodes])
    assert nodes[0].name == "boot"
    for name, handler, f1, f2 in ORIGINAL:
        n = next(x for x in nodes if x.name == name)
        assert (n.handler, n.flag1, n.flag2) == (handler, f1, f2), (name, n)

    checks = [
        ("download:00001000", VIVO_LOCKED, True),
        ("flash:boot", VIVO_LOCKED, False),
        ("erase:boot", VIVO_LOCKED, False),
        ("boot", VIVO_LOCKED, True),
        ("download:00001000", VIVO_UNLOCKED, True),
        ("flash:boot", VIVO_UNLOCKED, True),
        ("erase:boot", VIVO_UNLOCKED, True),
        ("boot", VIVO_UNLOCKED, True),
    ]
    print("Dispatcher gating:")
    for command, state, expected in checks:
        node = lookup(head, command)
        allowed, why = gate(node, state)
        print("  %-20s state=%d -> %s (%s)" % (command, state, allowed, why))
        assert allowed == expected, (command, state, allowed, expected)
    assert lookup(head, "boot").flag2 == 0, "boot must be allowed when locked"
    print("dispatcher gating: OK (boot reachable in locked fastboot)")

    print("RAWBOOT model:")
    cases = [
        (True, 0x2000, 0x1F00),
        (True, 0x100, 0x200),
        (True, 0x28, 0),
        (False, 0x2000, 0x100),
    ]
    for magic_ok, dl, ps in cases:
        result, why = rawboot_flow(magic_ok, dl, ps)
        print("  magic=%s dl=0x%x payload=0x%x -> %s (%s)" % (magic_ok, dl, ps, result, why))
    assert rawboot_flow(True, 0x2000, 0x1F00)[0] is True
    assert rawboot_flow(False, 0x2000, 0x100)[0] is False
    assert rawboot_flow(True, 0x100, 0x200)[0] is False
    assert rawboot_flow(True, 0x28, 0)[0] is False
    print("RAWBOOT model: OK")

    print("\nLK FLOW SMOKE TEST PASSED")


if __name__ == "__main__":
    main()
