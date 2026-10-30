#!/usr/bin/env python3
"""
Build a CERT2-signed 16MB lk image with `fastboot boot` support.

Input : OS3 iQOO Z8 lk.bin (MTK MKIMG container)
Output: dist/lk.img

The script:
  1. parses the MKIMG part_hdr chain and extracts the lk subimage;
  2. injects the AArch64 payload into the executable zero cave at 0x1880;
  3. patches:
       0x81d8  b  fastboot_register  ->  b  payload stub
       0xd12c  bl storage loader    ->  bl load_wrapper
       0xd15c  bl storage loader    ->  bl load_wrapper
  4. rebuilds the partition (subsequent subimages shift);
  5. re-signs CERT2 with the project's CVE overlay signer (no private key);
  6. pads/truncates to the 16MiB lk partition size;
  7. verifies CERT2 hashes, patch words, payload placement, cave bounds and part chain.
"""
import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROJECT = REPO.parent
TOOL = PROJECT / "tools" / "lk-patcher-master"
sys.path.insert(0, str(TOOL))

from mtk_img import (  # noqa: E402
    parse_part_headers,
    extract_lk_subimage,
    sign_image_bytes,
    verify_cert2_hashes,
    PART_HDR_SIZE,
    PART_MAGIC,
)

DEFAULT_INPUT = PROJECT / "Root-Unlockless-Images" / "iqoo-z8" / "lk" / "os3-unlockless" / "lk.bin"
DEFAULT_OUT = REPO / "dist" / "lk.img"
PAYLOAD = REPO / "build" / "payload.bin"
PAYLOAD_MAP = REPO / "build" / "payload.map"

PART_SIZE = 0x1000000
LK_PAYLOAD_OFF = 0x1880
LK_CAVE_END = 0x2400
LK_OLD_DSIZE = 0xcef90
LK_BSS_OFF = 0xd0000
PATCH_BOOT_REG = 0x81d8
PATCH_LOADER_1 = 0xd12c
PATCH_LOADER_2 = 0xd15c
PATCH_OVERLAY = 0xc3f0
PATCH_BOOTCONFIG = 0xcb7c


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def align_up(v, a):
    return (v + a - 1) // a * a


def branch_word(src, dst, is_bl):
    off = (dst - src) >> 2
    if off < -(1 << 25) or off >= (1 << 25):
        raise ValueError("branch out of range: 0x%x -> 0x%x" % (src, dst))
    op = 0x94000000 if is_bl else 0x14000000
    return op | (off & 0x03FFFFFF)


def decode_branch(word, pc):
    off = word & 0x03FFFFFF
    if off & 0x02000000:
        off -= 0x04000000
    return pc + off * 4


def load_symbols(path):
    syms = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) == 3:
            syms[parts[2]] = int(parts[0], 16)
    return syms


def part_table(data):
    out = []
    for idx, off, data_off, next_off, hdr in parse_part_headers(data):
        out.append({
            "idx": idx,
            "hdr_off": off,
            "data_off": data_off,
            "next_off": next_off,
            "name": hdr.name,
            "dsize": hdr.dsize,
            "naddr": hdr.maddr,
            "align": hdr.align_sz,
            "type": hdr.img_type,
            "list_end": hdr.img_list_end,
        })
    return out


def find_part(parts, name, occurrence=0):
    n = 0
    for p in parts:
        if p["name"] == name:
            if n == occurrence:
                return p
            n += 1
    raise KeyError(name)


def data_bytes(data, p):
    return data[p["data_off"]:p["data_off"] + p["dsize"]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(DEFAULT_INPUT))
    ap.add_argument("--output", default=str(DEFAULT_OUT))
    ap.add_argument("--payload", default=str(PAYLOAD))
    ap.add_argument("--map", default=str(PAYLOAD_MAP))
    args = ap.parse_args()

    inp = Path(args.input)
    out = Path(args.output)
    payload_path = Path(args.payload)

    raw = inp.read_bytes()
    raw_sha = hashlib.sha256(raw).hexdigest()
    print("Input :", inp)
    print("Size  :", len(raw), hex(len(raw)))
    print("SHA256:", raw_sha)

    if len(raw) != PART_SIZE:
        print("WARN: input is not 16MiB; output will be padded to 16MiB")

    parts = part_table(raw)
    print("\nPart table (input):")
    for p in parts:
        print("  %-12s off=0x%08x data=0x%08x dsz=0x%x align=0x%x type=0x%x end=%d" % (
            p["name"], p["hdr_off"], p["data_off"], p["dsize"], p["align"], p["type"], p["list_end"]))

    names = [p["name"] for p in parts]
    expected_prefix = ["lk", "cert1", "cert2", "bl2_ext"]
    if names[:4] != expected_prefix:
        raise SystemExit("unexpected part order: %r" % names[:8])

    ok, results = verify_cert2_hashes(raw, verbose=True)
    print("Input CERT2 verify:", ok)
    if not ok:
        print("WARN: input CERT2 hashes do not verify; continuing anyway")

    lk_block, lk_off, lk_end = extract_lk_subimage(raw)
    lk_hdr = lk_block[:PART_HDR_SIZE]
    old_dsize = u32(lk_hdr, 4)
    if old_dsize != LK_OLD_DSIZE:
        raise SystemExit("unexpected lk dsize 0x%x (expected 0x%x)" % (old_dsize, LK_OLD_DSIZE))
    if lk_off != 0:
        raise SystemExit("lk subimage is not first: 0x%x" % lk_off)
    print("\nlk block: off=0x%x end=0x%x old_dsize=0x%x" % (lk_off, lk_end, old_dsize))

    lk_data = bytearray(lk_block[PART_HDR_SIZE:PART_HDR_SIZE + old_dsize])
    if len(lk_data) != old_dsize:
        raise SystemExit("truncated lk data")

    payload = payload_path.read_bytes()
    print("Payload:", payload_path, "size", len(payload), hex(len(payload)))
    if len(payload) == 0 or LK_PAYLOAD_OFF + len(payload) > LK_CAVE_END:
        raise SystemExit("payload does not fit cave 0x%x..0x%x" % (LK_PAYLOAD_OFF, LK_CAVE_END))

    syms = load_symbols(Path(args.map))
    for sym in ("payload_base", "load_wrapper", "boot_handler", "overlay_hook", "bootconfig_hook"):
        if sym not in syms:
            raise SystemExit("missing symbol %s in payload map" % sym)
    if syms["payload_base"] != LK_PAYLOAD_OFF:
        raise SystemExit("payload_base 0x%x != injection offset 0x%x" % (
            syms["payload_base"], LK_PAYLOAD_OFF))
    print("Symbols: payload_base=0x%x load_wrapper=0x%x overlay_hook=0x%x "
          "bootconfig_hook=0x%x boot_handler=0x%x" % (
        syms["payload_base"], syms["load_wrapper"], syms["overlay_hook"],
        syms["bootconfig_hook"], syms["boot_handler"]))
    cave = lk_data[LK_PAYLOAD_OFF:LK_PAYLOAD_OFF + len(payload)]
    if set(cave) != {0}:
        raise SystemExit("target cave 0x%x..0x%x is not all zero (refusing to overwrite)" % (
            LK_PAYLOAD_OFF, LK_PAYLOAD_OFF + len(payload)))
    print("cave 0x%x..0x%x is all zero; payload end 0x%x < 0x%x" % (
        LK_PAYLOAD_OFF, LK_PAYLOAD_OFF + len(payload),
        LK_PAYLOAD_OFF + len(payload), LK_CAVE_END))

    # Patch registration tail and storage-loader call sites.
    new_boot_reg = branch_word(PATCH_BOOT_REG, syms["payload_base"], is_bl=False)
    new_loader1 = branch_word(PATCH_LOADER_1, syms["load_wrapper"], is_bl=True)
    new_loader2 = branch_word(PATCH_LOADER_2, syms["load_wrapper"], is_bl=True)
    new_overlay = branch_word(PATCH_OVERLAY, syms["overlay_hook"], is_bl=True)
    new_bootconfig = branch_word(PATCH_BOOTCONFIG, syms["bootconfig_hook"], is_bl=True)

    patch_specs = [
        ("fastboot_register tail -> payload stub", PATCH_BOOT_REG, 0x17FFF284, new_boot_reg, False, 0x4BE8),
        ("storage loader #1 -> wrapper", PATCH_LOADER_1, 0x94011236, new_loader1, True, 0x51A04),
        ("storage loader #2 -> wrapper", PATCH_LOADER_2, 0x9401122A, new_loader2, True, 0x51A04),
        ("dtbo overlay -> hook", PATCH_OVERLAY, 0x940198C4, new_overlay, True, 0x72700),
        ("bootconfig append -> hook", PATCH_BOOTCONFIG, 0x97FFF896, new_bootconfig, True, 0xadd4),
    ]
    new_targets = {
        PATCH_BOOT_REG: syms["payload_base"],
        PATCH_LOADER_1: syms["load_wrapper"],
        PATCH_LOADER_2: syms["load_wrapper"],
        PATCH_OVERLAY: syms["overlay_hook"],
        PATCH_BOOTCONFIG: syms["bootconfig_hook"],
    }
    for desc, off, expect, new, is_bl, target in patch_specs:
        cur = u32(lk_data, off)
        if cur != expect:
            raise SystemExit("patch %s: unexpected original word 0x%08x at 0x%x" % (desc, cur, off))
        got_target = decode_branch(cur, off)
        if got_target != target:
            raise SystemExit("patch %s: original target 0x%x != 0x%x" % (desc, got_target, target))
        struct.pack_into("<I", lk_data, off, new)
        new_target = decode_branch(new, off)
        print("  patch 0x%06x: 0x%08x -> 0x%08x  %s -> 0x%x" % (
            off, cur, new, "bl" if is_bl else "b", new_target))
        if new_target != new_targets[off]:
            raise SystemExit("patch target mismatch at 0x%x" % off)

    # The payload lives inside the existing lk data (executable text cave);
    # the lk dsize does not grow.  Only CERT2 may grow during signing.
    lk_data[LK_PAYLOAD_OFF:LK_PAYLOAD_OFF + len(payload)] = payload
    new_dsize = old_dsize
    if LK_PAYLOAD_OFF + len(payload) > LK_BSS_OFF:
        raise SystemExit("cave payload overlaps BSS")
    print("payload injected at 0x%x (size 0x%x); lk dsize unchanged 0x%x" % (
        LK_PAYLOAD_OFF, len(payload), new_dsize))

    new_hdr = bytearray(lk_hdr)
    struct.pack_into("<I", new_hdr, 4, new_dsize)
    tail = lk_block[PART_HDR_SIZE + old_dsize:]
    new_lk = bytes(new_hdr) + bytes(lk_data) + tail
    new_raw = raw[:lk_off] + new_lk + raw[lk_end:]
    print("partition growth before signing: 0x%x bytes" % (len(new_raw) - len(raw)))

    # Validate the new part chain before signing.
    np_parts = part_table(new_raw)
    lk_new = find_part(np_parts, "lk")
    if lk_new["dsize"] != new_dsize:
        raise SystemExit("rebuilt lk dsize mismatch")
    if lk_new["hdr_off"] != 0:
        raise SystemExit("rebuilt lk header moved")

    print("\nSigning CERT2 (legacy=False, CVE overlay)...")
    signed = sign_image_bytes(new_raw, verbose=True, legacy=False)
    if signed is None:
        raise SystemExit("CERT2 signing failed")
    print("signed size:", len(signed), hex(len(signed)))

    ok, results = verify_cert2_hashes(signed, verbose=True)
    print("Signed CERT2 verify:", ok)
    if not ok:
        raise SystemExit("CERT2 verification failed after signing")

    if len(signed) < PART_SIZE:
        signed = signed + b"\x00" * (PART_SIZE - len(signed))
    elif len(signed) > PART_SIZE:
        extra = signed[PART_SIZE:]
        if any(extra):
            raise SystemExit("signed image exceeds 16MiB and tail is not zero")
        signed = signed[:PART_SIZE]
    print("final size:", len(signed), hex(len(signed)))

    # Final part chain / content checks.
    fp = part_table(signed)
    for p in fp:
        print("  final %-12s off=0x%08x dsz=0x%x type=0x%x end=%d" % (
            p["name"], p["hdr_off"], p["dsize"], p["type"], p["list_end"]))
    flk = find_part(fp, "lk")
    if flk["dsize"] != new_dsize:
        raise SystemExit("final lk dsize mismatch")
    if flk["hdr_off"] != 0:
        raise SystemExit("final lk header not at 0")

    # The payload must be present verbatim at LK_PAYLOAD_OFF inside lk data.
    lk_final = signed[PART_HDR_SIZE:PART_HDR_SIZE + new_dsize]
    if lk_final[LK_PAYLOAD_OFF:LK_PAYLOAD_OFF + len(payload)] != payload:
        raise SystemExit("payload not found at 0x%x in final lk" % LK_PAYLOAD_OFF)
    if flk["hdr_off"] + PART_HDR_SIZE + new_dsize > LK_BSS_OFF + PART_HDR_SIZE:
        # lk data ends before BSS in the loaded image (VA space)
        raise SystemExit("lk data overlaps BSS")

    # Patch words in the final image.
    for desc, off, expect, new, is_bl, target in patch_specs:
        cur = u32(lk_final, off)
        if cur != new:
            raise SystemExit("final patch word mismatch at 0x%x" % off)
        if decode_branch(cur, off) != new_targets[off]:
            raise SystemExit("final patch target mismatch at 0x%x" % off)

    # Unmodified payload-bearing subimages must be byte-identical.
    orig_parts = part_table(raw)
    for name in ("bl2_ext", "aee", "lk_main_dtb"):
        a = data_bytes(raw, find_part(orig_parts, name))
        b = data_bytes(signed, find_part(fp, name))
        if hashlib.sha256(a).digest() != hashlib.sha256(b).digest():
            raise SystemExit("%s content changed unexpectedly" % name)
        print("  unchanged:", name, hashlib.sha256(a).hexdigest()[:16])

    # Count all differences in the original lk data region.
    orig_lk_data = raw[PART_HDR_SIZE:PART_HDR_SIZE + old_dsize]
    diff = [i for i, (a, b) in enumerate(zip(orig_lk_data, lk_final[:old_dsize])) if a != b]
    print("  lk data byte diffs (patch words + injected cave):", len(diff), [hex(x) for x in diff[:16]])
    allowed = set()
    for _desc, off, _e, _n, _b, _t in patch_specs:
        allowed.update(range(off, off + 4))
    allowed.update(range(LK_PAYLOAD_OFF, LK_PAYLOAD_OFF + len(payload)))
    unexpected = [x for x in diff if x not in allowed]
    if unexpected:
        raise SystemExit("unexpected lk data diffs: %r" % unexpected[:20])

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(signed)
    out_sha = hashlib.sha256(signed).hexdigest()
    out.with_suffix(out.suffix + ".sha256").write_text("%s  %s\n" % (out_sha, out.name))

    try:
        input_rel = os.path.relpath(inp, PROJECT)
    except ValueError:
        input_rel = inp.name
    try:
        output_rel = os.path.relpath(out, REPO)
    except ValueError:
        output_rel = out.name
    manifest = {
        "device": "iQOO Z8 / Y100t (PD2314, MT6895/MT6896)",
        "input": input_rel,
        "input_sha256": raw_sha,
        "input_size": len(raw),
        "output": output_rel,
        "output_sha256": out_sha,
        "output_size": len(signed),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_size": len(payload),
        "payload_offset": LK_PAYLOAD_OFF,
        "payload_cave_end": LK_CAVE_END,
        "lk_old_dsize": old_dsize,
        "lk_new_dsize": new_dsize,
        "bss_offset": LK_BSS_OFF,
        "patches": [
            {"desc": d, "offset": o, "old": "0x%08x" % e, "new": "0x%08x" % n}
            for (d, o, e, n, _is_bl, _t) in patch_specs
        ],
        "cert2_signed": True,
        "part_table": fp,
        "notes": [
            "Generated only; not flashed.",
            "fastboot host sends 'download:' then 'boot' (no colon).",
            "Payload logs are printed through LK printf and should reach the LK log/expdb.",
        ],
    }
    (REPO / "dist" / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print("\nWrote:", out)
    print("SHA256:", out_sha)
    print("Manifest:", REPO / "dist" / "manifest.json")


if __name__ == "__main__":
    main()
