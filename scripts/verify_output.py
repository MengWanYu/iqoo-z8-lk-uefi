#!/usr/bin/env python3
"""Independent verifier for the produced RAWBOOT LK image."""
import argparse
import hashlib
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROJECT = REPO.parent
TOOL = PROJECT / "tools" / "lk-patcher-master"
sys.path.insert(0, str(TOOL))
from mtk_img import parse_part_headers, verify_cert2_hashes  # noqa: E402

IN_DEFAULT = PROJECT / "Root-Unlockless-Images" / "iqoo-z8" / "lk" / "os3-unlockless" / "lk.bin"
OUT_DEFAULT = REPO / "dist" / "lk.img"
MAP_DEFAULT = REPO / "build" / "payload.map"
PAYLOAD_DEFAULT = REPO / "build" / "payload.bin"

PART_SIZE = 0x1000000
PAYLOAD_OFF = 0x1880
PAYLOAD_CAVE_END = 0x2400
LK_OLD_DSIZE = 0xCEF90
BSS_OFF = 0xD0000
PATCHES = [(0x81D8, 0x14000000, True), (0xD12C, 0x94000000, True),
           (0xD15C, 0x94000000, True), (0xC3F0, 0x94000000, True),
           (0xCB7C, 0x94000000, True)]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def parts(d):
    return [(h.name, off, data_off, next_off, h) for _, off, data_off, next_off, h in parse_part_headers(d)]


def find(ps, name):
    return next(p for p in ps if p[0] == name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(IN_DEFAULT))
    ap.add_argument("--output", default=str(OUT_DEFAULT))
    ap.add_argument("--map", default=str(MAP_DEFAULT))
    ap.add_argument("--payload", default=str(PAYLOAD_DEFAULT))
    a = ap.parse_args()

    inp = Path(a.input).read_bytes()
    out = Path(a.output).read_bytes()
    expected_payload = Path(a.payload).read_bytes()
    syms = {}
    for line in Path(a.map).read_text().splitlines():
        p = line.split()
        if len(p) == 3:
            syms[p[2]] = int(p[0], 16)

    assert len(out) == PART_SIZE, "output size %#x != 16MiB" % len(out)
    assert u32(out, 0) == 0x58881688, "lk magic missing"

    ps = parts(out)
    names = [p[0] for p in ps]
    assert names[:4] == ["lk", "cert1", "cert2", "bl2_ext"], names
    assert names[-3:] == ["cert1", "cert2"][:0] or names[-1] == "cert2", names
    final = ps[-1][4]
    assert final.img_list_end == 1, "last part does not terminate the chain"

    lk = find(ps, "lk")
    lk_data_off = lk[2]
    lk_dsize = lk[4].dsize
    assert lk[1] == 0, "lk header moved"
    assert lk_dsize == LK_OLD_DSIZE, "lk dsize changed unexpectedly: 0x%x" % lk_dsize
    assert lk_dsize < BSS_OFF, "lk data overlaps BSS"
    assert PAYLOAD_OFF + len(expected_payload) <= PAYLOAD_CAVE_END, "payload exceeds cave"
    assert PAYLOAD_OFF + len(expected_payload) < BSS_OFF, "cave payload overlaps BSS"

    payload = out[lk_data_off + PAYLOAD_OFF:lk_data_off + PAYLOAD_OFF + len(expected_payload)]
    assert payload == expected_payload, "payload bytes mismatch at 0x%x" % PAYLOAD_OFF
    # Magic and command string are in the payload; check both.
    assert b"RAWBOOT!" in payload, "RAWBOOT magic missing in payload"
    assert b"boot\0" in payload, "boot command string missing"
    assert b"kaeru-rawboot: payload=" in payload, "log strings missing"

    # Patch words and targets.
    expected = {
        0x81D8: (0x14000000, syms["payload_base"]),
        0xD12C: (0x94000000, syms["load_wrapper"]),
        0xD15C: (0x94000000, syms["load_wrapper"]),
        0xC3F0: (0x94000000, syms["overlay_hook"]),
        0xCB7C: (0x94000000, syms["bootconfig_hook"]),
    }
    for off, (op, target) in expected.items():
        w = u32(out, lk_data_off + off)
        assert (w & 0xFC000000) == op, "opcode mismatch at %#x: %#x" % (off, w)
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        got = off + imm * 4
        assert got == target, "branch target at %#x: %#x != %#x" % (off, got, target)

    # Only the three patch words and the injected cave may differ in the
    # original lk data region.
    inp_lk = inp[0x200:0x200 + LK_OLD_DSIZE]
    out_lk = out[lk_data_off:lk_data_off + LK_OLD_DSIZE]
    allowed = set()
    for off, _op, _t in PATCHES:
        allowed.update(range(off, off + 4))
    allowed.update(range(PAYLOAD_OFF, PAYLOAD_OFF + len(expected_payload)))
    diffs = [i for i, (x, y) in enumerate(zip(inp_lk, out_lk)) if x != y]
    bad = [i for i in diffs if i not in allowed]
    assert not bad, "unexpected lk diffs: %r" % bad[:10]
    print("lk patch words + cave: OK (%d bytes changed, cave %d B)" % (
        len(diffs), len(expected_payload)))

    # Unchanged subimages.
    ip = parts(inp)
    for name in ("bl2_ext", "aee", "lk_main_dtb"):
        x = find(ip, name)
        y = find(ps, name)
        hx = hashlib.sha256(inp[x[2]:x[2] + x[4].dsize]).hexdigest()
        hy = hashlib.sha256(out[y[2]:y[2] + y[4].dsize]).hexdigest()
        assert hx == hy, "%s changed" % name
        print("unchanged %-12s %s" % (name, hx[:16]))

    ok, _ = verify_cert2_hashes(out, verbose=True)
    assert ok, "CERT2 verification failed"
    print("CERT2: OK")
    print("OUTPUT VERIFY PASSED")
    print("sha256:", hashlib.sha256(out).hexdigest())


if __name__ == "__main__":
    main()
