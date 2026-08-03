#!/usr/bin/env python3
"""Append a file's bytes to the .text section of a JieLi app.bin, fixing offsets.

`app.bin = text.bin ++ data.bin ++ data_code.bin ++ bank.bin`, XIP-mapped at
CODE_BASE (0x1e00120). We insert the new bytes at the *end* of text.bin (file
offset == text_size), which is the one growth that stays reliable:

  * No existing .text byte moves, so every intra-.text reference — and the LZ4
    dictionary, a fixed window *inside* .text that the bank loader anchors at
    `text_base + stored_offset` — stays valid with no change.
  * Only .data / .data_code / .bank_lz4 shift down by N (= appended size).

So the only offsets to fix are absolute pointers INTO that shifted tail. Those
are 32-bit immediate loads `cX ff <imm32-LE>` (X = dest register) whose value is
>= text_end. They are few and enumerable by scanning: a random dword that both
matches the `cX ff` prefix *and* lands in the tail address range is
astronomically unlikely, so the scan finds exactly the real pointers.

Crucially the scan must cover not only .text but the RAM-resident CODE image in
.data_code: the overlay/bank loader is compiled into .data_code (it must stay
resident while banks are swapped), and it carries its OWN copy of the .bank_lz4
load address as a `cX ff` immediate. That copy lives in the tail and is shifted
bodily with it, so its immediate must be bumped too — miss it and the resident
loader reads compressed overlays from the wrong flash offset and the image won't
boot (verified against two SDK builds: growing .text by 4 changed exactly this
one .data_code immediate). We therefore scan [0, bank_base): .text + .data +
.data_code, but NOT the LZ4-compressed .bank blob (its bytes aren't instructions
and must be preserved verbatim). For this device image the scan finds 5 pointers:
the startup .data and .data_code copy sources and a second .data src reference
(all in .text), the .text overlay-loader's .bank_lz4 base, and the .data_code
resident loader's .bank_lz4 base. Each is bumped by N.

Left untouched (correctly): every pointer into the unmoved .text (< text_end),
the compressed .bank blob, and all RAM-resident data references — .data and
.data_code RUN at fixed RAM addrs (only their flash LOAD copies move) and .bss is
NOBITS, none of which move.

The appended bytes must already be assembled/linked to run at text_end
(0x1e00120 + old text_size); this tool does not relocate the payload itself. It
also does not re-run the outer firmware packager — feed the new app.bin to that.

Usage:
    python3 matcher/append_text.py PAYLOAD [--bin app.bin] [--out OUT]
                                   [--align N] [--fill HH] [--dry-run]
"""
import os
import struct
import argparse

from jl_sdk_utils import CODE_BASE, imm32, IMM_SLOTS, parse_packet

def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def image_boundaries(payload):
    """Return the vaddr boundaries of the movable tail from the startup slots:
    (text_end, data_code_src, bank_base, eof) — .data src = text_end."""
    text_size = imm32(payload, IMM_SLOTS['data_src']) - CODE_BASE
    dc_src = imm32(payload, IMM_SLOTS['data_code_src'])
    dc_size = imm32(payload, IMM_SLOTS['data_code_size'])
    text_end = CODE_BASE + text_size          # == .data flash source
    bank_base = dc_src + dc_size
    return text_end, dc_src, bank_base, CODE_BASE + len(payload)


def find_tail_pointers(region, text_end, eof):
    """[(file_off, value)] for every `cX ff imm32` load in `region` whose imm32
    lands in the movable tail [text_end, eof) — i.e. points into the shifted
    .data / .data_code / .bank_lz4. `region` should be bytes [0, bank_base): the
    .text plus the RAM-resident .data/.data_code code images, but NOT the
    LZ4-compressed .bank blob (whose bytes aren't instructions). The range is
    bounded on BOTH sides: values >= eof are not addresses into this image at all
    (ASCII, masks, other constants) and must be left alone, which is what keeps
    the scan free of false positives."""
    out = []
    for off in range(0, len(region) - 5):
        if (region[off] & 0xf0) == 0xc0 and region[off + 1] == 0xff:
            v = u32(region, off + 2)
            if text_end <= v < eof:
                out.append((off, v))
    return out


def label(off, v, text_end, dc_src, bank_base, eof):
    """Human tag for a relocated pointer: '<home region> -> <target>', where the
    home region is where the pointer itself lives (.text / .data / .data_code)
    and the target is what it points at in the shifted tail."""
    ts = text_end - CODE_BASE
    dc_off = dc_src - CODE_BASE
    bank_off = bank_base - CODE_BASE
    home = '.text' if off < ts else '.data' if off < dc_off else '.data_code'
    slot = {IMM_SLOTS['data_src'] - 2: 'startup .data src',
            IMM_SLOTS['data_code_src'] - 2: 'startup .data_code src'}.get(off)
    if slot:
        return f'{home}: {slot}'
    if v < dc_src:
        tgt = '.data src / text_end'
    elif v < bank_base:
        tgt = '.data_code src'
    elif v < eof:
        tgt = f'.bank_lz4 base (+{v - bank_base:#x})'
    else:
        tgt = '?? past end'
    return f'{home} -> {tgt}'


def append_text(payload, extra, align, fill):
    """Return (new_image, N, relocs). Inserts `extra` (padded to `align`) at the
    end of .text and bumps every tail pointer by N."""
    text_size = imm32(payload, IMM_SLOTS['data_src']) - CODE_BASE
    text_end, dc_src, bank_base, eof = image_boundaries(payload)
    bank_off = bank_base - CODE_BASE

    pad = (-len(extra)) % align
    extra_padded = extra + bytes([fill]) * pad
    N = len(extra_padded)

    # Patch every tail pointer in place across .text + .data + .data_code (but
    # not the compressed .bank blob), then splice the payload in at text_end. A
    # .data_code pointer lives past text_end, so it's patched in the tail and
    # then shifts bodily with it — both happen on the same `img` buffer.
    img = bytearray(payload)
    relocs = find_tail_pointers(img[:bank_off], text_end, eof)
    for off, v in relocs:
        struct.pack_into('<I', img, off + 2, v + N)

    new = bytes(img[:text_size]) + extra_padded + bytes(img[text_size:])
    info = [(off, v, label(off, v, text_end, dc_src, bank_base, eof))
            for off, v in relocs]
    return new, N, info


def verify(old, new, N):
    """Structural self-check: sizes bumped by N, the compressed .bank blob is
    byte-identical (only shifted), the packet still parses, and every tail
    pointer landed at its shifted position holding value+N."""
    old_ts = imm32(old, IMM_SLOTS['data_src']) - CODE_BASE
    new_ts = imm32(new, IMM_SLOTS['data_src']) - CODE_BASE
    assert new_ts == old_ts + N, (new_ts, old_ts, N)
    for k in ('data_code_src',):
        assert imm32(new, IMM_SLOTS[k]) == imm32(old, IMM_SLOTS[k]) + N, k
    for k in ('data_dest', 'data_size', 'data_code_dest', 'data_code_size',
              'bss_dest', 'bss_size'):
        assert imm32(new, IMM_SLOTS[k]) == imm32(old, IMM_SLOTS[k]), k
    # the compressed .bank blob must be preserved verbatim, just shifted by N
    text_end, _, old_bank, eof = image_boundaries(old)
    old_bank_off = old_bank - CODE_BASE
    assert new[old_bank_off + N:] == old[old_bank_off:], 'bank bytes changed'
    new_bank_off = old_bank_off + N
    assert parse_packet(new[new_bank_off:]), 'packet no longer parses'
    # every relocated pointer (in .text < text_size stays put; in the tail it
    # shifts by N) must now hold its old value + N — i.e. none was missed.
    for off, v in find_tail_pointers(old[:old_bank_off], text_end, eof):
        new_off = off if off < old_ts else off + N
        got = struct.unpack_from('<I', new, new_off + 2)[0]
        assert got == v + N, (hex(off), hex(v), hex(got), N)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('payload', help='file whose bytes to append to .text')
    ap.add_argument('--bin', help='input app.bin')
    ap.add_argument('--out', help='output image (default: <bin>.appended)')
    ap.add_argument('--align', type=int, default=4,
                    help='pad the appended size up to this many bytes (default 4, '
                    'keeps the following .data word-aligned)')
    ap.add_argument('--fill', default='00',
                    help='hex pad byte between payload and .data (default 00)')
    ap.add_argument('--dry-run', action='store_true',
                    help='show the plan and relocations without writing')
    args = ap.parse_args()

    payload = open(args.bin, 'rb').read()
    extra = open(args.payload, 'rb').read()
    fill = int(args.fill, 16)

    text_size = imm32(payload, IMM_SLOTS['data_src']) - CODE_BASE
    new, N, relocs = append_text(payload, extra, args.align, fill)
    verify(payload, new, N)

    print(f"input:   {args.bin}  ({len(payload):#x} bytes)")
    print(f"payload: {args.payload}  ({len(extra):#x} bytes"
          f"{f' -> {N:#x} padded to {args.align}' if N != len(extra) else ''})")
    print(f".text:   {text_size:#x} -> {text_size + N:#x}  "
          f"(new code runs at {CODE_BASE + text_size:#x})")
    print(f"\nrelocated {len(relocs)} tail pointer(s) (+{N:#x}):")
    for off, v, tag in relocs:
        print(f"  .text+{off:#07x} (vaddr {CODE_BASE + off:#x}): "
              f"{v:#x} -> {v + N:#x}   {tag}")

    if args.dry_run:
        print("\n[dry-run] not writing")
        return
    out = args.out or args.bin + '.appended'
    with open(out, 'wb') as f:
        f.write(new)
    print(f"\nwrote {out}  ({len(new):#x} bytes)  [verify OK]")


if __name__ == '__main__':
    main()
