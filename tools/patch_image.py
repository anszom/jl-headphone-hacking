#!/usr/bin/env python3
"""End-to-end JieLi app.bin patcher: append injected code + redirect call sites.

Combines two operations into one image build:

  1. Append the injected code. Takes an ELF built with the inject.ld linker script
     Its loadable bytes are spliced onto the end of .text exactly like append_text.py

  2. Apply binary patches in the original app.bin code. The patch locations & types
     (including goto & call branching) are taken from the .patchmeta section of
     inject.elf. Additionally, the following option is supported:
       --data VADDR          reserve the injected module's RAM: the 32-bit word
                             at VADDR must currently equal the injected .data VMA
                             (the injected .data VMA, __idata_start in the ELF); it
                             is rewritten to the end of .data+.bss (__ibss_end),
                             bumping the firmware heap up past the module. Aborts
                             on mismatch.

Usage:
    python3 ./tools/patch_image.py inject/inject.elf --data 0x1e494ca --bin app.bin --out out.bin [--dry-run]
"""
import os
import struct
import argparse

from jl_sdk_utils import CODE_BASE, imm32, IMM_SLOTS, parse_packet, derive_layout, decompress_overlays
from append_text import append_text, image_boundaries, verify as verify_append
import elf

# --- injected-ELF reading (ELF32 little-endian, pi32v2) ----------------------
def _u(b, o, n):
    return int.from_bytes(b[o:o + n], 'little')

def read_elf(path):
    data = open(path, 'rb').read()
    return elf.Elf(data)

# --- pi32v2 branch encoding --------------------------------------------------
# 4 bytes, verified against disassembly:
#    b1 = 0xEA;  top two bits of b0 select the op: 10=call, 11=goto (jump).
#    disp = TARGET - (VADDR + 4);  field = (disp // 2) & 0x3FFFFF  (22-bit signed)
#    b0 = marker | (field >> 16);  b2 = field & 0xFF;  b3 = (field >> 8) & 0xFF
# Reach is +/-4 MB, so a site in .text always reaches the appended code.

BRANCH_CALL = 0x80
BRANCH_GOTO = 0xC0

def encode_branch(site, target, kind):
    disp = target - (site + 4)
    if disp & 1:
        raise SystemExit(f"patch {site:#x}: odd displacement to {target:#x}")
    u = disp // 2
    if not (-(1 << 21) <= u < (1 << 21)):
        raise SystemExit(f"patch {site:#x} -> {target:#x}: {disp:#x} out of "
                         f"+/-4MB branch range")
    field = u & 0x3fffff
    return bytes([kind | (field >> 16), 0xea,
                  field & 0xff, (field >> 8) & 0xff])


# --- patch application -------------------------------------------------------

def apply_patches(img, entries, text_size):
    """Apply each site edit to `img` (bytearray of the final image). `entries`
    is [(kind, site_spec, spec)] with kind in {'goto','call','data'}:
    goto/call write a 4-byte branch to a symbol/address; patch overwrites the
    32-bit word with a literal value; data is a guarded heap-base bump (see
    below). Returns [(kind, site, info, old, new, tag, spec)]."""
    log = []
    for kind, site_spec, spec in entries:
        site = int(site_spec, 16)
        off = site - CODE_BASE
        if off < 0 or off + 4 > len(img):
            raise SystemExit(f"site {site:#x} outside image")
        tag = '' if off < text_size else '  (WARNING: site not in .text)'
        old = bytes(img[off:off + 4])
        if kind == 'data' and spec is not None:
            # --data VADDR=TARGET: write TARGET's 32-bit address as a pointer
            # (a symbol in the injected ELF, e.g. a hook, or a raw 0x address) --
            # e.g. to overwrite a firmware function-pointer with your hook.
            addr = int(spec, 16)
            new = struct.pack('<I', addr)
            info = ('ptr', addr)
        elif kind == 'data':
            # --data VADDR: reserve the injected module's RAM. The 32-bit word at
            # `site` must currently hold the injected .data VMA (__idata_start);
            # replace it with the end of .data+.bss so the firmware's heap starts
            # above the module's RAM. Abort on mismatch (wrong site, or the
            # firmware heap base is not where the payload expects it).
            vma, end = syms.get('__idata_start'), syms.get('__ibss_end')
            if vma is None or end is None:
                raise SystemExit(
                    "--data VADDR needs the payload ELF linked with inject.ld "
                    "(missing __idata_start / __ibss_end)")
            cur = struct.unpack_from('<I', old, 0)[0]
            if cur != vma:
                raise SystemExit(
                    f"--data {site:#x}: expected the injected .data VMA "
                    f"{vma:#x} here but found {cur:#x}; aborting")
            new = struct.pack('<I', end)
            info = ('heap', vma, end)
        else:
            info = int(spec, 16)
            new = encode_branch(site, info, kind)
            assert k == kind and back == info, (k, hex(back))
        img[off:off + 4] = new
        log.append((kind, site, info, old, new, tag, spec))
    return log


# --- overlay integrity check -------------------------------------------------

def decode_overlays(img):
    secs = derive_layout(img)
    return decompress_overlays(img, secs)

def verify_overlays(old, new):
    """The LZ4 overlays (.common, aec, aac) are compressed against a window of
    .text; a site edit inside a window that a back-reference reads would make
    the overlay decompress to garbage on the device. Decompress every overlay
    from the original and the final image and require identical output."""
    before, after = decode_overlays(old), decode_overlays(new)
    if len(before) != len(after):
        raise SystemExit("overlay packet entry count changed")
    for a, b in zip(before, after):
        if a == b:
            continue
        raise SystemExit(f"overlay changed after decompression. This will require an updated patcher")
    return before

def injected_image(elff):
    lo = None

    out = []
    for s in elff.sections:
        if s.sh_flags & elf.SHF_ALLOC and s.sh_type != elf.SHT_NOBITS and s.lma:
            out.append((s.lma, s.data))

    lo = min(off for off, _ in out)
    hi = max(off + len(data) for off, data in out)
    buf = bytearray()

    for off, data in out:
        buf[off - lo:off - lo + len(data)] = data

    return lo, bytes(buf)

def parse_patchmeta(elff, out):
    sect = elff.named_sections.get('.patchmeta')
    if not sect:
        return

    for off in range(0, len(sect.data), 12):
        pt, a, b = struct.unpack_from('<III', sect.data[off:off+12])

        if pt == 0: # call
            out.append((a, encode_branch(a, b, BRANCH_CALL), 'call'))
        elif pt == 1: # goto
            out.append((a, encode_branch(a, b, BRANCH_GOTO), 'goto'))
        elif pt == 2: # u32
            out.append((a, struct.pack('<I', b), 'u32'))
        elif pt == 3: # u8
            out.append((a, struct.pack('<B', b), 'u8'))
        else:
            raise Exception(f"Invalid patch type ${pt} in .patchmeta")

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('elf', help='injected code, ELF linked via gen_symld.py')
    ap.add_argument('--data',
                    metavar='VADDR',
                    help='reserve the injected module RAM -- the 32-bit word at '
                         'VADDR must currently equal the injected .data VMA '
                         '(__idata_start) and is rewritten to the end of .data+.bss, '
                         'bumping the firmware heap past the module (aborts on mismatch).'
                    )
    ap.add_argument('--bin', required=True, help='input app.bin')
    ap.add_argument('--out', help='output image (default: <bin>.patched)')
    ap.add_argument('--align', type=int, default=4,
                    help='pad appended size up to N bytes (default 4)')
    ap.add_argument('--fill', default='00', help='hex pad byte (default 00)')
    ap.add_argument('--dry-run', action='store_true',
                    help='show the plan without writing')
    args = ap.parse_args()

    appbin = open(args.bin, 'rb').read()
    elff = read_elf(args.elf)

    run_base, inject = injected_image(elff)
    fill = int(args.fill, 16)

    text_size = imm32(appbin, IMM_SLOTS['data_src']) - CODE_BASE
    text_end = CODE_BASE + text_size
    if run_base != text_end:
        raise SystemExit(
            f"injected ELF is linked at {run_base:#x} but this app.bin's "
            f"text_end (__inject_base) is {text_end:#x}. Regenerate the linker "
            f"script from THIS image (gen_symld.py) and relink.")

    # 1. append the injected code (shifts the tail, bumps its pointers)
    new, N, relocs = append_text(appbin, inject, args.align, fill)
    verify_append(appbin, new, N)
    img = bytearray(new)

    # 2. prepare patch list
    patches = []
    if args.data:
        site = int(args.data, 16)
        off = site - CODE_BASE

        # reserve the injected module's RAM. The 32-bit word at `site` must currently hold
        # the injected .data VMA (__idata_start); replace it with the end of .data+.bss
        # so the firmware's heap starts above the module's RAM. Abort on mismatch
        vma, end = elff.named_symbols.get('__idata_start'), elff.named_symbols.get('__ibss_end')
        if vma is None or end is None:
            raise SystemExit("injected module missing __idata_start or __ibss_end")
        old = img[off:off + 4]
        cur = struct.unpack_from('<I', old, 0)[0]

        if cur != vma:
            raise SystemExit(
                f"--data {site:#x}: expected the injected .data VMA "
                f"{vma:#x} here but found {cur:#x}; aborting")
        patches.append((site, struct.pack('<I', end), 'data'))

    parse_patchmeta(elff, patches)

    # 3. apply the requested site edits to the final image
    patchlog = []
    for site, patch, label in patches:
        patchlen = len(patch)
        off = site - CODE_BASE
        if off < 0 or off+patchlen >= len(img):
            raise SystemExit(f"Invalid {label} patch offset: {off:x}");

        old = img[off:off+patchlen]
        img[off:off+patchlen] = patch
        patchlog.append((off, old, patch, label))
    new = bytes(img)

    print(f"input:    {args.bin}  ({len(appbin):#x} bytes)")
    print(f"injected: {args.elf}  ({len(inject):#x} bytes at {run_base:#x}"
          f"{f' -> {N:#x} padded' if N != len(inject) else ''})")

    print(f".text:    {text_size:#x} -> {text_size + N:#x}  "
          f"(injected code runs at {text_end:#x})")
    print(f"\nrelocated {len(relocs)} tail pointer(s) (+{N:#x}):")
    for off, v, tag in relocs:
        print(f"  vaddr {CODE_BASE + off:#x}: {v:#x} -> {v + N:#x}   {tag}")
    print(f"\napplied {len(patches)} site edit(s):")
    for off, old, new_b, label in patchlog:
        print(f"    {label:4} at {off + CODE_BASE:#x}: {old.hex()} => {new_b.hex()}")

    # 4. overlays must decompress identically (dicts are windows into .text)
    overlays = verify_overlays(appbin, new)

    print(f"\noverlays decompress identically ({len(overlays)} checked)")

    if args.dry_run:
        print("\n[dry-run] not writing")
        return
    out = args.out or args.bin + '.patched'
    with open(out, 'wb') as f:
        f.write(new)
    print(f"\nwrote {out}  ({len(new):#x} bytes)  [verify OK]")


if __name__ == '__main__':
    main()
