#!/usr/bin/env python3
"""Reconstruct a properly-sectioned app.elf from the flattened app.bin.

The device image is `cat text.bin data.bin data_code.bin bank.bin` (see the SDK's
tools/download.c), where bank.bin is an lz4_packet blob (dict=text.bin) holding
common + overlays + banks. Our original app.elf force-fit the whole thing into
one .text at vaddr = off+0x1e00000, so everything past text.bin has wrong vaddrs
and the compressed tail disassembles as garbage.

This tool recovers the real section layout and emits a multi-section ELF:
  .text       code+rodata, vaddr 0x1e00120
  .data       initialized data, at its RAM vaddr
  .data_code   RAM-resident code, at its RAM vaddr
  .bss        NOBITS, at its RAM vaddr (from the startup clear loop)
  .bank_lz4    the compressed remainder (archival; also decompressed below)
  .common / .overlay_aec / .overlay_aac  the LZ4-decompressed overlays, at
              their linker-formula runtime addresses (see decompress_overlays)
  .rom_code / .nul_space  the chip maskrom, embedded from the SDK's rom.lst
              disassembly so calls into ROM resolve and Ghidra can browse it

Section sizes/addresses are read straight out of the startup copy loops
(startup.S: bss-clear, .data copy, .data_code copy). Each copy loop bakes in
  dest(runtime addr), src(file addr = vaddr in text.bin), size
as immediates; the src loads are the only immediates >= 0x1000000, which makes
them unambiguous to find. text_size = (.data source) - 0x1e00120.

If map files are given with --map, a .symtab is embedded so the disassembly is
self-documenting. Pass --map repeatedly to layer several maps (later ones
override earlier by address), e.g. the matcher output plus a hand-annotated map:
    python3 tools/rebuild_elf.py --map work/graph_map.tsv --map manual.syms

Usage:  python3 tools/rebuild_elf.py --bin app.bin --out app.rebuilt.elf
                                       [--map FILE ...] [--no-symbols]
                                       [--rom-lst FILE [--stubs FILE]]
"""
import os
import re
import struct
import argparse

from jl_sdk_utils import derive_layout, decompress_overlays, CODE_BASE, E_MACHINE_PI32

# ELF constants
from elf import SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_NOBITS, SHF_WRITE, SHF_ALLOC, SHF_EXEC, WA, AX, STT_FUNC, STB_GLOBAL;

OVERLAY_NAMES = ['.common', '.overlay_aec', '.overlay_aac']  # download.c order

# ---- maskrom: code + symbols -----------------------------------------------
# The chip's mask ROM isn't in app.bin, but the SDK ships a full disassembly of
# it (tools/rom.lst, a dump of `rom.exe`) plus a stub symbol table
# (maskrom_stubs.ld). App/overlay code calls into the ROM (e.g. memcpy, LZ4_*,
# os_*), so materializing the ROM as real sections + symbols lets objdump/Ghidra
# resolve those targets and browse the ROM itself.
_ROM_SECT = re.compile(r'^Disassembly of section (\S+):')
_ROM_BYTES = re.compile(r'^\s*([0-9a-f]{5,6}):\s*((?:[0-9a-f]{2} )+)')
_ROM_LABEL = re.compile(r'^([A-Za-z_$][\w.$]*):\s*$')
_STUB = re.compile(r'^\s*([A-Za-z_]\w*)\s*=\s*ABSOLUTE\(0x([0-9a-f]+)\)')


def load_rom_sections(lst_path):
    """Parse an objdump listing (rom.lst) into contiguous byte sections. Both
    instruction lines (`ADDR:  hexbytes  <TAB>mnemonic`) and data lines
    (`ADDR:  hexbytes   ascii`) carry `ADDR: hex-byte-run`; the run stops at the
    multi-space gap before the mnemonic/ascii column. Gaps are zero-filled."""
    sects = []                       # [(name, {addr: byte})], in file order
    bm = None
    with open(lst_path) as f:
        for ln in f:
            ms = _ROM_SECT.match(ln)
            if ms:
                bm = {}
                sects.append((ms.group(1), bm))
                continue
            if bm is None:
                continue
            mb = _ROM_BYTES.match(ln)
            if mb:
                addr = int(mb.group(1), 16)
                for i, b in enumerate(mb.group(2).split()):
                    bm[addr + i] = int(b, 16)
    out = []
    for name, bytemap in sects:
        if not bytemap:
            continue
        lo, hi = min(bytemap), max(bytemap) + 1
        data = bytearray(hi - lo)
        for a, b in bytemap.items():
            data[a - lo] = b
        flags = AX if name == '.rom_code' else SHF_ALLOC
        out.append(dict(name=name, vaddr=lo, size=len(data), data=bytes(data),
                        flags=flags, type=SHT_PROGBITS))
    return out


def load_rom_symbols(lst_path, stubs_path):
    """ROM symbols: labels from the disassembly (name above the next ADDR line)
    plus the stub table (`name = ABSOLUTE(0xADDR);`). Returns [(name, addr)]."""
    syms = []
    if lst_path and os.path.exists(lst_path):
        pending = []
        with open(lst_path) as f:
            for ln in f:
                ml = _ROM_LABEL.match(ln)
                if ml:
                    pending.append(ml.group(1))
                    continue
                mb = _ROM_BYTES.match(ln)
                if mb and pending:
                    addr = int(mb.group(1), 16)
                    syms += [(nm, addr) for nm in pending]
                    pending = []
    if stubs_path and os.path.exists(stubs_path):
        with open(stubs_path) as f:
            for ln in f:
                m = _STUB.match(ln)
                if m:
                    syms.append((m.group(1), int(m.group(2), 16)))
    return syms


# ---- symbols from the matcher output ---------------------------------------
def load_symbols(map_path):
    """Read (name, vaddr) from a map file: tab-separated `name<TAB>hexaddr[...]`
    (the matcher's graph_map.tsv format; extra columns ignored). Blank lines and
    a `name` header are skipped."""
    syms = []
    with open(map_path) as f:
        for ln in f:
            p = ln.rstrip('\n').split('\t')
            if p[0] in ('name', '') or len(p) < 2 or p[1] in ('None', ''):
                continue
            syms.append((p[0], int(p[1], 16)))
    return syms


def merge_maps(sym_lists):
    """Merge several map files into one (name, addr) list. Later files override
    earlier ones *by address*: an address named in a later file discards all
    earlier names at that address (so a hand-annotated map passed last wins),
    while multiple names at one address within a single file are kept as aliases."""
    by_addr = {}
    for syms in sym_lists:
        this = {}
        for name, addr in syms:
            this.setdefault(addr, []).append(name)
        by_addr.update(this)
    return [(n, a) for a, names in by_addr.items() for n in names]


def build_symtab(symbols, secs):
    """Build (.symtab bytes, .strtab bytes). Each symbol is placed in the section
    (by header index) whose vaddr range contains it; st_size runs to the next
    symbol in the same section (0 for the last, letting objdump run to the next
    label). Symbols outside any allocated section are dropped."""
    ranges = [(s['vaddr'], s['vaddr'] + s['size'], 1 + i)   # +1: NULL is index 0
              for i, s in enumerate(secs)
              if (s['flags'] & SHF_ALLOC) and s['size']]

    def locate(addr):
        for lo, hi, idx in ranges:
            if lo <= addr < hi:
                return idx
        return None

    placed = sorted((addr, name, idx)
                    for name, addr in symbols
                    if (idx := locate(addr)) is not None)
    strtab = bytearray(b'\0')
    syms = [b'\x00' * 16]                       # mandatory null symbol
    for j, (addr, name, idx) in enumerate(placed):
        size = (placed[j + 1][0] - addr
                if j + 1 < len(placed) and placed[j + 1][2] == idx else 0)
        noff = len(strtab)
        strtab += name.encode() + b'\0'
        info = (STB_GLOBAL << 4) | STT_FUNC
        syms.append(struct.pack('<IIIBBH', noff, addr, max(size, 0), info, 0, idx))
    return b''.join(syms), bytes(strtab), len(placed)


# ---- emit the reconstructed ELF --------------------------------------------
def build_elf(payload, secs, symbols=None):
    content_off = 0x40
    align4 = lambda x: (x + 3) & ~3
    payload_off = content_off

    # Sections carrying their own bytes (the decompressed overlays, marked by a
    # 'data' key) are appended after the raw payload; base sections index into
    # the payload by 'fileoff'.
    cur = payload_off + len(payload)
    for s in secs:
        if 'data' in s:
            s['_foff'] = align4(cur)
            cur = s['_foff'] + len(s['data'])

    sym_data = str_data = None
    if symbols:
        sym_data, str_data, _ = build_symtab(symbols, secs)

    # section-header string table
    order = [s['name'] for s in secs]
    if symbols:
        order += ['.symtab', '.strtab']
    order += ['.shstrtab']
    shstr = bytearray(b'\0')
    noff = {}
    for nm in order:
        noff[nm] = len(shstr)
        shstr += nm.encode() + b'\0'

    if symbols:
        symtab_off = align4(cur); cur = symtab_off + len(sym_data)
        strtab_off = align4(cur); cur = strtab_off + len(str_data)
    shstr_off = align4(cur); cur = shstr_off + len(shstr)
    shoff = align4(cur)

    def sec_foff(s):
        if s['type'] == SHT_NOBITS:
            return 0
        if 'data' in s:
            return s['_foff']
        return payload_off + s['fileoff']

    shdrs = [struct.pack('<10I', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]   # NULL
    for s in secs:
        shdrs.append(struct.pack('<10I', noff[s['name']], s['type'], s['flags'],
                                 s['vaddr'], sec_foff(s), s['size'], 0, 0, 4, 0))
    if symbols:
        strtab_idx = len(shdrs) + 1              # .symtab, then .strtab
        shdrs.append(struct.pack('<10I', noff['.symtab'], SHT_SYMTAB, 0, 0,
                                 symtab_off, len(sym_data), strtab_idx, 1, 4, 16))
        shdrs.append(struct.pack('<10I', noff['.strtab'], SHT_STRTAB, 0, 0,
                                 strtab_off, len(str_data), 0, 0, 1, 0))
    shstr_idx = len(shdrs)
    shdrs.append(struct.pack('<10I', noff['.shstrtab'], SHT_STRTAB, 0, 0,
                             shstr_off, len(shstr), 0, 0, 1, 0))

    ehdr = (b'\x7fELF\x01\x01\x01' + b'\0' * 9 +
            struct.pack('<HHIIIIIHHHHHH', 2, E_MACHINE_PI32, 1, CODE_BASE,
                        0, shoff, 0, 52, 0, 0, 40, len(shdrs), shstr_idx))

    out = bytearray(ehdr)
    out += b'\0' * (payload_off - len(out)); out += payload
    for s in secs:
        if 'data' in s:
            out += b'\0' * (s['_foff'] - len(out)); out += s['data']
    if symbols:
        out += b'\0' * (symtab_off - len(out)); out += sym_data
        out += b'\0' * (strtab_off - len(out)); out += str_data
    out += b'\0' * (shstr_off - len(out)); out += shstr
    out += b'\0' * (shoff - len(out))
    for sh in shdrs:
        out += sh
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bin', required=True,
                    help='raw flattened app.bin (the reconstructor input)')
    ap.add_argument('--out', required=True,
                    help='reconstructed multi-section ELF (the matcher input)')
    ap.add_argument('--map', action='append', metavar='FILE',
                    help='map file(s) to import symbols from (name<TAB>hexaddr); '
                    'repeatable, later files override earlier by address. '
                    'No default: without --map there are no symbols to embed.')
    ap.add_argument('--no-symbols', action='store_true',
                    help='emit a symbol-free ELF even if a map exists')
    ap.add_argument('--rom-lst',
                    help='maskrom disassembly listing (rom.lst) to embed; '
                         'omit to skip the maskrom code/symbols')
    ap.add_argument('--stubs',
                    help='maskrom stub symbol table (maskrom_stubs.ld); '
                         'only used with --rom-lst')
    args = ap.parse_args()

    payload = open(args.bin, 'rb').read()
    secs = derive_layout(payload)
    secs += decompress_overlays(payload, secs, OVERLAY_NAMES)

    rom_syms = []
    if args.rom_lst:
        rsecs = load_rom_sections(args.rom_lst)
        secs += rsecs
        rom_syms = load_rom_symbols(args.rom_lst, args.stubs)
        print(f"maskrom: {len(rsecs)} section(s) "
              f"({', '.join(s['name'] for s in rsecs)}), {len(rom_syms)} symbols")

    maps = args.map or []
    symbols = None
    if not args.no_symbols:
        loaded = [(p, load_symbols(p)) for p in maps if os.path.exists(p)]
        layers = ([rom_syms] if rom_syms else []) + [s for _, s in loaded]
        if layers:
            symbols = merge_maps(layers)      # ROM first: a --map can override it
            for p, s in loaded:
                print(f"symbols: {len(s):>5} from {p}")
            print(f"symbols: {len(symbols):>5} merged (unique aliases)")

    print(f"payload (app.bin): {len(payload):#x} bytes (from {args.bin})")
    print(f"\n{'section':<14} {'vaddr':>10} {'file_off':>10} {'size':>10}  flags")
    for s in secs:
        fl = ''.join(c for c, b in (('A', s['flags'] & SHF_ALLOC),
                                    ('W', s['flags'] & SHF_WRITE),
                                    ('X', s['flags'] & SHF_EXEC)) if b) or '-'
        t = ('NOBITS' if s['type'] == SHT_NOBITS
             else 'embedded' if 'data' in s else '')
        fo = 'appended' if 'data' in s else f"{s['fileoff']:#x}"
        print(f"{s['name']:<14} {s['vaddr']:>#10x} {fo:>10} "
              f"{s['size']:>#10x}  {fl} {t}")

    elf = build_elf(payload, secs, symbols)
    with open(args.out, 'wb') as f:
        f.write(elf)
    print(f"\nwrote {args.out}  ({len(elf):#x} bytes"
          f"{', ' + str(len(symbols)) + ' symbols' if symbols else ''})")


if __name__ == '__main__':
    main()
