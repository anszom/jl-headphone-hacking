import lz4.block as lz4
import struct
from elf import SHT_PROGBITS, SHT_NOBITS, SHF_ALLOC, WA, AX

CODE_BASE = 0x1e00120        # entry / .text vaddr (== ORIGIN(code0))
E_MACHINE_PI32 = 0xf1

# ---- extract layout from fixed startup instruction slots -------------------
# The startup routine (driver/cpu/br36/startup.S) is instruction-identical
# across builds, so each `rN = imm32` load sits at a fixed offset from
# text_begin (0x1e00120). Each such load is 6 bytes: `cX ff <imm32-LE>`, so the
# 32-bit immediate is at (instruction_offset + 2). Offsets below are app.bin
# file offsets (== vaddr - CODE_BASE). See sdk.lst @ text_begin.
IMM_SLOTS = {
    'bss_dest':        0x12,   # r3 = system_bss_start   @1e00130
    'bss_size':        0x1a,   # r2 = report_bss_size    @1e00138
    'data_dest':       0x28,   # r4 = .data runtime addr @1e00146
    'data_src':        0x2e,   # r1 = text_end (= .data file addr) @1e0014c
    'data_size':       0x34,   # r2 = report_data_size   @1e00152
    'data_code_dest':  0x44,   # r4 = .data_code runtime @1e00162
    'data_code_src':   0x4a,   # r1 = data_code_begin    @1e00168
    'data_code_size':  0x50,   # r2 = report_data_code_size @1e0016e
}

def imm32(payload, imm_off):
    """Read the imm32 of a `cX ff <imm32-LE>` load; verify the opcode so a
    divergent startup fails loudly rather than silently mis-sectioning."""
    op, b1 = payload[imm_off - 2], payload[imm_off - 1]
    if (op & 0xf0) != 0xc0 or b1 != 0xff:
        raise SystemExit(
            f"bytes at offset {imm_off - 2:#x} don't match expected startup.S sequence, see IMM_SLOTS.\n"
            f"    expected `cX ff imm32` load\n"
            f"    got {op:02x} {b1:02x}")
    return struct.unpack_from('<I', payload, imm_off)[0]

def derive_layout(payload):
    """Read section sizes/addresses from the fixed startup slots and return the
    section list. text_size = (.data source addr) - CODE_BASE."""
    v = {k: imm32(payload, off) for k, off in IMM_SLOTS.items()}
    text_size = v['data_src'] - CODE_BASE
    secs = [
        dict(name='.text', vaddr=CODE_BASE, fileoff=0, size=text_size,
             flags=AX, type=SHT_PROGBITS),
        dict(name='.data', vaddr=v['data_dest'], fileoff=v['data_src'] - CODE_BASE,
             size=v['data_size'], flags=WA, type=SHT_PROGBITS),
        dict(name='.data_code', vaddr=v['data_code_dest'],
             fileoff=v['data_code_src'] - CODE_BASE, size=v['data_code_size'],
             flags=AX, type=SHT_PROGBITS),
        dict(name='.bss', vaddr=v['bss_dest'], fileoff=0, size=v['bss_size'],
             flags=WA, type=SHT_NOBITS),
    ]
    # The whole app.bin is XIP-mapped at CODE_BASE (app.bin[0] == .text @ CODE_BASE;
    # the startup copy loops read .data/.data_code from CODE_BASE+fileoff). The
    # compressed bank blob is likewise mapped there — the bank loader reads packet
    # data straight from it — so it's ALLOC and lives at CODE_BASE + its file off.
    bank_off = (v['data_code_src'] - CODE_BASE) + v['data_code_size']
    if bank_off < len(payload):
        secs.append(dict(name='.bank_lz4', vaddr=CODE_BASE + bank_off,
                         fileoff=bank_off, size=len(payload) - bank_off,
                         flags=SHF_ALLOC, type=SHT_PROGBITS))
    return secs


# ---- decompress the lz4_packet overlays ------------------------------------
# The bank region is an `lz4_packet` blob (tools/lz4_packet, dict=text.bin). Its
# header is a table of 24-byte entries, one per packed input file *in the order
# tools/download.c passes them*: common.bin, aec.bin, aac.bin, then bank0..20.
# Each entry is 6 little-endian u32 (field roles confirmed from the on-device
# bank loader's disassembly — it reads exactly these to set up the decompress):
#     [0] dict_offset  (into .text; the dict for THIS block is a window here)
#     [1] dict_size    (== 0x10000: a per-entry 64 KB window, NOT the whole text)
#     [2] run_addr     (0 here; the build script passes 0, so it's unused)
#     [3] file_offset  (of the LZ4 block within the bank region)
#     [4] compressed_size   [5] uncompressed_size
# The number of entries = entry[0].file_offset / 24 (data starts after the table).
# Each block is a raw LZ4 block decompressed against text[dict_off:dict_off+dict_size]
# as the dictionary. IMPORTANT: the window is per-entry and generally NOT the last
# 64 KB of .text, so the FULL text as dict (lz4 would take its last 64 KB) is wrong.
ENTRY = struct.Struct('<6I')       # dict_off, dict_size, run, off, csz, usz


def parse_packet(bank):
    """Parse the lz4_packet header. Returns [(dict_off, dict_size, run, off, csz,
    usz)] per entry, or [] if `bank` doesn't look like a packet (bad table
    length)."""
    if len(bank) < ENTRY.size:
        return []
    first_off = struct.unpack_from('<I', bank, 12)[0]
    if first_off < ENTRY.size or first_off % ENTRY.size or first_off > len(bank):
        return []
    return [ENTRY.unpack_from(bank, k * ENTRY.size)
            for k in range(first_off // ENTRY.size)]


def decompress_overlays(payload, secs, names=[]):
    """Decompress the .bank_lz4 region into overlay sections placed at their
    linker-formula runtime addresses (sdk_ld.c):
        .data_code (ALIGN 32) -> .common (ALIGN 32) -> overlay region (ALIGN 4),
    where .overlay_aec and .overlay_aac share one run address (an OVERLAY: they
    are mutually exclusive at runtime, so they overlap here too).
    Returns a list of section dicts, each carrying its decompressed bytes in
    'data'. Empty entries (the disabled code banks) are skipped."""
    bank_sec = next((s for s in secs if s['name'] == '.bank_lz4'), None)
    if bank_sec is None:
        return []

    text = next(s for s in secs if s['name'] == '.text')
    dc = next(s for s in secs if s['name'] == '.data_code')
    text_bin = payload[:text['size']]
    bank = payload[bank_sec['fileoff']:bank_sec['fileoff'] + bank_sec['size']]

    a32 = lambda x: (x + 31) & ~31
    a4 = lambda x: (x + 3) & ~3
    common_addr = a32(dc['vaddr'] + dc['size'])
    overlay_base = a4(common_addr)      # refined once .common size is known

    out = []
    for k, (dict_off, dict_size, run, off, csz, usz) in enumerate(parse_packet(bank)):
        if csz == 0 or usz == 0:
            continue                    # empty overlay / disabled bank
        # dict = a per-entry window into .text (Python slice clamps if it runs off)
        win = text_bin[dict_off:dict_off + dict_size]
        data = lz4.decompress(bank[off:off + csz], uncompressed_size=usz,
                               dict=win)
        name = (names[k] if k < len(names)
                else f'.overlay_bank{k - len(names)}')
        if name == '.common':
            vaddr = common_addr
            overlay_base = a4(common_addr + len(data))
        else:
            vaddr = overlay_base        # aec/aac (and banks) share the region
        out.append(dict(name=name, vaddr=vaddr, size=len(data), data=data,
                        flags=AX, type=SHT_PROGBITS))
    return out
