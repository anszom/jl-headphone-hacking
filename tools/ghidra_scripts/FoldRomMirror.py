#@category JieLi
#@keybinding
#@menupath Tools.JieLi.Fold ROM Mirror References
#@toolbar
# Redirect ROM-mirror call/branch/data references to the canonical maskrom.
#
# On pi32v2 the maskrom is mirrored every 2**25 bytes (the address decoder
# ignores bit 25+). `call` is PC-relative with a signed field reaching only
# +/-16 MB, so far XIP .text (based at 0x1e00000) cannot encode a backward jump
# to ROM at 0x10ffd4; the linker instead targets the reachable forward mirror at
# ROM+2**25 (e.g. 0x210ffd4). objdump/Ghidra print that literal architectural
# target, so the reference lands on an undefined mirror address with no symbol.
#
# This script folds every reference whose target sits in a mirror band back onto
# the canonical ROM address, so calls resolve to the real ROM function name and
# the XREF appears on the real function. The canonical ROM extent is taken from
# the program's own maskrom blocks -- the .rom_code / .nul_space blocks
# rebuild_elf.py emits (see ROM_BLOCK_PREFIXES) -- so there are no manual
# constants to keep in sync. Only targets that fold *into* one of those blocks
# are touched.
#
# IMPORTANT: scope is the maskrom ONLY, not every low block. .text, .common,
# .data_code and the overlays also sit below the 2**25 period but have their own
# addressing and must NOT be rewritten -- matching them by "executable and low"
# folds ~everything (1600+ refs). Hence the explicit block-name allowlist.
#
# Run after auto-analysis (Script Manager, or assign a keybinding above).

from ghidra.program.model.symbol import SourceType

ALIAS = 0x2000000       # maskrom image repeats every 2**25 bytes

# maskrom image blocks to fold mirror refs onto (as named by rebuild_elf.py).
# Edit if your import names the ROM differently -- the script prints what it
# picked so you can confirm.
ROM_BLOCK_PREFIXES = ('.rom', '.nul')

space  = currentProgram.getAddressFactory().getDefaultAddressSpace()
refMgr = currentProgram.getReferenceManager()
mem    = currentProgram.getMemory()


def rom_ranges():
    """[(start, end)] of the canonical maskrom blocks (by name) that live below
    one alias period -- the image the mirrors alias onto."""
    out = []
    for b in mem.getBlocks():
        if (b.getName().startswith(ROM_BLOCK_PREFIXES)
                and b.getStart().getOffset() < ALIAS):
            out.append((b.getStart().getOffset(),
                        b.getStart().getOffset() + b.getSize()))
    return out


def canon(off, roms):
    """Fold a mirror offset down by whole alias periods; return the canonical
    ROM offset if it lands inside a ROM block, else None."""
    while off >= ALIAS:
        off -= ALIAS
        for lo, hi in roms:
            if lo <= off < hi:
                return off
    return None


roms = rom_ranges()
if not roms:
    print("no maskrom block %s found -- nothing to fold "
          "(adjust ROM_BLOCK_PREFIXES)" % (ROM_BLOCK_PREFIXES,))
else:
    print("canonical ROM: " +
          ", ".join("%#x-%#x" % (lo, hi) for lo, hi in roms))

    # collect first; don't mutate the reference table while iterating it
    todo = []
    it = refMgr.getReferenceIterator(currentProgram.getMinAddress())
    while it.hasNext():
        ref = it.next()
        to = ref.getToAddress()
        if to is None or not to.isMemoryAddress():
            continue
        tgt = canon(to.getOffset(), roms)
        if tgt is not None:
            todo.append((ref, tgt))

    for ref, tgt in todo:
        new = refMgr.addMemoryReference(
            ref.getFromAddress(), space.getAddress(tgt),
            ref.getReferenceType(), SourceType.USER_DEFINED,
            ref.getOperandIndex())
        refMgr.setPrimary(new, True)
        refMgr.delete(ref)

    print("redirected %d mirror reference(s) -> canonical ROM" % len(todo))
