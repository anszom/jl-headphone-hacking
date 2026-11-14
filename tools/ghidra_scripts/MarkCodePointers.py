# Scan the whole program for 4-byte-aligned words that look like code pointers
# (little-endian values in [0x01e00000, 0x01e70000)) located in currently
# undefined ("unexplored") bytes, and convert each such word into a pointer.
#
# Rationale: this firmware's ELF has only a bare .text header, so pointer tables
# were disassembled as bogus code / left undefined. .text lives at
# vaddr = file_offset + 0x1e00000 spanning ~0x1e00120..0x1e76467, so any word
# holding a value in the code range is almost certainly a code pointer.
#
#@category JL
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.data import PointerDataType

# Code-pointer value window (adjust HIGH if .text grows past this).
LOW = 0x01e00000
HIGH = 0x01e70000

mem = currentProgram.getMemory()
listing = currentProgram.getListing()
ptr = PointerDataType.getPointer(None, 4)  # untyped 4-byte pointer

created = 0
scanned = 0
skipped = 0

for block in mem.getBlocks():
    if not block.isInitialized():
        continue

    start = block.getStart()
    end = block.getEnd()

    # Align the starting address up to a 4-byte boundary.
    rem = start.getOffset() % 4
    addr = start if rem == 0 else start.add(4 - rem)

    while addr.compareTo(end) <= 0:
        if monitor.isCancelled():
            break

        # Need a full 4-byte word inside the block.
        try:
            last = addr.add(3)
        except:
            break
        if last.compareTo(end) > 0:
            break

        # Only touch bytes that are currently undefined ("unexplored"):
        # no instruction and no defined data over the whole word.
        if listing.isUndefined(addr, last):
            try:
                val = mem.getInt(addr) & 0xffffffff  # program endianness (LE)
                if LOW <= val < HIGH:
                    listing.createData(addr, ptr)
                    created += 1
            except:
                # createData conflict / read error -> just skip this word.
                skipped += 1
        scanned += 1

        try:
            addr = addr.add(4)
        except:
            break

print("MarkCodePointers: scanned %d undefined-aligned words, created %d pointers (%d skipped)"
      % (scanned, created, skipped))
