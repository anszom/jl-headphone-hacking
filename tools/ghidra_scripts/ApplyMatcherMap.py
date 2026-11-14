#@category JieLi
#@keybinding
#@menupath Tools.JieLi.Apply Matcher Map
#@toolbar
# Apply the matcher's graph_map.tsv names onto the already-open program, so you
# can pull in freshly-resolved names after an SDK rebuild + re-match WITHOUT
# re-importing the ELF (which would throw away your analysis / manual edits).
#
# For each `name<TAB>0xADDR<TAB>via` row the script renames the function at ADDR
# only when its current name is auto-generated (default `FUN_*` / thunk / none).
# Anything you renamed by hand (USER_DEFINED, non-default) is left untouched, so
# it is safe to re-run after every re-match. Where no function exists at ADDR yet
# one is created (set CREATE_MISSING = False to only touch existing functions).
#
# Run from the Script Manager (category "JieLi") with your program open.

from ghidra.program.model.symbol import SourceType
import os

# Point at the matcher's authoritative map. Override via the GHIDRA_MATCHER_MAP
# env var if your checkout lives elsewhere.
MAP = os.environ.get(
    "GHIDRA_MATCHER_MAP",
    os.path.expanduser("~/Dev/jl/jl-uboot-tool/.match-cache/graph_map.tsv"))

# Create a function when none exists at the target address.
CREATE_MISSING = True


def is_auto_name(cur, src):
    """True if `cur` is a Ghidra-default name we're allowed to overwrite."""
    if src != SourceType.USER_DEFINED:
        return True                      # DEFAULT / ANALYSIS / IMPORTED
    return (cur.startswith("FUN_") or cur.startswith("thunk_FUN_")
            or cur.startswith("SUB_") or cur.startswith("LAB_"))


def run():
    fm = currentProgram.getFunctionManager()
    space = currentProgram.getAddressFactory().getDefaultAddressSpace()

    renamed = created = skipped_manual = unchanged = missing = 0
    with open(MAP) as f:
        header = f.readline()            # discard `name  app_entry  via`
        for line in f:
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            name = parts[0].strip()
            addr_s = parts[1].strip()
            if not name or not addr_s:
                continue
            addr = space.getAddress(int(addr_s, 16))

            fn = fm.getFunctionAt(addr)
            if fn is None:
                if not CREATE_MISSING:
                    missing += 1
                    continue
                fn = createFunction(addr, name)
                if fn is None:
                    missing += 1
                else:
                    created += 1
                continue

            cur = fn.getName()
            src = fn.getSymbol().getSource()
            if not is_auto_name(cur, src):
                skipped_manual += 1
                continue
            if cur == name:
                unchanged += 1
                continue
            fn.setName(name, SourceType.IMPORTED)
            renamed += 1

    print("ApplyMatcherMap: renamed=%d created=%d skipped_manual=%d "
          "unchanged=%d missing=%d  (map=%s)"
          % (renamed, created, skipped_manual, unchanged, missing, MAP))


run()
