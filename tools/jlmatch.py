#!/usr/bin/env python3
"""Match sdk.elf .text functions against the device app.elf.

Reverse-engineering / matching-build tool: given a fully-symbolized SDK build
(sdk.elf) and the stripped device image (app.elf, = app.bin force-fit into one
.text at vaddr=off+0x1e00000), report which sdk functions appear in app.elf's
uncompressed text.bin region, byte-identical modulo relocation.

Reference side (sdk.elf): function boundaries from the symbol table.
Target side  (app.elf):  one long normalized instruction stream; each sdk
function's normalized instruction sequence is searched as a contiguous run.

Only sdk `.text` funcs are considered (they live in app.bin's uncompressed
text.bin). Overlay/bank code is LZ4-compressed in app.bin and not matchable here.

Usage:
    python3 tools/jlmatch.py --sdk X --app Y --objdump Z --workdir DIR
Importable: `from jlmatch import Matcher, norm`.
"""
import os
import re
import sys
import argparse
import subprocess
import collections
from typing import NamedTuple, Optional

# --- normalization tunables --------------------------------------------------
ADDR_IMM = 0x1000        # a `= N` load with |N| >= this is treated as an address
MIN_INSNS = 4            # functions shorter than this are flagged (weak signal)
SEED_MAX_FREQ = 4000     # don't seed candidate search on tokens more common than
MAX_CANDIDATES = 200     # cap candidate windows scored per function (fuzzy)

# --- objdump text parsing ----------------------------------------------------
# " 1e00120:    ee ff 50 13 00 00   \tsp = 4944"  (bytes are space-padded then TAB)
_LINE = re.compile(r'^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2} )+)\s*\t(.*)$')
_COMMENT = re.compile(r'\s*<[^>]*>')      # objdump resolved-target comment (derived)


def _mask_imm(m):
    v = int(m.group(1))
    return '= I' if abs(v) >= ADDR_IMM else m.group(0)


def norm(mn: str) -> str:
    """Normalize one instruction's mnemonic text so that code differing only by
    relocation compares equal. Symmetric between symbolized sdk.elf and stripped
    app.elf (does NOT depend on comment presence, which app.elf lacks for data).

      - drop the ` <...>` resolved-target comment
      - `call <disp>`        -> masked (inter-function, caller-position dependent)
      - `rN = <imm>`, |imm|>=ADDR_IMM -> masked (address-sized literal)

    Kept (stable across identical builds): mnemonic, registers, small literals,
    memory offsets `[rN+off]`, add-immediates `+ N`, intra-function relative
    branch offsets (`goto -N`, `if(..)goto N`).
    """
    mn = _COMMENT.sub('', mn).strip()
    mn = re.sub(r'\bcall\s+-?\d+', 'call T', mn)
    mn = re.sub(r'=\s*(-?\d+)', _mask_imm, mn)
    return mn


class Insns(NamedTuple):
    addr: list      # int vaddr per instruction
    norm: list      # normalized mnemonic per instruction
    raw: list       # raw hex byte string per instruction (no spaces)


def parse_insns(path: str) -> Insns:
    addr, nrm, raw = [], [], []
    with open(path) as f:
        for ln in f:
            m = _LINE.match(ln)
            if not m:
                continue
            addr.append(int(m.group(1), 16))
            raw.append(m.group(2).replace(' ', ''))
            nrm.append(norm(m.group(3)))
    return Insns(addr, nrm, raw)


# sdk code lives in .text plus the RAM-resident / overlay code sections. The
# device image carries the latter LZ4-compressed; rebuild_elf.py decompresses
# them into matching sections, so we consider their functions too (else the ~120
# overlay/common funcs are unmatchable — they'd look "absent").
CODE_SECTIONS = ('.text', '.common', '.data_code',
                 '.overlay_aec', '.overlay_aac')


def load_sdk_funcs(syms_path: str, sections=CODE_SECTIONS):
    """Return [(name, vaddr, size)] for every `F <sec>` symbol (sec in
    `sections`) with size>0."""
    secset = set(sections)
    funcs = []
    with open(syms_path) as f:
        for ln in f:
            if ' F ' not in ln:
                continue
            parts = ln.split()
            fi = parts.index('F')
            if fi + 2 >= len(parts) or parts[fi + 1] not in secset:
                continue
            val = int(parts[0], 16)
            size = int(parts[fi + 2], 16)
            name = parts[fi + 3] if len(parts) > fi + 3 else '?'
            if size > 0:
                funcs.append((name, val, size))
    return funcs


def gen_dump(objdump: str, elf: str, out: str, flag: str) -> str:
    """Run `objdump <flag> elf > out`, cached on mtime. flag: '-d' or '-t'."""
    if (os.path.exists(out) and os.path.getmtime(out) >= os.path.getmtime(elf)):
        return out
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w') as fh:
        subprocess.run([objdump, flag, elf], stdout=fh,
                       stderr=subprocess.DEVNULL, check=True)
    return out


class Result(NamedTuple):
    name: str
    sdk_vaddr: int
    ninsns: int
    nhits: int
    app_vaddr: Optional[int]
    raw_ident: bool


class Matcher:
    def __init__(self, sdk: Insns, app: Insns, funcs):
        self.sdk = sdk
        self.app = app
        self.funcs = funcs
        self.sdk_idx = {a: i for i, a in enumerate(sdk.addr)}
        self.app_tokpos = collections.defaultdict(list)
        for i, t in enumerate(app.norm):
            self.app_tokpos[t].append(i)
        self.tokfreq = {t: len(v) for t, v in self.app_tokpos.items()}

    @classmethod
    def from_paths(cls, sdk_elf, app_elf, objdump, workdir, verbose=True):
        def say(*a):
            if verbose:
                print(*a, file=sys.stderr)
        say("generating/caching objdump dumps...")
        sdk_asm = gen_dump(objdump, sdk_elf, os.path.join(workdir, "sdk.asm"), '-d')
        sdk_sym = gen_dump(objdump, sdk_elf, os.path.join(workdir, "sdk.syms"), '-t')
        app_asm = gen_dump(objdump, app_elf, os.path.join(workdir, "app.asm"), '-d')
        say("parsing app.elf...")
        app = parse_insns(app_asm)
        say(f"  {len(app.addr)} app instructions")
        say("parsing sdk.elf...")
        sdk = parse_insns(sdk_asm)
        funcs = load_sdk_funcs(sdk_sym)
        say(f"  {len(sdk.addr)} sdk instructions, {len(funcs)} .text funcs")
        return cls(sdk, app, funcs)

    def sdk_func_insns(self, vaddr, size):
        """Instruction indices covering the sdk function [vaddr, vaddr+size)."""
        i = self.sdk_idx.get(vaddr)
        if i is None:
            return None
        end = vaddr + size
        js = []
        while i < len(self.sdk.addr) and self.sdk.addr[i] < end:
            js.append(i)
            i += 1
        return js

    def find_run(self, seq):
        """App positions where `seq` (list of normalized instrs) occurs
        contiguously. Seeds on the rarest of the first few tokens."""
        n = len(seq)
        if n == 0:
            return []
        best_k, best_f = 0, None
        for k in range(min(6, n)):
            f = self.tokfreq.get(seq[k], 0)
            if f == 0:
                return []          # a token absent from app -> impossible
            if best_f is None or f < best_f:
                best_f, best_k = f, k
        hits = []
        an = self.app.norm
        for p in self.app_tokpos[seq[best_k]]:
            s = p - best_k
            if s < 0 or s + n > len(an):
                continue
            if an[s:s + n] == seq:
                hits.append(s)
        return hits

    def match_all(self):
        results, stats = [], collections.Counter()
        for name, vaddr, size in self.funcs:
            js = self.sdk_func_insns(vaddr, size)
            if not js:
                stats['no_disasm'] += 1
                continue
            seq = [self.sdk.norm[j] for j in js]
            ni = len(seq)
            if ni < MIN_INSNS:
                stats['too_short'] += 1
            hits = self.find_run(seq)
            app_vaddr = self.app.addr[hits[0]] if hits else None
            raw = False
            if len(hits) == 1:
                raw = all(self.app.raw[hits[0] + k] == self.sdk.raw[js[k]]
                          for k in range(ni))
            results.append(Result(name, vaddr, ni, len(hits), app_vaddr, raw))
            if not hits:
                stats['nomatch'] += 1
            elif len(hits) == 1:
                stats['unique'] += 1
                stats['unique_insns'] += ni
                if raw:
                    stats['unique_rawident'] += 1
            else:
                stats['ambiguous'] += 1
        return results, stats


def report(results, stats):
    total = len(results) + stats['no_disasm']
    uniq = stats['unique']
    matched = [r.app_vaddr for r in results if r.nhits == 1 and r.app_vaddr is not None]
    tot_insns = sum(r.ninsns for r in results)
    print("\n==================== BASELINE MATCH ====================")
    print(f"sdk .text functions:      {total}")
    print(f"  unique match in app:    {uniq}  ({100*uniq/total:.1f}%)")
    print(f"    of which raw-byte-id:  {stats['unique_rawident']}")
    print(f"  ambiguous (>1 hit):     {stats['ambiguous']}")
    print(f"  no match:               {stats['nomatch']}")
    print(f"  too short (<{MIN_INSNS} insn):    {stats['too_short']}")
    if matched:
        print(f"\nunique-match app vaddr span: {min(matched):#x} .. {max(matched):#x}")
        print("  (estimates text.bin code extent)")
    if tot_insns:
        print(f"\ninstruction coverage (unique matches): "
              f"{stats['unique_insns']}/{tot_insns} = "
              f"{100*stats['unique_insns']/tot_insns:.1f}%")


def write_tsv(results, path):
    with open(path, "w") as f:
        f.write("name\tsdk_vaddr\tninsns\tnhits\tapp_vaddr\traw_ident\n")
        for r in sorted(results, key=lambda r: r.sdk_vaddr):
            av = 'None' if r.app_vaddr is None else hex(r.app_vaddr)
            f.write(f"{r.name}\t{r.sdk_vaddr:#x}\t{r.ninsns}\t{r.nhits}\t{av}\t{int(r.raw_ident)}\n")
    print(f"\nfull table -> {path}")


def build_argparser():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--sdk", required=True, help="symbolized SDK build ELF")
    p.add_argument("--app", required=True, help="device image ELF")
    p.add_argument("--objdump", required=True, help="pi32v2 objdump")
    p.add_argument("--workdir", required=True, help="dump cache dir")
    return p


def main():
    args = build_argparser().parse_args()
    m = Matcher.from_paths(args.sdk, args.app, args.objdump, args.workdir)
    results, stats = m.match_all()
    report(results, stats)
    write_tsv(results, os.path.join(args.workdir, "match_report.tsv"))


if __name__ == "__main__":
    main()
