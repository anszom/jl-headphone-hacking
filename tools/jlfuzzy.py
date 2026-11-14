#!/usr/bin/env python3
"""Fuzzy matcher: find each sdk .text function in app.elf even when it differs by
struct-member offsets, sizeof strides, or minor inlining.

Struct accesses come from prebuilt libraries whose layout we can't change, so
byte-matching is impossible. Instead we normalize away the things that
legitimately drift and score by similarity:

  coarse normalization = fine norm (jlmatch.norm) PLUS
    - memory-access offsets   [rN+NN] -> [rN+#]   (struct member offsets)
    - register add/sub imm    rX + NN -> rX + #    (sizeof strides)
  KEPT for discrimination: mnemonics, registers, control-flow shape, branch
  distances, shifts/masks, small constant loads.

Candidate generation: k-gram (k=4) index over app coarse tokens, voting on
window starts. Each candidate window is scored by difflib ratio on coarse
tokens. A match is CONFIDENT when best ratio is high AND clears the runner-up by
a margin (uniqueness).

Usage: python3 tools/jlfuzzy.py [--min-ratio 0.90] [--margin 0.04] [std args]
Writes fuzzy_map.tsv (name, sdk_vaddr, app_vaddr, ratio, margin, exact, tier).
"""
import os
import re
import sys
import difflib
import argparse
import collections

import jlmatch
from jlmatch import Matcher

K = 4                    # k-gram size for candidate seeding
TOP_CANDIDATES = 24      # windows scored with difflib per function

# --- coarse normalization ----------------------------------------------------
_MEMOFF = re.compile(r'(\[[a-z][a-z0-9_]*)\+\d+\]')     # [r7+852] / b[r6+6]
_ADDIMM = re.compile(r'(\br\d+ [+\-] )\d+')             # r6 + 140 / r4 - 8
_OPEQIMM = re.compile(r'(\br\d+ [+\-]= )\d+')           # r3 += 30


def coarsen(fine: str) -> str:
    s = _MEMOFF.sub(r'\1+#]', fine)
    s = _ADDIMM.sub(r'\1#', s)
    s = _OPEQIMM.sub(r'\1#', s)
    return s


def coarse_list(norm_list):
    return [coarsen(x) for x in norm_list]


def kgrams(seq, k=K):
    for i in range(len(seq) - k + 1):
        yield i, tuple(seq[i:i + k])


class Fuzzy:
    def __init__(self, m: Matcher):
        self.m = m
        self.a_coarse = coarse_list(m.app.norm)
        self.s_coarse = coarse_list(m.sdk.norm)
        # k-gram -> app start positions (candidate seeding)
        self.index = collections.defaultdict(list)
        for i, g in kgrams(self.a_coarse):
            self.index[g].append(i)
        # coarse single-token -> app positions (fallback for short funcs)
        self.tokpos = collections.defaultdict(list)
        for i, t in enumerate(self.a_coarse):
            self.tokpos[t].append(i)

    def sdk_coarse_seq(self, js):
        return [self.s_coarse[j] for j in js]

    def candidates(self, cseq):
        """Vote window starts from shared k-grams; return best-voted starts."""
        n = len(cseq)
        grams = list(kgrams(cseq))
        votes = collections.Counter()
        if grams:
            for off, g in grams:
                for p in self.index.get(g, ()):
                    s = p - off
                    if 0 <= s <= len(self.a_coarse) - n:
                        votes[s] += 1
        else:                                   # func shorter than K: use tokens
            for off, t in enumerate(cseq):
                positions = self.tokpos.get(t, ())
                if len(positions) > jlmatch.SEED_MAX_FREQ:
                    continue                    # too common to seed on
                for p in positions:
                    s = p - off
                    if 0 <= s <= len(self.a_coarse) - n:
                        votes[s] += 1
        return [s for s, _ in votes.most_common(TOP_CANDIDATES)]

    def scored_candidates(self, js):
        """Return sorted [(coarse_ratio, fine_ratio, app_start)] for a sdk func,
        best first. Shared by the plain and call-graph matchers."""
        cseq = self.sdk_coarse_seq(js)
        fseq = [self.m.sdk.norm[j] for j in js]
        n = len(cseq)
        cands = self.candidates(cseq)
        if not cands:
            return []
        cm = difflib.SequenceMatcher(autojunk=False); cm.set_seq2(cseq)
        fm = difflib.SequenceMatcher(autojunk=False); fm.set_seq2(fseq)
        scored = []
        for s in cands:
            cm.set_seq1(self.a_coarse[s:s + n])
            fm.set_seq1(self.m.app.norm[s:s + n])
            scored.append((cm.ratio(), fm.ratio(), s))
        scored.sort(reverse=True)
        return scored

    def match(self, js):
        """Return (best_start, coarse_ratio, margin) for a sdk function.

        Rank candidates lexicographically by (coarse_ratio, fine_ratio): coarse
        finds the function despite offset drift; the fine (unmasked) ratio breaks
        ties so tiny leaf stubs that collapse under coarsening (e.g. gpio/usb
        register writers, identical but for a masked port address) still resolve
        to their true location. Margin is on coarse ratio, or on fine ratio when
        the top candidates tie on coarse."""
        scored = self.scored_candidates(js)
        if not scored:
            return None, 0.0, 0.0
        best_c, best_f, best_s = scored[0]
        if len(scored) > 1:
            sec_c, sec_f, _ = scored[1]
            margin = (best_c - sec_c) if abs(best_c - sec_c) > 1e-9 \
                else (best_f - sec_f)
        else:
            margin = best_c
        return best_s, best_c, margin


def main():
    ap = jlmatch.build_argparser()
    ap.add_argument("--min-ratio", type=float, default=0.90)
    ap.add_argument("--margin", type=float, default=0.04)
    args = ap.parse_args()
    m = Matcher.from_paths(args.sdk, args.app, args.objdump, args.workdir)
    fz = Fuzzy(m)

    rows = []
    tiers = collections.Counter()
    for name, vaddr, size in m.funcs:
        js = m.sdk_func_insns(vaddr, size)
        if not js:
            tiers['no_disasm'] += 1
            continue
        exact = len(m.find_run([m.sdk.norm[j] for j in js])) == 1
        s, r, mg = fz.match(js)
        app_vaddr = m.app.addr[s] if s is not None else None
        if exact:
            tier = 'exact'
        elif r >= args.min_ratio and mg >= args.margin:
            tier = 'confident'
        elif r >= args.min_ratio:
            tier = 'ambiguous'      # good match but not unique
        elif r >= 0.60:
            tier = 'weak'
        else:
            tier = 'none'
        tiers[tier] += 1
        rows.append((name, vaddr, app_vaddr, r, mg, int(exact), tier))

    total = sum(tiers.values())
    print("\n==================== FUZZY MATCH ====================")
    for t in ['exact', 'confident', 'ambiguous', 'weak', 'none', 'no_disasm']:
        if tiers[t]:
            print(f"  {t:12s} {tiers[t]:5d}  ({100*tiers[t]/total:.1f}%)")
    ported = tiers['exact'] + tiers['confident']
    print(f"  {'-'*30}")
    print(f"  portable (exact+confident): {ported}  ({100*ported/total:.1f}%)")
    print(f"  (+{tiers['ambiguous']} good-but-ambiguous need call-graph tiebreak)")

    out = os.path.join(args.workdir, "fuzzy_map.tsv")
    with open(out, "w") as f:
        f.write("name\tsdk_vaddr\tapp_vaddr\tratio\tmargin\texact\ttier\n")
        for name, sv, av, r, mg, ex, tier in sorted(rows, key=lambda x: x[1]):
            avs = 'None' if av is None else hex(av)
            f.write(f"{name}\t{sv:#x}\t{avs}\t{r:.3f}\t{mg:.3f}\t{ex}\t{tier}\n")
    print(f"\nmap -> {out}")

    # unresolved = everything not confidently placed by content alone
    # (tier not in exact/confident). NOTE: jlgraph's call-graph stage resolves a
    # further ~100 of these, so its unresolved set is smaller/authoritative.
    unresolved = os.path.join(args.workdir, "unresolved.txt")
    with open(unresolved, "w") as f:
        for name, sv, av, r, mg, ex, tier in sorted(rows, key=lambda x: x[1]):
            if tier not in ('exact', 'confident'):
                f.write(f"{sv:#x}\t{name}\t{tier}\t{r:.3f}\n")
    n_unres = sum(1 for row in rows if row[6] not in ('exact', 'confident'))
    print(f"unresolved ({n_unres}) -> {unresolved}  "
          f"[sdk_vaddr, name, tier, best_ratio]")


if __name__ == "__main__":
    main()
