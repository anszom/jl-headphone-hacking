#!/usr/bin/env python3
"""Aggregate the *kind* of difference across near/weak matches.

For every sdk function that didn't exact-match, align it to its best app window
and classify each differing instruction:
  - offset/literal diff : same mnemonic+registers, only integer operand(s)
    differ (struct member offsets, sizeof strides) -> struct-layout divergence
  - structural diff      : mnemonic/register/instruction-count differs
                           (inlining, regalloc, real source change)
  - extra/missing insn   : insert/delete (inlining / added code)

Prints the recurring (sdk_val -> app_val) integer-delta histogram: the
fingerprint of which struct layouts differ. If the device build has smaller
structs, sdk_val > app_val consistently.

Usage: python3 tools/jloffsets.py [--sdk ... --app ... etc]
"""
import re
import difflib
import collections

import jlmatch
from jlmatch import Matcher

SHAPE = re.compile(r'-?\d+')
INT = re.compile(r'-?\d+')


def shape(s):
    return SHAPE.sub('#', s)


def best_window(m, seq):
    n = len(seq)
    order = sorted(range(n), key=lambda k: m.tokfreq.get(seq[k], 0))
    starts = set()
    for k in order[:4]:
        f = m.tokfreq.get(seq[k], 0)
        if 0 < f <= jlmatch.SEED_MAX_FREQ:
            for p in m.app_tokpos[seq[k]]:
                s = p - k
                if 0 <= s <= len(m.app.norm) - n:
                    starts.add(s)
    best_s, best_r = None, 0.0
    sm = difflib.SequenceMatcher(autojunk=False)
    sm.set_seq2(seq)
    for s in list(starts)[:jlmatch.MAX_CANDIDATES]:
        sm.set_seq1(m.app.norm[s:s + n])
        r = sm.ratio()
        if r > best_r:
            best_r, best_s = r, s
    return best_s, best_r


def main():
    args = jlmatch.build_argparser().parse_args()
    m = Matcher.from_paths(args.sdk, args.app, args.objdump, args.workdir,
                           verbose=False)

    delta_hist = collections.Counter()     # (sdk_int, app_int) -> count
    cat = collections.Counter()
    funcs_offset_only = 0
    funcs_structural = 0
    considered = 0

    for name, vaddr, size in m.funcs:
        js = m.sdk_func_insns(vaddr, size)
        if not js or len(js) < jlmatch.MIN_INSNS:
            continue
        sseq = [m.sdk.norm[j] for j in js]
        if len(m.find_run(sseq)) == 1:
            continue                        # exact match, skip
        start, ratio = best_window(m, sseq)
        if start is None or ratio < 0.60:
            continue                        # too different / absent
        considered += 1
        aseq = m.app.norm[start:start + len(sseq)]
        sm = difflib.SequenceMatcher(autojunk=False, a=aseq, b=sseq)
        f_off = f_struct = 0
        for tag, a1, a2, b1, b2 in sm.get_opcodes():
            if tag == 'equal':
                continue
            if tag in ('insert', 'delete'):
                cat['extra_missing_insn'] += (a2 - a1) + (b2 - b1)
                f_struct += 1
                continue
            # replace: pair up position-wise
            for off in range(max(a2 - a1, b2 - b1)):
                an = aseq[a1 + off] if a1 + off < a2 else None
                sn = sseq[b1 + off] if b1 + off < b2 else None
                if an is None or sn is None:
                    cat['extra_missing_insn'] += 1
                    f_struct += 1
                elif shape(an) == shape(sn):
                    ai = [int(x) for x in INT.findall(an)]
                    si = [int(x) for x in INT.findall(sn)]
                    diffs = [(s, a) for s, a in zip(si, ai) if s != a]
                    for pair in diffs:
                        delta_hist[pair] += 1
                    cat['offset_literal_diff'] += len(diffs)
                    f_off += 1
                else:
                    cat['structural_diff'] += 1
                    f_struct += 1
        if f_off and not f_struct:
            funcs_offset_only += 1
        elif f_struct:
            funcs_structural += 1

    print(f"\n==== DIFFERENCE ANATOMY (near/weak, ratio>=0.60) ====")
    print(f"functions considered: {considered}")
    print(f"  differ by OFFSETS/LITERALS ONLY: {funcs_offset_only}  "
          f"(struct-layout divergence — one config away)")
    print(f"  have structural diffs:           {funcs_structural}  "
          f"(inlining / regalloc / real source change)")
    print(f"\ndiff-instruction categories:")
    for k, v in cat.most_common():
        print(f"  {k:22s} {v}")

    print(f"\ntop recurring (sdk_off -> app_off) deltas  [sdk-app]:")
    print(f"  {'sdk':>6} {'app':>6} {'d':>5}  count")
    for (s, a), c in delta_hist.most_common(30):
        print(f"  {s:>6} {a:>6} {s-a:>5}  {c}")
    bigger = sum(c for (s, a), c in delta_hist.items() if s > a)
    smaller = sum(c for (s, a), c in delta_hist.items() if s < a)
    print(f"\nsdk offset > app offset (sdk structs bigger): {bigger}")
    print(f"sdk offset < app offset:                      {smaller}")


if __name__ == "__main__":
    main()
