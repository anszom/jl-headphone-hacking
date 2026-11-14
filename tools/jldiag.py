#!/usr/bin/env python3
"""Diagnose the no-match bucket from jlmatch.

For every sdk .text function that did NOT uniquely exact-match, find the best
difflib similarity against app candidate windows and bucket it:

  exact_unique       : matched uniquely by jlmatch (baseline)
  identical_nonuniq  : ratio > 0.98 but exact run wasn't unique (dup/near copies)
  near               : 0.80-0.98  -> minor real diff (small source/config drift)
  weak               : 0.50-0.80  -> substantial diff
  absent             : < 0.50 or a distinctive instr missing -> inlined / removed
                       / genuinely different (e.g. a feature the device omits)
  too_short          : < MIN_INSNS instructions (unreliable standalone)

Usage: python3 tools/jldiag.py [same args as jlmatch.py]
"""
import difflib
import collections

import jlmatch
from jlmatch import Matcher, MIN_INSNS, SEED_MAX_FREQ, MAX_CANDIDATES


def best_ratio(m: Matcher, seq):
    """(best difflib ratio vs app windows, #distinctive tokens present in app).
    Seeds candidate windows on the rarest present, non-ubiquitous tokens."""
    n = len(seq)
    order = sorted(range(n), key=lambda k: m.tokfreq.get(seq[k], 0))
    starts, present = set(), 0
    for k in order[:4]:
        f = m.tokfreq.get(seq[k], 0)
        if f == 0:
            continue
        present += 1
        if f > SEED_MAX_FREQ:
            continue
        for p in m.app_tokpos[seq[k]]:
            s = p - k
            if 0 <= s <= len(m.app.norm) - n:
                starts.add(s)
    if not starts:
        return 0.0, present
    best = 0.0
    sm = difflib.SequenceMatcher(autojunk=False)
    sm.set_seq2(seq)
    for s in list(starts)[:MAX_CANDIDATES]:
        sm.set_seq1(m.app.norm[s:s + n])
        r = sm.quick_ratio()
        if r > best:
            best = r
            if best == 1.0:
                break
    return best, present


def diagnose(m: Matcher):
    # which sdk funcs matched uniquely (baseline)
    unique = set()
    for name, vaddr, size in m.funcs:
        js = m.sdk_func_insns(vaddr, size)
        if js and len(m.find_run([m.sdk.norm[j] for j in js])) == 1:
            unique.add(vaddr)

    buckets = collections.Counter()
    examples = collections.defaultdict(list)
    for name, vaddr, size in m.funcs:
        if vaddr in unique:
            buckets['exact_unique'] += 1
            continue
        js = m.sdk_func_insns(vaddr, size)
        if not js:
            buckets['no_disasm'] += 1
            continue
        seq = [m.sdk.norm[j] for j in js]
        if len(seq) < MIN_INSNS:
            buckets['too_short'] += 1
            continue
        r, present = best_ratio(m, seq)
        if present == 0:
            b = 'absent'
        elif r > 0.98:
            b = 'identical_nonuniq'
        elif r >= 0.80:
            b = 'near'
        elif r >= 0.50:
            b = 'weak'
        else:
            b = 'absent'
        buckets[b] += 1
        if len(examples[b]) < 8:
            examples[b].append((name, len(seq), round(r, 3)))
    return buckets, examples


def main():
    args = jlmatch.build_argparser().parse_args()
    m = Matcher.from_paths(args.sdk, args.app, args.objdump, args.workdir)
    buckets, examples = diagnose(m)

    order = ['exact_unique', 'identical_nonuniq', 'near', 'weak',
             'absent', 'too_short', 'no_disasm']
    tot = sum(buckets.values())
    print("\n==================== NO-MATCH DIAGNOSIS ====================")
    for b in order:
        print(f"  {b:20s} {buckets[b]:5d}  ({100*buckets[b]/tot:.1f}%)")
    print(f"  {'TOTAL':20s} {tot:5d}")
    same = buckets['exact_unique'] + buckets['identical_nonuniq'] + buckets['near']
    print(f"\n  plausibly-same code (exact+identical+near): "
          f"{same} ({100*same/tot:.1f}%)")
    print("\n--- examples ---")
    for b in ['identical_nonuniq', 'near', 'weak', 'absent']:
        print(f"[{b}]")
        for nm, ln, r in examples[b]:
            print(f"    {r:5.3f}  {ln:4d}i  {nm}")


if __name__ == "__main__":
    main()
