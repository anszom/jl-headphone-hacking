#!/usr/bin/env python3
"""Side-by-side diff of one sdk function vs its best app.elf candidate.

Locates the best-matching app window for a named sdk function and prints an
aligned instruction diff (sdk | app), showing raw bytes + normalized text, so
you can see *why* a "near" match isn't exact: a differing constant/offset
(struct layout / config), an extra/missing instruction (inlining), a different
register (source/flag drift), etc.

Usage: python3 tools/jlshow.py <func_name> [--app ... --sdk ... etc]
"""
import sys
import difflib

import jlmatch
from jlmatch import Matcher


def best_window(m: Matcher, seq):
    """Return (start, ratio) of the best app window for `seq`, or (None,0)."""
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


def show(m: Matcher, name):
    hit = [(nm, v, sz) for (nm, v, sz) in m.funcs if nm == name]
    if not hit:
        print(f"no sdk .text function named {name!r}")
        return
    nm, vaddr, size = hit[0]
    js = m.sdk_func_insns(vaddr, size)
    sseq = [m.sdk.norm[j] for j in js]
    start, ratio = best_window(m, sseq)
    print(f"# {nm}  sdk@{vaddr:#x}  {len(js)} insns  best ratio {ratio:.3f}")
    if start is None:
        print("  (no app candidate window found — likely absent)")
        return
    aidx = list(range(start, start + len(sseq)))
    sm = difflib.SequenceMatcher(autojunk=False,
                                 a=[m.app.norm[i] for i in aidx], b=sseq)
    print(f"# app@{m.app.addr[start]:#x}")
    print(f"{'':1} {'SDK raw':<12} {'SDK norm':<32} | {'APP raw':<12} APP norm")
    for tag, a1, a2, b1, b2 in sm.get_opcodes():
        if tag == 'equal':
            for off in range(b2 - b1):
                j = js[b1 + off]
                print(f"  {m.sdk.raw[j]:<12} {m.sdk.norm[j]:<32} | "
                      f"{m.app.raw[aidx[a1+off]]:<12} {m.app.norm[aidx[a1+off]]}")
        else:
            nb, na = b2 - b1, a2 - a1
            for off in range(max(nb, na)):
                sj = js[b1 + off] if off < nb else None
                ai = aidx[a1 + off] if off < na else None
                sr = m.sdk.raw[sj] if sj is not None else ''
                sn = m.sdk.norm[sj] if sj is not None else ''
                ar = m.app.raw[ai] if ai is not None else ''
                an = m.app.norm[ai] if ai is not None else ''
                print(f"X {sr:<12} {sn:<32} | {ar:<12} {an}")


def main():
    ap = jlmatch.build_argparser()
    ap.add_argument("func", help="sdk .text function name to inspect")
    args = ap.parse_args()
    m = Matcher.from_paths(args.sdk, args.app, args.objdump, args.workdir,
                           verbose=False)
    show(m, args.func)


if __name__ == "__main__":
    main()
