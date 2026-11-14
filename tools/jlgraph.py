#!/usr/bin/env python3
"""Call-graph disambiguation on top of the fuzzy matcher.

The fuzzy matcher leaves ~280 "ambiguous" functions: good content similarity but
several app windows score alike (common code shapes, tiny stubs). We break these
ties the way BinDiff does — by *who each function calls*.

Anchors = the exact + confident fuzzy matches (trusted sdk_func -> app_entry).
For an ambiguous sdk function F that calls C1..Ck, we know (for anchored Ci)
their app entry addresses. F's true app location is the candidate window whose
*containing app function* calls that same set of app addresses. Overlap in the
call set disambiguates where raw content can't. Newly resolved matches become
anchors and we iterate to a fixpoint.

Usage: python3 tools/jlgraph.py [--min-ratio 0.85] [std args]
Writes graph_map.tsv and unresolved.txt.
"""
import os
import re
import bisect
import collections

import jlmatch
import jlfuzzy
from jlmatch import Matcher
from jlfuzzy import Fuzzy

# target hex address inside an objdump call/branch comment: "< name : 1e13b90 >"
_CALL_TGT = re.compile(r'<[^>]*?([0-9a-fA-F]{5,})\s*>')
# the (signed, decimal) PC-relative displacement operand of a `call`
_CALL_OP = re.compile(r'\bcall\s+(-?\d+)\b')

# call-graph promotion only needs the candidate to be plausibly the right region;
# inlining drift makes correct windows score low on content, so overlap decides.
CG_FLOOR = 0.25


def raw_call_targets(asm_path):
    """Map site_addr -> target_addr for `call` lines. Robust to both symbolized
    and symbol-free disassembly:
      - symbolized: read the resolved address from the `< ... : ADDR >` comment.
      - symbol-free: compute it, since the printed operand is the signed
        PC-relative displacement: target = site + instr_len + displacement.
    (Both agree; the comment path is just a shortcut when objdump resolved it.)"""
    out = {}
    with open(asm_path) as f:
        for ln in f:
            m = jlmatch._LINE.match(ln)
            if not m:
                continue
            mn = m.group(3)
            if 'call' not in mn:
                continue
            addr = int(m.group(1), 16)
            t = _CALL_TGT.search(mn)
            if t:
                out[addr] = int(t.group(1), 16)
                continue
            op = _CALL_OP.search(jlmatch._COMMENT.sub('', mn))
            if op:
                instr_len = len(m.group(2).split())      # hex byte count
                out[addr] = addr + instr_len + int(op.group(1))
    return out


class Graph:
    def __init__(self, m: Matcher, workdir):
        self.m = m
        self.fz = Fuzzy(m)
        # --- sdk side: function spans + name lookup ------------------------
        self.sdk_funcs = sorted(m.funcs, key=lambda f: f[1])
        self.sdk_starts = [f[1] for f in self.sdk_funcs]
        self.sdk_name_at = {v: n for n, v, s in m.funcs}
        # --- call targets straight from objdump text ----------------------
        self.sdk_ct = raw_call_targets(os.path.join(workdir, "sdk.asm"))
        self.app_ct = raw_call_targets(os.path.join(workdir, "app.asm"))
        # sdk func -> set of callee names (attributed by symbol span)
        self.sdk_callees = collections.defaultdict(set)
        for site, tgt in self.sdk_ct.items():
            fn = self._sdk_func_of(site)
            nm = self.sdk_name_at.get(tgt)
            if fn is not None and nm is not None:
                self.sdk_callees[fn].add(nm)
        # app call sites sorted for range queries (calls within a window)
        self.app_sites = sorted(self.app_ct)
        self.app_tgts = [self.app_ct[s] for s in self.app_sites]
        # app entry points = harvested call targets (every called func starts one)
        self.app_entries = sorted(set(self.app_ct.values()))

    def snap_to_entry(self, addr, max_back):
        """Nearest app entry point <= addr within max_back bytes, else addr.
        A call-graph match identifies the right function; its content-alignment
        start can be a few instructions past the true (called) entry."""
        i = bisect.bisect_right(self.app_entries, addr) - 1
        if i >= 0 and 0 <= addr - self.app_entries[i] <= max_back:
            return self.app_entries[i]
        return addr

    def _sdk_func_of(self, addr):
        i = bisect.bisect_right(self.sdk_starts, addr) - 1
        if i < 0:
            return None
        n, v, s = self.sdk_funcs[i]
        return n if v <= addr < v + s else None

    def calls_in_range(self, lo, hi):
        """Set of call-target addrs from sites in [lo, hi] of app.elf."""
        i = bisect.bisect_left(self.app_sites, lo)
        j = bisect.bisect_right(self.app_sites, hi)
        return set(self.app_tgts[i:j])

    def run(self, min_ratio=0.85):
        m = self.fz.m
        # seed anchors from a base fuzzy pass (exact + confident)
        anchors = {}            # sdk_name -> app_entry
        score = {}              # sdk_name -> (numeric confidence, tier)
        pending = []            # (name, js) still ambiguous/weak
        for name, vaddr, size in m.funcs:
            js = m.sdk_func_insns(vaddr, size)
            if not js:
                continue
            exact = len(m.find_run([m.sdk.norm[j] for j in js])) == 1
            s, r, mg = self.fz.match(js)
            av = m.app.addr[s] if s is not None else None
            if exact:
                anchors[name] = av; score[name] = (1000.0, 'exact')
            elif r >= 0.90 and mg >= 0.04:
                anchors[name] = av; score[name] = (100.0 * r, 'confident')
            else:
                pending.append((name, js, vaddr))
        n_base = len(anchors)

        # iterate: use call-set overlap to resolve pending funcs
        promoted = {}
        had_callees = 0
        changed = True
        rounds = 0
        while changed and rounds < 6:
            changed = False
            rounds += 1
            still = []
            for name, js, vaddr in pending:
                want = {anchors[c] for c in self.sdk_callees.get(name, ())
                        if c in anchors}
                if len(want) < 2:
                    still.append((name, js, vaddr))
                    continue      # too few anchored callees to disambiguate
                if rounds == 1:
                    had_callees += 1
                scored = self.fz.scored_candidates(js)
                if not scored:
                    still.append((name, js, vaddr))
                    continue
                n = len(js)
                # evaluate call-overlap for every plausible window. Content gate
                # is only a low floor: inlining drift makes the *correct* window
                # score 0.4-0.7, so overlap (not content) is the evidence here.
                evals = []
                for cr, fr, s in scored[:jlfuzzy.TOP_CANDIDATES]:
                    if cr < CG_FLOOR:
                        continue
                    a0, a1 = m.app.addr[s], m.app.addr[s + n - 1]
                    ov = len(want & self.calls_in_range(a0, a1))
                    evals.append((ov, cr, a0, a1 - a0))
                if not evals:
                    still.append((name, js, vaddr))
                    continue
                evals.sort(reverse=True)
                best_ov, best_cr, best_a, best_span = evals[0]
                # runner-up = best overlap from a DIFFERENT app region (windows
                # overlapping the winner are shifted copies of the same func)
                second_ov = 0
                for ov, cr, a0, _ in evals[1:]:
                    if abs(a0 - best_a) > best_span:
                        second_ov = ov
                        break
                # accept if overlap is decisive, unique across regions, and
                # covers a real fraction of the callees
                if best_ov >= 2 and best_ov > second_ov and \
                        best_ov >= (len(want) + 1) // 2:
                    entry = self.snap_to_entry(best_a, best_span or 64)
                    anchors[name] = entry
                    score[name] = (200.0 + best_ov, 'callgraph')
                    promoted[name] = (entry, best_cr)
                    changed = True
                else:
                    still.append((name, js, vaddr))
            pending = still

        self._had_callees = had_callees

        # ---- injectivity resolution -------------------------------------
        # One app function may legitimately back several sdk names only via ICF
        # (identical code folding): those share a base name (foo / foo.1234).
        # For genuine conflicts (different funcs on one addr) keep the strongest
        # evidence and drop the rest.
        def base(n):
            return re.sub(r'\.\d+$', '', n)
        by_addr = collections.defaultdict(list)
        for nm, av in anchors.items():
            by_addr[av].append(nm)
        dropped = 0
        for av, names in by_addr.items():
            if len(names) < 2:
                continue
            bases = {base(n) for n in names}
            if len(bases) == 1:
                continue                        # ICF fold: legitimate
            keep = max(names, key=lambda n: score[n][0])
            for n in names:
                if n is not keep and base(n) != base(keep):
                    del anchors[n]
                    promoted.pop(n, None)
                    dropped += 1
        self._dropped = dropped

        print("\n============ CALL-GRAPH DISAMBIGUATION ============")
        print(f"base anchors (exact+confident): {n_base}")
        print(f"pending with >=2 anchored callees: {self._had_callees}")
        print(f"promoted via call graph:        {len(promoted)}")
        print(f"  in {rounds} propagation round(s)")
        print(f"dropped in injectivity resolve: {self._dropped}")
        print(f"still unresolved:               {len(pending)}")
        total = len(m.funcs)
        resolved = len(anchors)
        print(f"\ntotal resolved: {resolved}/{total} ({100*resolved/total:.1f}%)")
        print("\nsample call-graph-promoted matches:")
        for name in list(promoted)[:12]:
            av, cr = promoted[name]
            print(f"    {cr:.3f}  {name} -> {av:#x}")
        return anchors, promoted


def main():
    ap = jlmatch.build_argparser()
    ap.add_argument("--min-ratio", type=float, default=0.85)
    args = ap.parse_args()
    m = Matcher.from_paths(args.sdk, args.app, args.objdump, args.workdir)
    g = Graph(m, args.workdir)
    anchors, promoted = g.run(min_ratio=args.min_ratio)
    out = os.path.join(args.workdir, "graph_map.tsv")
    with open(out, "w") as f:
        f.write("name\tapp_entry\tvia\n")
        for name, av in sorted(anchors.items()):
            via = 'callgraph' if name in promoted else 'content'
            f.write(f"{name}\t{av if av is None else hex(av)}\t{via}\n")
    print(f"\nmap -> {out}")

    # authoritative unresolved set = sdk .text funcs not in the injective map.
    # Annotate each with its best content ratio so absent (no/low candidate) is
    # distinguishable from present-but-ambiguous (high ratio, non-unique).
    unres = os.path.join(args.workdir, "unresolved.txt")
    rows = []
    for name, vaddr, size in m.funcs:
        if name in anchors:
            continue
        js = m.sdk_func_insns(vaddr, size)
        r = g.fz.match(js)[1] if js else 0.0
        cls = 'absent' if r < 0.50 else ('ambiguous' if r >= 0.90 else 'weak')
        rows.append((vaddr, name, cls, r))
    with open(unres, "w") as f:
        for vaddr, name, cls, r in sorted(rows):
            f.write(f"{vaddr:#x}\t{name}\t{cls}\t{r:.3f}\n")
    n_absent = sum(1 for _, _, c, _ in rows if c == 'absent')
    print(f"unresolved ({len(rows)}, {n_absent} likely-absent) -> {unres}  "
          f"[sdk_vaddr, name, class, best_ratio]")


if __name__ == "__main__":
    main()
