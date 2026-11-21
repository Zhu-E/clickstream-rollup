#!/usr/bin/env python3
"""Exact order-insensitive diff: cmp.py OUT_DIR ANSWER_DIR [limit]"""
import csv, sys, datetime
import pyarrow.parquet as pq

SCH = {
 "user_daily": ["user_id","day","sessions","events","revenue_cents","top_category"],
 "campaign_daily": ["campaign_id","channel","day","sessions","purchasing_sessions","revenue_cents","assisted_sessions"],
}
KEYS = {"user_daily": 2, "campaign_daily": 3}

def load_pq(folder, cols):
    t = pq.read_table(folder, columns=cols)
    d = t.to_pydict()
    rows = []
    n = t.num_rows
    cl = [d[c] for c in cols]
    for i in range(n):
        rows.append(tuple(
            (v.isoformat() if isinstance(v, datetime.date) else ("" if v is None else str(v)))
            for v in (c[i] for c in cl)))
    return rows

def load_csv(path, cols):
    rows = []
    with open(path, newline="") as f:
        r = csv.reader(f)
        hdr = next(r)
        idx = [hdr.index(c) for c in cols]
        for line in r:
            rows.append(tuple(line[i] for i in idx))
    return rows

def main():
    out, ans = sys.argv[1], sys.argv[2]
    lim = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    bad = 0
    for tbl, cols in SCH.items():
        a = load_pq(f"{out}/{tbl}", cols)
        b = load_csv(f"{ans}/{tbl}.csv", cols)
        nk = KEYS[tbl]
        sa, sb = set(a), set(b)
        ka = {}
        for r in a: ka.setdefault(r[:nk], []).append(r)
        kb = {}
        for r in b: kb.setdefault(r[:nk], []).append(r)
        dup = sum(len(v)-1 for v in ka.values() if len(v) > 1)
        only_a = sa - sb
        only_b = sb - sa
        print(f"{tbl}: rows {len(a)} vs {len(b)}; only_mine {len(only_a)}; only_ans {len(only_b)}; dupkeys {dup}")
        if only_a or only_b or dup:
            bad += 1
            # classify: key missing entirely vs value mismatch
            miss_key = [r for r in only_b if r[:nk] not in ka]
            extra_key = [r for r in only_a if r[:nk] not in kb]
            valdiff = [r for r in only_b if r[:nk] in ka]
            print(f"  keys only in answer: {len(miss_key)}; keys only in mine: {len(extra_key)}; value diffs: {len(valdiff)}")
            for r in sorted(miss_key)[:lim]: print("   ANS-ONLY-KEY", r)
            for r in sorted(extra_key)[:lim]: print("   MINE-ONLY-KEY", r)
            for r in sorted(valdiff)[:lim]:
                print("   ANS", r, "\n   MINE", ka[r[:nk]])
    print("MATCH" if bad == 0 else "DIFFER")
    return 1 if bad else 0

sys.exit(main())
