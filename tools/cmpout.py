#!/usr/bin/env python3
"""Order-insensitive diff of two output directories (both parquet).
Usage: cmpout.py A B"""
import sys, collections
import pyarrow.dataset as ds

SCH = {
    "user_daily": ["user_id", "day", "sessions", "events", "revenue_cents", "top_category"],
    "campaign_daily": ["campaign_id", "channel", "day", "sessions", "purchasing_sessions",
                       "revenue_cents", "assisted_sessions"],
}

def load(path, cols):
    t = ds.dataset(path, format="parquet").to_table()
    cs = [t.column(c).to_pylist() for c in cols]
    return collections.Counter(
        tuple("" if v is None else str(v) for v in row) for row in zip(*cs))

bad = 0
for tbl, cols in SCH.items():
    a = load(f"{sys.argv[1]}/{tbl}", cols)
    b = load(f"{sys.argv[2]}/{tbl}", cols)
    if a == b:
        print(f"  {tbl}: {sum(a.values())} rows identical")
    else:
        bad += 1
        only_a = a - b
        only_b = b - a
        print(f"  {tbl}: DIFFER  only_a {sum(only_a.values())} only_b {sum(only_b.values())}")
        for r in list(only_a)[:3]:
            print("    A", r)
        for r in list(only_b)[:3]:
            print("    B", r)
sys.exit(1 if bad else 0)
