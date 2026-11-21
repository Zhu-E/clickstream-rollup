#!/usr/bin/env python3
"""Order-insensitive diff of two output directories (both parquet).
Usage: cmpout.py A B"""
import sys, collections
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.dataset as ds

SCH = {
    "user_daily": ["user_id", "day", "sessions", "events", "revenue_cents", "top_category"],
    "campaign_daily": ["campaign_id", "channel", "day", "sessions", "purchasing_sessions",
                       "revenue_cents", "assisted_sessions"],
}

def load(path, cols):
    return ds.dataset(path, format="parquet").to_table(columns=cols)

def canon(t, cols):
    # every value as text and null as empty, rows sorted: equal tables are equal multisets of rows
    cs = [pc.fill_null(pc.cast(t.column(c), pa.string()), "") for c in cols]
    return pa.table(cs, names=cols).sort_by([(c, "ascending") for c in cols]).combine_chunks()

def bag(t, cols):
    cs = [t.column(c).to_pylist() for c in cols]
    return collections.Counter(
        tuple("" if v is None else str(v) for v in row) for row in zip(*cs))

bad = 0
for tbl, cols in SCH.items():
    ta = load(f"{sys.argv[1]}/{tbl}", cols)
    tb = load(f"{sys.argv[2]}/{tbl}", cols)
    if ta.num_rows == tb.num_rows and canon(ta, cols).equals(canon(tb, cols)):
        print(f"  {tbl}: {ta.num_rows} rows identical")
    else:
        # the slow way, only to show what differs
        a, b = bag(ta, cols), bag(tb, cols)
        bad += 1
        only_a = a - b
        only_b = b - a
        print(f"  {tbl}: DIFFER  only_a {sum(only_a.values())} only_b {sum(only_b.values())}")
        for r in list(only_a)[:3]:
            print("    A", r)
        for r in list(only_b)[:3]:
            print("    B", r)
sys.exit(1 if bad else 0)
