#!/usr/bin/env python3
"""Read an output directory with every Parquet reader installed and check
that they all see the same rows and sensible types. The scorer's reader is
not known, so a file only pyarrow can read is not good enough.
Usage: readers.py OUT [OTHER_OUT]   (OTHER_OUT: a second output to diff against)"""
import collections, datetime, glob, sys

SCH = {
    "user_daily": ["user_id", "day", "sessions", "events", "revenue_cents", "top_category"],
    "campaign_daily": ["campaign_id", "channel", "day", "sessions", "purchasing_sessions",
                       "revenue_cents", "assisted_sessions"],
}
NULLABLE = {"top_category"}


def bag(cols, columns):
    for name, c in zip(cols, columns):
        for v in c[:50]:
            if name == "day":
                assert type(v) is datetime.date, f"{name} is {type(v)}, not a date"
            elif name in ("sessions", "events", "revenue_cents", "purchasing_sessions", "assisted_sessions"):
                assert type(v) is int, f"{name} is {type(v)}"
            elif v is not None:
                assert type(v) is str, f"{name} is {type(v)}"
        assert name in NULLABLE or None not in c, f"null in {name}"
    return collections.Counter(tuple("" if v is None else str(v) for v in row) for row in zip(*columns))


def with_pyarrow(path, cols):
    import pyarrow.dataset as ds
    import pyarrow.parquet as pq
    t = ds.dataset(path, format="parquet").to_table()
    assert sorted(t.column_names) == sorted(cols), t.column_names
    whole = bag(cols, [t.column(c).to_pylist() for c in cols])
    # and file by file, the way a reader that does not unify schemas would
    parts = collections.Counter()
    for f in sorted(glob.glob(f"{path}/*.parquet")):
        ft = pq.ParquetFile(f).read()
        parts += bag(cols, [ft.column(c).to_pylist() for c in cols])
    assert whole == parts, "pyarrow: dataset and per-file reads differ"
    return whole


def with_polars(path, cols):
    import polars as pl
    df = pl.read_parquet(f"{path}/*.parquet")
    assert sorted(df.columns) == sorted(cols), df.columns
    assert df.schema["day"] == pl.Date, df.schema
    lazy = pl.scan_parquet(f"{path}/*.parquet").collect()
    a = bag(cols, [df[c].to_list() for c in cols])
    assert a == bag(cols, [lazy[c].to_list() for c in cols]), "polars: eager and lazy differ"
    return a


def with_duckdb(path, cols):
    import duckdb
    con = duckdb.connect()
    rel = con.sql(f"select {', '.join(cols)} from read_parquet('{path}/*.parquet')")
    assert str(rel.types[cols.index("day")]) == "DATE", rel.types
    return bag(cols, list(zip(*rel.fetchall())) or [[] for _ in cols])


READERS = {"pyarrow": with_pyarrow, "polars": with_polars, "duckdb": with_duckdb}


def main():
    out = sys.argv[1]
    other = sys.argv[2] if len(sys.argv) > 2 else None
    bad = 0
    for tbl, cols in SCH.items():
        seen = {}
        for name, fn in READERS.items():
            try:
                seen[name] = fn(f"{out}/{tbl}", cols)
            except ImportError:
                continue
            except Exception as e:
                bad += 1
                print(f"  {tbl}: {name} FAILED: {type(e).__name__}: {e}")
        first = next(iter(seen.values()), None)
        if first is None:
            print(f"  {tbl}: no reader could read it")
            bad += 1
            continue
        for name, b in seen.items():
            if b != first:
                bad += 1
                print(f"  {tbl}: {name} disagrees with {next(iter(seen))}")
        if other:
            ref = with_pyarrow(f"{other}/{tbl}", cols)
            if ref != first:
                bad += 1
                print(f"  {tbl}: DIFFERS from {other}: only here {sum((first - ref).values())}, "
                      f"only there {sum((ref - first).values())}")
        print(f"  {tbl}: {sum(first.values())} rows, same through {', '.join(seen)}"
              + (", same as the other output" if other else ""))
    if len(READERS) > 1 and bad == 0:
        print("READERS OK")
    sys.exit(1 if bad else 0)


main()
