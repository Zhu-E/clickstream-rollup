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


def canon(t, cols):
    """every value as text and null as empty, rows sorted: equal tables are equal multisets of rows"""
    import pyarrow as pa
    import pyarrow.compute as pc
    cs = [pc.fill_null(pc.cast(t.column(c), pa.string()), "") for c in cols]
    return pa.table(cs, names=cols).sort_by([(c, "ascending") for c in cols]).combine_chunks()


def bag(cols, t):
    """type checks on an Arrow table as a reader delivered it, then its canonical form"""
    for name in cols:
        c = t.column(name)
        for v in c.slice(0, 50).to_pylist():
            if name == "day":
                assert type(v) is datetime.date, f"{name} is {type(v)}, not a date"
            elif name in ("sessions", "events", "revenue_cents", "purchasing_sessions", "assisted_sessions"):
                assert type(v) is int, f"{name} is {type(v)}"
            elif v is not None:
                assert type(v) is str, f"{name} is {type(v)}"
        assert name in NULLABLE or c.null_count == 0, f"null in {name}"
    return canon(t, cols)


def with_pyarrow(path, cols):
    import pyarrow as pa
    import pyarrow.dataset as ds
    import pyarrow.parquet as pq
    t = ds.dataset(path, format="parquet").to_table()
    assert sorted(t.column_names) == sorted(cols), t.column_names
    whole = bag(cols, t)
    # and file by file, the way a reader that does not unify schemas would
    parts = [bag(cols, pq.ParquetFile(f).read()) for f in sorted(glob.glob(f"{path}/*.parquet"))]
    joined = canon(pa.concat_tables(parts), cols) if parts else whole
    assert whole.equals(joined), "pyarrow: dataset and per-file reads differ"
    return whole


def with_polars(path, cols):
    import polars as pl
    df = pl.read_parquet(f"{path}/*.parquet")
    assert sorted(df.columns) == sorted(cols), df.columns
    assert df.schema["day"] == pl.Date, df.schema
    lazy = pl.scan_parquet(f"{path}/*.parquet").collect()
    a = bag(cols, df.to_arrow())
    assert a.equals(bag(cols, lazy.to_arrow())), "polars: eager and lazy differ"
    return a


def with_duckdb(path, cols):
    import duckdb
    con = duckdb.connect()
    rel = con.sql(f"select {', '.join(cols)} from read_parquet('{path}/*.parquet')")
    assert str(rel.types[cols.index("day")]) == "DATE", rel.types
    fetch = getattr(rel, "to_arrow_table", None) or rel.fetch_arrow_table
    return bag(cols, fetch())


def count_diff(a, b):
    """rows only in a and only in b, for the message when two canonical tables differ"""
    import collections
    ca = collections.Counter(zip(*[a.column(c).to_pylist() for c in a.column_names]))
    cb = collections.Counter(zip(*[b.column(c).to_pylist() for c in b.column_names]))
    return sum((ca - cb).values()), sum((cb - ca).values())


READERS = {"pyarrow": with_pyarrow, "polars": with_polars, "duckdb": with_duckdb}


def main():
    out = sys.argv[1]
    other = sys.argv[2] if len(sys.argv) > 2 else None
    bad = 0
    missing = set()
    for tbl, cols in SCH.items():
        seen = {}
        for name, fn in READERS.items():
            try:
                seen[name] = fn(f"{out}/{tbl}", cols)
            except ImportError:
                missing.add(name)
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
            if not b.equals(first):
                bad += 1
                print(f"  {tbl}: {name} disagrees with {next(iter(seen))}")
        if other:
            ref = with_pyarrow(f"{other}/{tbl}", cols)
            if not ref.equals(first):
                bad += 1
                here, there = count_diff(first, ref)
                print(f"  {tbl}: DIFFERS from {other}: only here {here}, only there {there}")
        print(f"  {tbl}: {first.num_rows} rows, same through {', '.join(seen)}"
              + (", same as the other output" if other else ""))
    if missing:
        # not a pass: only the readers that are installed were checked
        print(f"readers not installed, so not checked: {', '.join(sorted(missing))}")
    elif bad == 0:
        print("READERS OK")
    sys.exit(1 if bad else 0)


main()
