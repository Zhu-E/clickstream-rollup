#!/usr/bin/env python3
"""One person-day whose revenue does not fit in 32 bits. The integer columns
are written as INT32 when every value in the run fits and as INT64 otherwise,
and every file of a run must make the same choice, so check both the values
and that no two files disagree on a type.
Usage: wide_test.py BIN"""
import collections, datetime, glob, os, shutil, subprocess, sys, tempfile
import pyarrow.parquet as pq

binp = sys.argv[1]
here = os.path.dirname(os.path.abspath(__file__))
tmp = tempfile.mkdtemp(prefix="ss-wide-")
T0 = datetime.datetime(2026, 10, 3, tzinfo=datetime.timezone.utc)
PRICE, BUYS = 10_000_000, 300


def stamp(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def case(name, whale):
    src, out = f"{tmp}/{name}-in", f"{tmp}/{name}-out"
    os.makedirs(f"{src}/events")
    with open(f"{src}/manifest.json", "w") as f:
        f.write('{"window_start": "2026-10-01T00:00:00Z", "window_end": "2026-10-15T00:00:00Z"}\n')
    with open(f"{src}/products.csv", "w") as f:
        f.write("product_id,category\np1,toys\np2,books\n")
    with open(f"{src}/campaigns.csv", "w") as f:
        f.write("campaign_id,channel\nc_1,email\n")
    want = collections.Counter()
    sessions = collections.Counter()
    with open(f"{src}/events/part-0.csv", "w") as f:
        f.write("event_id,user_id,ts,ingest_ts,event_type,product_id,price_cents\n")
        if whale:
            for i in range(BUYS):
                t = stamp(T0 + datetime.timedelta(minutes=i))
                f.write(f"w{i},whale,{t},{t},purchase,p1,{PRICE}\n")
            want[("whale", "2026-10-03", 1, BUYS, PRICE * BUYS, "toys")] += 1
            sessions["2026-10-03"] += 1
        # enough other people that every thread writes a file
        for i in range(400):
            day = T0 + datetime.timedelta(days=1 + i % 3)
            t = stamp(day + datetime.timedelta(seconds=i))
            f.write(f"s{i},small{i},{t},{t},purchase,p2,250\n")
            want[(f"small{i}", day.strftime("%Y-%m-%d"), 1, 1, 250, "books")] += 1
            sessions[day.strftime("%Y-%m-%d")] += 1
    subprocess.run([binp, src, out], check=True, env=dict(os.environ, NCPU="4"))
    subprocess.run([sys.executable, f"{here}/readers.py", out], check=True, stdout=subprocess.DEVNULL)
    got = collections.Counter()
    types = collections.defaultdict(set)
    files = sorted(glob.glob(f"{out}/user_daily/*.parquet"))
    for path in files:
        t = pq.ParquetFile(path).read()
        for c in ("sessions", "events", "revenue_cents"):
            types[c].add(str(t.schema.field(c).type))
        cols = [t.column(c).to_pylist() for c in ("user_id", "day", "sessions", "events", "revenue_cents", "top_category")]
        got += collections.Counter((u, str(d), s, e, r, c) for u, d, s, e, r, c in zip(*cols))
    ok = got == want
    expect = "int64" if whale else "int32"
    for c, seen in types.items():
        if seen != {expect}:
            ok = False
            print(f"{name}: {c} is {sorted(seen)} across {len(files)} files, expected {expect} in all")
    c = pq.read_table(f"{out}/campaign_daily").to_pylist()
    cd = {(r["campaign_id"], str(r["day"])): (r["sessions"], r["purchasing_sessions"], r["revenue_cents"]) for r in c}
    cd_want = {("organic", d): (n, n, 250 * n + (PRICE * BUYS - 250 if whale and d == "2026-10-03" else 0))
               for d, n in sessions.items()}
    if cd != cd_want:
        ok = False
        print(f"{name}: campaign_daily is {cd}, expected {cd_want}")
    if got != want:
        print(f"{name}: user_daily rows differ: {list((got - want).items())[:3]} vs {list((want - got).items())[:3]}")
    print(f"{name}: {len(files)} files, integer columns {expect}, {sum(got.values())} rows" + (" as expected" if ok else ""))
    return ok


try:
    results = [case("wide", True), case("narrow", False)]
finally:
    shutil.rmtree(tmp, ignore_errors=True)
print("OK" if all(results) else "FAIL")
sys.exit(0 if all(results) else 1)
