#!/usr/bin/env python3
"""Rewrite the dev products.csv to use N categories, then check that every
column that does not depend on categories still matches the dev answer.
Usage: cats_test.py BIN DATA ANSWER [N]"""
import csv, os, subprocess, sys, shutil
import pyarrow.parquet as pq, pyarrow.dataset as ds

binp, data, answer = sys.argv[1], sys.argv[2], sys.argv[3]
n = int(sys.argv[4]) if len(sys.argv) > 4 else 40
tmp = "/tmp/ss-cats"
shutil.rmtree(tmp, ignore_errors=True)
os.makedirs(tmp)
for d in ("events", "clicks", "links"):
    if os.path.isdir(f"{data}/{d}"):
        os.symlink(os.path.abspath(f"{data}/{d}"), f"{tmp}/{d}")
for f in ("manifest.json", "campaigns.csv"):
    if os.path.exists(f"{data}/{f}"):
        shutil.copy(f"{data}/{f}", f"{tmp}/{f}")
with open(f"{data}/products.csv") as fi, open(f"{tmp}/products.csv", "w") as fo:
    r = csv.reader(fi)
    hdr = next(r)
    fo.write(",".join(hdr) + "\n")
    for row in r:
        cat = "cat%03d" % (hash(row[0]) % n)
        fo.write("%s,%s\n" % (row[0], cat))
out = "/tmp/ss-cats-out"
shutil.rmtree(out, ignore_errors=True)
subprocess.run([binp, tmp, out], check=True)

def rows(path, keep):
    t = ds.dataset(path, format="parquet").to_table()
    cols = {c: t.column(c).to_pylist() for c in keep}
    return sorted(zip(*[cols[c] for c in keep]))

def ans(path, idx):
    got = []
    with open(path) as f:
        r = csv.reader(f)
        next(r)
        for row in r:
            got.append(tuple(row[i] for i in idx))
    return sorted(got)

def norm(v):
    return tuple("" if x is None else str(x) for x in v)

ud = [norm(v) for v in rows(f"{out}/user_daily", ["user_id", "day", "sessions", "events", "revenue_cents"])]
uda = ans(f"{answer}/user_daily.csv", [0, 1, 2, 3, 4])
cd = [norm(v) for v in rows(f"{out}/campaign_daily",
      ["campaign_id", "channel", "day", "sessions", "purchasing_sessions", "revenue_cents", "assisted_sessions"])]
cda = ans(f"{answer}/campaign_daily.csv", [0, 1, 2, 3, 4, 5, 6])
ncat = len({c for c in ds.dataset(f"{out}/user_daily", format="parquet").to_table()
            .column("top_category").to_pylist() if c is not None})
ok = True
for name, a, b in (("user_daily", ud, uda), ("campaign_daily", cd, cda)):
    if a != b:
        ok = False
        print(f"{name}: DIFFER ({len(a)} vs {len(b)} rows)")
        for x, y in list(zip(a, b))[:3]:
            if x != y:
                print("  mine", x, "\n  ans ", y)
    else:
        print(f"{name}: {len(a)} rows match on category-independent columns")
print(f"distinct top_category values: {ncat} (products rewritten to {n} categories)")
print("OK" if ok else "FAIL")
sys.exit(0 if ok else 1)
