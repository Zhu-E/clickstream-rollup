#!/usr/bin/env python3
"""More product categories than the generator makes, checked two ways.

pad:  add N-minus-the-real-ones categories that only unused products belong
      to. No purchase is in them, so the published answer still holds for every
      column, top_category included, while the real categories move to other
      positions in the sorted list: one of them onto 31, or all of them above
      the padding.
hash: spread the real products over N new categories. The answer's
      top_category no longer applies, so check the columns that do not depend
      on categories, that top_category is null exactly where revenue is 0,
      and that every category wins somewhere.

Usage: cats_test.py BIN DATA ANSWER [N]"""
import csv, os, shutil, subprocess, sys, tempfile, zlib
import pyarrow.dataset as ds

binp, data, answer = sys.argv[1], sys.argv[2], sys.argv[3]
n = int(sys.argv[4]) if len(sys.argv) > 4 else 40
here = os.path.dirname(os.path.abspath(__file__))
tmp = tempfile.mkdtemp(prefix="ss-cats-")

with open(f"{data}/products.csv", newline="") as f:
    r = csv.reader(f)
    header = next(r)
    products = [row for row in r]
in_file = {row[1] for row in products}
real = sorted(in_file | {"unknown"})


def run(name, rows):
    """Run the binary on DATA with products.csv replaced by `rows`."""
    src, out = f"{tmp}/{name}-in", f"{tmp}/{name}-out"
    os.makedirs(src)
    for d in ("events", "clicks", "links"):
        if os.path.isdir(f"{data}/{d}"):
            os.symlink(os.path.abspath(f"{data}/{d}"), f"{src}/{d}")
    for f in ("manifest.json", "campaigns.csv"):
        shutil.copy(f"{data}/{f}", f"{src}/{f}")
    with open(f"{src}/products.csv", "w") as fo:
        fo.write(",".join(header) + "\n")
        for pid, cat in rows:
            fo.write(f"{pid},{cat}\n")
    subprocess.run([binp, src, out], check=True)
    return out


def table(path, cols):
    t = ds.dataset(path, format="parquet").to_table()
    return [t.column(c).to_pylist() for c in cols]


def answer_rows(path, idx):
    with open(path, newline="") as f:
        r = csv.reader(f)
        next(r)
        return sorted(tuple(row[i] for i in idx) for row in r)


def pad(before):
    """`before` padding categories sort ahead of the real ones, the rest after."""
    extra = n - len(in_file)
    names = ["!pad%03d" % i for i in range(min(before, extra))]
    names += ["~pad%03d" % i for i in range(extra - len(names))]
    rows = products + [("zz-unused-%d" % i, c) for i, c in enumerate(names)]
    order = sorted(set(real) | set(names))
    at = [order.index(c) for c in real]
    label = f"pad to {n}, real categories at {min(at)}..{max(at)}"
    out = run(f"pad{before}", rows)
    p = subprocess.run([sys.executable, f"{here}/cmp.py", out, answer], capture_output=True, text=True)
    if p.returncode != 0:
        print(f"{label}: DIFFERS from the answer")
        print("\n".join(p.stdout.splitlines()[:12]))
        return False
    print(f"{label}: both tables match the answer exactly")
    return True


def rehash():
    names = ["cat%03d" % i for i in range(n)]
    out = run("hash", [(pid, names[zlib.crc32(pid.encode()) % n]) for pid, _ in products])
    ok = True
    norm = lambda rows: sorted(tuple("" if v is None else str(v) for v in row) for row in rows)
    ud = table(f"{out}/user_daily", ["user_id", "day", "sessions", "events", "revenue_cents", "top_category"])
    cd = table(f"{out}/campaign_daily", ["campaign_id", "channel", "day", "sessions", "purchasing_sessions",
                                         "revenue_cents", "assisted_sessions"])
    for name, mine, ans in (("user_daily", norm(zip(*ud[:5])), answer_rows(f"{answer}/user_daily.csv", range(5))),
                            ("campaign_daily", norm(zip(*cd)), answer_rows(f"{answer}/campaign_daily.csv", range(7)))):
        if mine != ans:
            ok = False
            print(f"hash to {n}: {name} DIFFERS on category-independent columns ({len(mine)} vs {len(ans)} rows)")
    rev, top = ud[4], ud[5]
    wrong_null = sum((t is None) != (r == 0) for r, t in zip(rev, top))
    if wrong_null:
        ok = False
        print(f"hash to {n}: {wrong_null} rows where top_category is null with revenue or set without")
    won = {t for t in top if t is not None}
    stray = won - set(names) - {"unknown"}
    lost = set(names) - won
    if stray:
        ok = False
        print(f"hash to {n}: top_category values that are not categories: {sorted(stray)[:5]}")
    # a category that wins nowhere is a bug unless the data is too small to tell
    if lost and sum(r > 0 for r in rev) >= 50 * n:
        ok = False
        print(f"hash to {n}: categories that never win: {sorted(lost)[:8]}")
    if ok:
        print(f"hash to {n}: other columns match the answer, nulls line up with revenue, "
              f"{len(won & set(names))} of {n} categories win")
    return ok


try:
    results = [pad(31), rehash()]
    if n - len(in_file) > 31:
        results.append(pad(n))
finally:
    shutil.rmtree(tmp, ignore_errors=True)
print("OK" if all(results) else "FAIL")
sys.exit(0 if all(results) else 1)
