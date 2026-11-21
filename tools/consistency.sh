#!/bin/sh
# consistency.sh DATA -- the output must not depend on how the work was split,
# so run with several thread counts and diff them, then check the rules'
# own cross-table identity.
set -e
BIN=${BIN:-./solution/target/release/shopsess}
DATA=$1
BASE=${TMPDIR:-/tmp}/cons
rm -rf "$BASE"; mkdir -p "$BASE"
first=""
for n in 1 3 8 5; do
  NCPU=$n "$BIN" "$DATA" "$BASE/n$n" >/dev/null
  if [ -z "$first" ]; then first="$BASE/n$n"; else
    python3 tools/cmpout.py "$BASE/n$n" "$first" >/dev/null 2>&1 \
      && echo "  NCPU=$n: identical to NCPU=1" \
      || { echo "  NCPU=$n: DIFFERS from NCPU=1"; python3 tools/cmpout.py "$BASE/n$n" "$first" 2>&1 | head -8; exit 1; }
  fi
done
python3 - "$first" <<'PY'
import sys
import pyarrow.dataset as ds
o = sys.argv[1]
u = ds.dataset(o + "/user_daily", format="parquet").to_table()
c = ds.dataset(o + "/campaign_daily", format="parquet").to_table()
import pyarrow.compute as pc
us, ur = pc.sum(u.column("sessions")).as_py() or 0, pc.sum(u.column("revenue_cents")).as_py() or 0
cs, cr = pc.sum(c.column("sessions")).as_py() or 0, pc.sum(c.column("revenue_cents")).as_py() or 0
print(f"  rows {u.num_rows}/{c.num_rows}  sessions {us} vs {cs}  revenue {ur} vs {cr}")
assert us == cs, "session totals differ across tables"
assert ur == cr, "revenue totals differ across tables"
print("  self-check OK")
PY
