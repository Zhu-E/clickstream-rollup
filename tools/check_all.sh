#!/bin/sh
# check_all.sh [DEV] [ANSWER] -- everything that has to hold before submitting.
# Needs python3 with pyarrow, and `generate` from the track's generator.zip for
# the fresh-seed checks (skipped if GEN is not set or found).
set -e
cd "$(dirname "$0")/.."
DEV=${1:-data/dev}
ANSWER=${2:-ex/dev-answer/dev-answer}
GEN=${GEN:-ex/generator/generator/target/release/generate}
BIN=solution/target/release/shopsess
NOENC=${TMPDIR:-/tmp}/ss-noenc/release/shopsess

say() { printf '\n== %s\n' "$1"; }

say "unit tests"
( cd solution && cargo test --release 2>&1 | tail -3 )

say "build"
( cd solution && cargo build --release 2>&1 | tail -1 )
( cd solution && SS_NOENC=1 cargo build --release --target-dir "${TMPDIR:-/tmp}/ss-noenc" 2>&1 | tail -1 )

say "dev set, exact diff against the published answer"
rm -rf "${TMPDIR:-/tmp}/ck-dev"
$BIN "$DEV" "${TMPDIR:-/tmp}/ck-dev" >/dev/null
python3 tools/cmp.py "${TMPDIR:-/tmp}/ck-dev" "$ANSWER" | tail -1

say "36 edge-case fixtures"
BIN=$BIN ./tools/fixtures.sh 2>&1 | tail -2 | head -1

say "scalar scanner (SS_NOSIMD=1) agrees"
rm -rf "${TMPDIR:-/tmp}/ck-sc"
SS_NOSIMD=1 $BIN "$DEV" "${TMPDIR:-/tmp}/ck-sc" >/dev/null
python3 tools/cmpout.py "${TMPDIR:-/tmp}/ck-dev" "${TMPDIR:-/tmp}/ck-sc"
BIN=$BIN SS_NOSIMD=1 ./tools/fixtures.sh 2>&1 | tail -2 | head -1

say "hashed-id path (SS_NOENC=1) agrees"
rm -rf "${TMPDIR:-/tmp}/ck-ne"
$NOENC "$DEV" "${TMPDIR:-/tmp}/ck-ne" >/dev/null
python3 tools/cmpout.py "${TMPDIR:-/tmp}/ck-dev" "${TMPDIR:-/tmp}/ck-ne"
BIN=$NOENC ./tools/fixtures.sh 2>&1 | tail -2 | head -1

say "thread-count independence and cross-table totals"
./tools/consistency.sh "$DEV"

say "more product categories than the generator makes"
python3 tools/cats_test.py $BIN "$DEV" "$ANSWER" 40 | tail -2
python3 tools/cats_test.py $BIN "$DEV" "$ANSWER" 200 | tail -2

say "inputs with nothing in them"
for d in ck-empty ck-nolinks; do rm -rf "${TMPDIR:-/tmp}/$d" "${TMPDIR:-/tmp}/$d-in"; done
mkdir -p "${TMPDIR:-/tmp}/ck-empty-in/events"
cp "$DEV/manifest.json" "$DEV/products.csv" "$DEV/campaigns.csv" "${TMPDIR:-/tmp}/ck-empty-in/"
$BIN "${TMPDIR:-/tmp}/ck-empty-in" "${TMPDIR:-/tmp}/ck-empty" >/dev/null
python3 - "${TMPDIR:-/tmp}/ck-empty" <<'PY'
import sys
import pyarrow.dataset as ds
for t in ("user_daily", "campaign_daily"):
    d = ds.dataset(f"{sys.argv[1]}/{t}", format="parquet").to_table()
    assert d.num_rows == 0, t
    print(f"  {t}: 0 rows, schema {[str(f.type) for f in d.schema]}")
PY

if [ -x "$GEN" ]; then
  say "fresh seeds"
  for s in 2 77 404; do
    dir=${TMPDIR:-/tmp}/ck-seed$s
    [ -d "$dir" ] || "$GEN" --seed $s --events 2000000 --clicks 500000 --output "$dir" >/dev/null
    echo "  seed $s"
    ./tools/consistency.sh "$dir" | sed 's/^/  /'
  done
else
  say "fresh seeds skipped (no generate binary at $GEN)"
fi

say "all checks finished"
