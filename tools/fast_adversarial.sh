#!/bin/bash
# fast_adversarial.sh [BASE_DATASET ...]
# The fast path against the forced general pipeline (SS_NOFAST=1): outputs
# must be identical on the datasets as they are, on fresh seeds at several
# thread counts, and on variants that break the structure the fast path
# uses (tools/fast_adversarial.py). Run from the workspace that holds
# data/, tools/ and the generator; BIN names the binary.
#   SEEDS="11 12"  fresh seeds to generate (2M events each); empty to skip
#   JOBS=4         datasets checked at once; every dataset is one job
#   ADV_CACHE=dir  built variants and seeds, reused while the inputs and
#                  fast_adversarial.py are unchanged (default under TMPDIR)
set -u
BIN="${BIN:-./solution/target/release/shopsess}"
HERE="$(cd "$(dirname "$0")" && pwd)"
GEN="${GEN:-ex/generator/generator/target/release/generate}"
CMP="${CMP:-tools/cmpout.py}"
TMP="${TMPDIR:-/tmp}/fast-adv.$$"
SEEDS="${SEEDS-11 12}"
JOBS="${JOBS:-4}"
CACHE="${ADV_CACHE:-${TMPDIR:-/tmp}/fast-adv-cache}"
bases="${*:-data/tiny data/dev}"
mkdir -p "$TMP" "$CACHE"
hash() { cksum | cut -d" " -f1; }
VKEY=$(hash < "$HERE/fast_adversarial.py")

# pair NAME DATA [ENV...]: fast vs forced general, in the job's own folder $W
pair() {
  name=$1; data=$2; shift 2
  rm -rf "$W/a" "$W/b"
  env "$@" SS_TIMING=1 "$BIN" "$data" "$W/a" 2>"$W/a.err" || { echo "FAIL $name: fast run crashed"; tail -3 "$W/a.err"; return; }
  SS_NOFAST=1 "$BIN" "$data" "$W/b" 2>/dev/null || { echo "FAIL $name: general run crashed"; return; }
  if grep -q "fast: gave up" "$W/a.err"; then how="fell back ($(grep -o 'gave up.*' "$W/a.err" | head -1))"
  elif grep -q "folded here" "$W/a.err"; then how="fast ($(grep -o 'odd [0-9]* esc [0-9]* odd clicks [0-9]*' "$W/a.err"), $(grep -o 'folded here [0-9]* general [0-9]*' "$W/a.err"))"
  else how="general (no keys)"; fi
  # every user_daily file must agree on its column types
  types=$(python3 -c "
import glob, sys, pyarrow.parquet as pq
print(len({str(pq.read_schema(f)) for f in glob.glob(sys.argv[1] + '/user_daily/*.parquet')}), pq.read_schema(sorted(glob.glob(sys.argv[1] + '/user_daily/*.parquet'))[0]).field('revenue_cents').type)" "$W/a")
  case "$types" in "1 "*) how="$how, ${types#1 }";; *) echo "FAIL $name $*: user_daily files disagree on types";; esac
  if [ -f "$HERE/readers.py" ] && ! python3 "$HERE/readers.py" "$W/a" >"$W/rd.txt" 2>&1; then
    echo "FAIL $name $*: a reader rejected the output"; tail -3 "$W/rd.txt"
  fi
  if python3 "$CMP" "$W/a" "$W/b" >"$W/cmp.txt" 2>&1; then
    echo "ok   $name $*: $how"
  else
    echo "FAIL $name $*: $how"; head -6 "$W/cmp.txt"
  fi
}

# cached DIR CMD...: run CMD OUT to build DIR unless DIR.done says it is there;
# built under a private name and moved into place whole, so runs can share it
cached() {
  dir=$1; shift
  [ -f "$dir.done" ] && return 0
  part="$dir.part.$$.$k"
  rm -rf "$part"
  "$@" "$part" || { rm -rf "$part"; return 1; }
  [ -e "$dir" ] || mv "$part" "$dir"
  rm -rf "$part"
  touch "$dir.done"
}

# one job per dataset; each writes its own log, printed in order at the end
job_base() {  # base
  echo "== $1"
  pair "$(basename "$1")" "$1"
  for n in 1 3; do pair "$(basename "$1")" "$1" NCPU=$n; done
}
job_variant() {  # base variant
  base=$1; v=$2
  d="$CACHE/v-$(cd "$base" && pwd | hash)-$VKEY-$v"
  cached "$d" build_variant "$base" "$v" || { echo "FAIL $v: could not build the variant"; return; }
  pair "$(basename "$base")/$v" "$d"
  # the same with the odd-row limit lifted, so the merge paths run too
  pair "$(basename "$base")/$v" "$d" SS_FODD=1000000000
  pair "$(basename "$base")/$v" "$d" NCPU=3 SS_FSHIFT=9
  case "$v" in *link*) for n in 1 8; do pair "$(basename "$base")/$v" "$d" NCPU=$n; done;; esac
}
build_variant() { python3 "$HERE/fast_adversarial.py" "$1" "$3" "$2" >/dev/null; }
job_seed() {  # seed
  echo "== fresh seed $1"
  g="$CACHE/seed-$1-$(hash < "$GEN")"
  cached "$g" "$GEN" --seed "$1" --events 2000000 --clicks 500000 --output >/dev/null 2>&1 || { echo "FAIL: generator"; return; }
  for n in 1 3 8; do pair "seed$1" "$g" NCPU=$n; done
  pair "seed$1" "$g" SS_FSHIFT=15
  pair "seed$1" "$g" SS_NOSIMD=1
}

variants=$(python3 "$HERE/fast_adversarial.py" list)
k=0
run() {  # run KIND ARGS...: start one job in the background, at most JOBS at once
  k=$((k + 1))
  while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do sleep 0.2; done
  ( W="$TMP/w$k"; mkdir -p "$W"; "$@" > "$TMP/log.$(printf %04d $k)" 2>&1 ) &
}
for base in $bases; do
  run job_base "$base"
  for v in $variants; do run job_variant "$base" "$v"; done
done
for seed in $SEEDS; do run job_seed "$seed"; done
wait

cat "$TMP"/log.*
fail=0
grep -q "^FAIL" "$TMP"/log.* && fail=1
rm -rf "$TMP"
if [ "$fail" = 0 ]; then echo "ADVERSARIAL PASS"; else echo "ADVERSARIAL FAILED"; fi
exit $fail
