#!/bin/bash
# fast_adversarial.sh [BASE_DATASET ...]
# The fast path against the forced general pipeline (SS_NOFAST=1): outputs
# must be identical on the datasets as they are, on fresh seeds at several
# thread counts, and on variants that break the structure the fast path
# uses (tools/fast_adversarial.py). Run from the workspace that holds
# data/, tools/ and the generator; BIN names the binary.
#   SEEDS="11 12"  fresh seeds to generate (2M events each); empty to skip
set -u
BIN="${BIN:-./solution/target/release/shopsess}"
HERE="$(cd "$(dirname "$0")" && pwd)"
GEN="${GEN:-ex/generator/generator/target/release/generate}"
CMP="${CMP:-tools/cmpout.py}"
TMP="${TMPDIR:-/tmp}/fast-adv.$$"
SEEDS="${SEEDS-11 12}"
bases="${*:-data/tiny data/dev}"
mkdir -p "$TMP"
fail=0

# pair NAME DATA [ENV...]: fast vs forced general
pair() {
  name=$1; data=$2; shift 2
  rm -rf "$TMP/a" "$TMP/b"
  env "$@" SS_TIMING=1 "$BIN" "$data" "$TMP/a" 2>"$TMP/a.err" || { echo "FAIL $name: fast run crashed"; tail -3 "$TMP/a.err"; fail=1; return; }
  SS_NOFAST=1 "$BIN" "$data" "$TMP/b" 2>/dev/null || { echo "FAIL $name: general run crashed"; fail=1; return; }
  if grep -q "fast: gave up" "$TMP/a.err"; then how="fell back ($(grep -o 'gave up.*' "$TMP/a.err" | head -1))"
  elif grep -q "folded here" "$TMP/a.err"; then how="fast ($(grep -o 'odd [0-9]* esc [0-9]* odd clicks [0-9]*' "$TMP/a.err"), $(grep -o 'folded here [0-9]* general [0-9]*' "$TMP/a.err"))"
  else how="general (no keys)"; fi
  if python3 "$CMP" "$TMP/a" "$TMP/b" >"$TMP/cmp.txt" 2>&1; then
    echo "ok   $name $*: $how"
  else
    echo "FAIL $name $*: $how"; head -6 "$TMP/cmp.txt"; fail=1
  fi
}

for base in $bases; do
  echo "== $base"
  pair "$(basename "$base")" "$base"
  for n in 1 3; do pair "$(basename "$base")" "$base" NCPU=$n; done
  for v in $(python3 "$HERE/fast_adversarial.py" list); do
    rm -rf "$TMP/d"
    python3 "$HERE/fast_adversarial.py" "$base" "$TMP/d" "$v" || { echo "FAIL $v: could not build the variant"; fail=1; continue; }
    pair "$(basename "$base")/$v" "$TMP/d"
    # the same with the odd-row limit lifted, so the merge paths run too
    pair "$(basename "$base")/$v" "$TMP/d" SS_FODD=1000000000
    pair "$(basename "$base")/$v" "$TMP/d" NCPU=3 SS_FSHIFT=9
  done
done

for seed in $SEEDS; do
  echo "== fresh seed $seed"
  rm -rf "$TMP/g"
  "$GEN" --seed "$seed" --events 2000000 --clicks 500000 --output "$TMP/g" >/dev/null 2>&1 || { echo "FAIL: generator"; fail=1; continue; }
  for n in 1 3 8; do pair "seed$seed" "$TMP/g" NCPU=$n; done
  pair "seed$seed" "$TMP/g" SS_FSHIFT=15
  pair "seed$seed" "$TMP/g" SS_NOSIMD=1
done

rm -rf "$TMP"
if [ "$fail" = 0 ]; then echo "ADVERSARIAL PASS"; else echo "ADVERSARIAL FAILED"; fi
exit $fail
