#!/bin/sh
# Run the binary on every fixture and diff against expected/
BIN="${BIN:-./solution/target/release/shopsess}"
FIX="${FIX:-ex/starter-polars/starter-polars/fixtures}"
TMP=$(mktemp -d)
pass=0; fail=0; failed=""
for d in "$FIX"/*/; do
  name=$(basename "$d")
  rm -rf "$TMP/$name"; mkdir -p "$TMP/$name"
  if ! "$BIN" "$d/input" "$TMP/$name" >/dev/null 2>"$TMP/$name.err"; then
    echo "$name: CRASH"; cat "$TMP/$name.err" | head -3; fail=$((fail+1)); failed="$failed $name"; continue
  fi
  if out=$(python3 tools/cmp.py "$TMP/$name" "$d/expected" 3 2>&1); then
    pass=$((pass+1))
  else
    fail=$((fail+1)); failed="$failed $name"
    echo "=== $name FAILED"; echo "$out"
  fi
done
echo "passed $pass, failed $fail:$failed"
echo "tmp=$TMP"
