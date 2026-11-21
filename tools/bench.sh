#!/bin/sh
# bench.sh DATA N  -> prints each run's stages and the min total
D="${1:-data/d20}"; N="${2:-5}"
i=0
while [ $i -lt "$N" ]; do
  rm -rf /tmp/bout
  SS_TIMING=1 NCPU=8 ./solution/target/release/shopsess "$D" /tmp/bout 2>&1 | tail -1
  i=$((i+1))
done
