# Shopping Sessions

A single-binary Rust implementation of the Buildathon *Shopping Sessions*
track: it reads tens of millions of messy click-stream rows from `/data` and
writes the two daily Parquet tables to `/output`.

No third-party crates and nothing but the Rust standard library, so the image
is one ~500 KB binary; it needs no network at run time and no files outside
`/data` and `/output`.

## How it works

Five passes, each spread over all eight threads, over one bump-allocated arena
backed by transparent huge pages.

1. **Links.** Every `links/*.csv` row is parsed in parallel, then a union-find
   joins the ids into people. A person is named by the byte-wise smallest of
   its ids, and that name *is* the person key: ids that fit ten bytes of the
   63-symbol alphabet are packed six bits to a byte into a u64, which is
   injective and keeps byte order, so comparing two keys compares two ids and
   a record never has to carry a pointer back to the bytes it came from. Ids
   that do not fit get a hashed key with the top bit set and their name in a
   side table — real data never needs it, which is why `SS_NOENC=1` builds a
   binary that takes that path for *every* id and has to produce the same
   answers.
2. **Parse.** Event and click files are cut into 1 MiB chunks and parsed
   independently, 8 KiB at a time in two passes (`split.rs`). The first
   compares 64 bytes against comma, quote and newline and writes down where
   the delimiters are, plus one bit per delimiter for "is a newline" and "the
   next field opens with a quote"; nothing in it branches on the data. A
   quote is legal only next to exactly one delimiter, and a field that opens
   with one must close with one, which is a handful of shifts and two `pext`
   per block. A block that breaks either rule is noted, and lines touching it
   go through the older one-line scanner, as do the last lines of a file, so
   that scanner stays the definition of the dialect. The second pass takes a
   row off the index with one test ("six commas, then a newline") and one
   vector add for all seven spans.
   Timestamps go through a 64-entry cache keyed on `YYYY-MM-DD`, so the
   calendar arithmetic runs about twenty times per thread instead of 120
   million. The time of day is one 64-bit word: every byte is checked against
   its own limit by a single carry-free add and one multiply pairs the digits.
   Epoch digits and the ten-symbol id encoding use `pmaddubsw`/`pmaddwd`.
   Resolving a user to a person
   would be a miss in a 30-130 MB link map, so a blocked Bloom filter at 16
   bits per linked id answers "no link" from one cache line and keeps the
   half of all events whose user appears in no link out of the map entirely.
   For the half that does need the map, the person key is computed and the
   slot prefetched before the event timestamp is parsed, so that miss is in
   flight during the timestamp, the window checks and the price. Map and
   filter are mapped 2 MB-aligned and `MADV_HUGEPAGE`, because at that size a
   probe misses the TLB as well as the cache.
   Each event is scattered into one of up to 8192 buckets by its `event_id`,
   each click into a bucket by person.
3. **Dedup.** An event-id bucket is sized to dedup in cache: one
   open-addressing table keyed on a 96-bit event-id key — exact, not a hash,
   for ids up to eleven bytes — keeps the copy with the smallest `ingest_ts`.
   Survivors that pass validation are scattered again, now by person, as
   16-byte rows.
4. **Fold.** A person bucket is grouped by a counting sort, each person's rows
   are ordered by timestamp, and one pass sessionizes, picks the credited
   campaign with a sliding window over that person's clicks, and accumulates
   per-day totals. Assists are not counted per session: each campaign's clicks
   are merged into `[click, click + 7 days]` intervals and the sessions in an
   interval are counted per day from a prefix sum, which keeps the shared
   devices that merge thousands of people linear instead of quadratic.
5. **Write.** Each thread writes its own `user_daily` file once every thread
   has folded, and `campaign_daily`, a dense `(campaign, day)` array reduced
   across threads, is written at the same time. The Parquet writer is about
   500 lines: one row group, one uncompressed page per column, Thrift-compact
   metadata, written straight from the column buffers. Integers in a narrow
   range (`day`, the counts) and `top_category` are bit-packed dictionary
   indexes, and the integer columns are INT32 when every value of the run
   fits, which the threads agree on before any of them writes: files of one
   table must not differ in type. That halves the output.

Any block of 2 MB or more is allocated on huge pages (`HugeAlloc` in
`sys.rs`), because 4K anonymous memory costs twice as much to touch and
twenty times as much to give back at exit, and the process leaves with
`exit` as soon as both tables are closed.

### Things that bit, and would bite again

- `hits()` must stay carry-free. The usual `x - 0x01..01 & !x & 0x80..80`
  byte-match reports a phantom match one byte above a real one, which turns
  `,-5` into two commas and silently drops every line with a negative price.
- The per-bucket person table is cleared by the slot indices recorded at
  insert time. Re-probing to find them stops at a slot already zeroed and
  leaves live entries behind, which fills the table a few hundred buckets
  later and spins forever.
- Keys here are dense encodings, not hashes, so the hash tables mix before
  masking. One table was still probing on raw low bits, which made link
  building seven times slower than it needed to be.
- With `target-cpu=cascadelake` the compiler will reach for 512-bit registers
  on its own: eight scalar `tzcnt` stores were packed into `zmm` with
  `vplzcntq`, and two adjacent 256-bit compares were merged into one. Both
  were slower, and on Cascade Lake any 512-bit use lowers the clock for
  everything around it. The stores are volatile for that reason; `objdump -d
  | grep zmm` should show nothing in a hot loop.
- A closure called from two places is not inlined, and vector constants that
  are live across a call are reloaded after it. The row callback is forced
  inline and the indexer is forced out of line: left to the compiler, the
  callback was a real call per row and the indexer's three comparison
  constants were reloaded inside every timestamp.
- Credit depends on the session start, not just on which clicks precede it: a
  cache keyed on the click index alone credits sessions more than seven days
  after their last click.

## Build and test

```sh
make build        # the linux/amd64 image the scorer runs
make test         # unit tests for the timestamp and id encodings
make fixtures     # all 36 edge-case fixtures, native binary
make dev          # exact diff against the published 1M-event dev answer
tools/check_all.sh   # everything below, in one go
make bench DATA=../data/d20 N=5
```

`tools/check_all.sh` runs: unit tests; the exact dev diff; all 36 fixtures;
the same two against the scalar scanner (`SS_NOSIMD=1`) and against the
all-ids-hashed binary (`SS_NOENC=1`); identical output under
`NCPU=1,3,5,8` plus the rules' own cross-table totals, on the dev set and on
three freshly generated seeds; a products file padded and rewritten to 40 and
to 200 categories, checked against the answer on every column the rewrite
leaves alone (all of them when padding); a person-day whose revenue needs 64
bits; every installed Parquet reader (pyarrow, polars, duckdb) seeing the same
rows; and inputs with no rows, no clicks and no links at all.

The x86 scanner cannot be executed on an arm64 laptop, so startup compares the
vector scanner against the scalar one over delimiters at every offset, runs of
them, lines shorter than a block and lines longer than the mask. A
disagreement switches the run to the scalar path and says so on stderr, so a
mistake in a path I cannot run here costs speed, not correctness. Deliberately
breaking the vector path is part of how that was checked. The two-pass
splitter gets the same treatment: startup runs it and the one-line scanner
over a few hundred made-up lines (every field count, quotes in every wrong
place, a line longer than a batch) and over lines laid out so that a quote or
a delimiter sits on each side of a 64-byte boundary, and any difference in the
rows handed out sends the whole run down the old path. The unit tests do the
same over some twenty megabytes of such lines with chunk boundaries anywhere,
and `SS_SPLIT_DIR=<dataset> cargo test --release rows_match_on_files` does it
over real files. Twelve deliberate breaks of the first pass (a carry dropped,
a rule left out, the chunk end ignored) were each caught by the unit tests
and by the startup check.

`SS_TIMING=1` prints a per-stage breakdown on stderr, including the share of
rows that pass validation (97.8% on the dev set, which is why the person key
is computed before validation rather than after). `SS_MEM=1` adds how much
anonymous memory is still mapped at exit and how much of it is on 4K pages.
`SS_BENCH=<0..6>` runs
only the parse with that many steps enabled, which is how the per-step costs
were measured; `tools/perf.sh` reports instructions retired and cycles, which
unlike wall time do not move when a laptop throttles.

### Measured and rejected

- **Non-temporal stores for the shuffle.** Holding records back per bucket and
  writing whole 64-byte lines with `vmovntdq` (`stnp` on aarch64) should save
  the read-for-ownership on 3.6 GB of record writes. Interleaved, min of six,
  parse only: 27.88 Gcycles storing each record straight into its bucket,
  28.86 with the staging and ordinary stores, 28.60 with the staging and the
  non-temporal store. The staging costs 3.5% and the instruction gives 0.9%
  of it back, so it is a 2.6% loss. The reason is fanout: one line per bucket
  is 128-512 KB of staging, which fits L1 on neither machine, so every record
  is written and read again a level further out. And the saving it chases is
  small -- the whole pipeline moves about 12 GB in a few seconds, nowhere near
  either machine's memory bandwidth, so read-for-ownership traffic is not
  where the time goes. Kept behind `SS_WC=1`, with `SS_NONT=1` to separate the
  two effects, because a machine that *is* bandwidth bound would flip it.
- **A wider hoist for the prefetch.** Prefetching the Bloom block as well, and
  computing the person key before the ingest timestamp, cost three times the
  instructions for the same cycles as prefetching the map alone. The filter is
  L2-resident; only the map probe is worth covering.
- **Merging the two shuffles.** Duplicate events may name different users, so
  dedup has to be global by `event_id` before anything is grouped by person.
- **28-byte packed event records.** The bytes saved come straight back as
  records that straddle cache lines.
- **64-bit hashed dedup keys.** A one-in-ten-thousand chance of silently
  dropping an event is not worth 8 bytes a row.

## Numbers

Best of five on an M3 MacBook Air (8 threads), which is not the scorer:
1.12 s for 20M events / 5M clicks (1.8 GB), of which about 0.2 s is startup
and link building, 0.6 s parse, 0.15 s dedup, 0.2 s fold. The same code and
machine took 2.3 s before this round of work.

Wall time on a laptop swings by a factor of two under thermal throttling, and
at 40M the input stops fitting in the page cache, so none of these numbers
came off a stopwatch. Builds were compared interleaved, min of five or six, on
instructions retired and cycles elapsed, mostly with `SS_BENCH` running the
parse alone; a 2% difference is invisible without that. Work per row is flat
with scale -- 1074 instructions per event row at 20M against 1102 at 40M --
which is the reason to expect 60M to scale. Peak RSS is about
2.3× the input size and the 60M-event case fits in well under the scorer's
24 GB. Work per row is flat with scale: 1074 instructions per event row at
20M, 1102 at 40M.

## Libraries and pre-existing code

None. The only dependency is the Rust standard library; `mmap`, `madvise` and
`munmap` are declared directly. The two algorithms taken from the literature
are Howard Hinnant's `days_from_civil` and the SWAR eight-digit parse used in
many fast number parsers.
