# Shopping Sessions

A single-binary Rust implementation of the Buildathon *Shopping Sessions* track:
it reads ~60M messy click-stream rows from `/data` and writes the two daily
Parquet tables to `/output`.

No third-party crates, no runtime dependencies: the image is a statically
linked binary on `scratch`, so the build needs no network beyond the Rust base
image and the run needs none at all.

## How it works

Five passes, each parallel over 8 threads, over one bump-allocated arena backed
by transparent huge pages.

1. **Links.** Every `links/*.csv` row is parsed in parallel, then a union-find
   joins the ids into people. A person is named by the byte-wise smallest of
   its ids, and that name's hash becomes the person key, so a key never needs a
   second lookup later. Ids that appear in no link are their own person.
2. **Parse.** Event and click files are cut into 1 MiB chunks and parsed
   independently. A line is scanned once, word at a time, for `,`, `\n` and
   `"`; the quote positions become a bitmap, which makes unquoting and the
   "a quote anywhere else is malformed" rule a couple of shifts. Timestamps go
   through a 64-entry cache keyed on `YYYY-MM-DD`, so the calendar arithmetic
   runs a handful of times per thread instead of 60M; the rest of a timestamp
   is validated and converted with SWAR digit tricks. Each event is scattered
   into one of up to 8192 buckets by its `event_id`, clicks into buckets by
   person.
3. **Dedup.** Each event-id bucket is small enough to dedup in cache: one
   open-addressing table keyed on a 96-bit event-id key (exact, not a hash, for
   ids up to 11 bytes) keeps the copy with the smallest `ingest_ts`. Survivors
   that pass validation are scattered again, now by person.
4. **Fold.** A person bucket is grouped by a counting sort, each person's rows
   are ordered by timestamp, and then one pass sessionizes, picks the credited
   campaign with a sliding window over the person's clicks, and accumulates
   per-day totals. Assists are not counted per session: each campaign's clicks
   are merged into `[click, click + 7 days]` intervals and the sessions in an
   interval are counted per day from a prefix sum, which keeps whale people
   (thousands of clicks, tens of thousands of sessions) linear instead of
   quadratic.
5. **Write.** Each thread writes its own `user_daily` Parquet file as it
   finishes folding; `campaign_daily` is a dense `(campaign, day)` array
   reduced across threads. The Parquet writer is ~250 lines: one row group,
   one uncompressed PLAIN page per column, Thrift-compact metadata.

Correctness notes worth keeping in mind if you change the code:

- `hits()` must stay carry-free. The usual `x - 0x01..01 & !x & 0x80..80`
  byte-match reports a phantom match one byte above a real one, which turns
  `,-5` into two commas and silently drops every line with a negative price.
- The person table is cleared by the slot indices recorded at insert time.
  Re-probing to find them stops at a slot already zeroed and leaves live
  entries behind, which fills the table a few hundred buckets later.
- Credit depends on the session start, not just on which clicks precede it: a
  cache keyed on the click index alone credits sessions that are more than
  7 days after their last click.

## Build and test

```sh
make test       # unit tests for the timestamp and id encodings
make fixtures   # all 36 edge-case fixtures, native binary
make dev        # exact diff against the published 1M-event dev answer
make build      # the linux/amd64 image the scorer runs
make bench DATA=../data/d20 N=5
```

`tools/cmp.py` is an exact, order-insensitive diff (needs `pyarrow`);
`tools/fixtures.sh` runs every fixture through it.

`SS_TIMING=1` prints a per-stage breakdown on stderr. `SS_BENCH=<0..6>` runs
only the parse stage with that many steps enabled, which is how the per-step
costs above were measured.

## Libraries and pre-existing code

None. The only dependency is the Rust standard library; `mmap`/`madvise` are
declared directly. The two algorithms taken from the literature are Howard
Hinnant's `days_from_civil`, and the SWAR eight-digit parse used in many
fast number parsers.
