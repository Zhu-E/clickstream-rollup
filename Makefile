IMAGE ?= shopsess:latest
CPUS  ?= 8
MEM   ?= 24g
PLATFORM ?= linux/amd64
DEV   ?= ../data/dev
export IMAGE CPUS MEM PLATFORM

.PHONY: build test fixtures dev bench native

## Build the scorer's image
build:
	docker buildx build --platform $(PLATFORM) --load -t $(IMAGE) .

## Build a native binary for local iteration
native:
	cargo build --release

## Unit tests (timestamp and key encodings)
test:
	cargo test --release

## Run the native binary on all 36 edge-case fixtures and diff
fixtures: native
	BIN=./target/release/shopsess FIX=fixtures tools/fixtures.sh

## Diff against the published 1M-event dev answer: make dev ANSWER=../ex/dev-answer/dev-answer
ANSWER ?= ../ex/dev-answer/dev-answer
dev: native
	rm -rf /tmp/ss-dev && ./target/release/shopsess $(DEV) /tmp/ss-dev
	python3 tools/cmp.py /tmp/ss-dev $(ANSWER)

## Time the native binary: make bench DATA=../data/d20 N=5
DATA ?= ../data/d20
N ?= 5
bench: native
	cd .. && solution/tools/bench.sh $(DATA) $(N)
