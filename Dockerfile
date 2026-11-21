# Probe build, not a scoring build: four builds of the same source and the
# track's generator, so one run can compare them on a genuine dataset.
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN mkdir /out /gen
ENV BASE="-C target-cpu=cascadelake -C strip=symbols"
RUN RUSTFLAGS="$BASE" cargo build --release --offline && cp target/release/shopsess /out/shopsess
# branch alignment for the jump erratum on this cpu family
RUN (RUSTFLAGS="$BASE -C llvm-args=-x86-branches-within-32B-boundaries" cargo build --release --offline --target-dir /t/jcc \
    && cp /t/jcc/release/shopsess /out/v-jcc) || true
# staged sink with non-temporal stores
RUN (SS_WC=1 RUSTFLAGS="$BASE" cargo build --release --offline --target-dir /t/wc \
    && cp /t/wc/release/shopsess /out/v-wc) || true
# no avx-512 at all
RUN (RUSTFLAGS="-C target-cpu=skylake -C strip=symbols" cargo build --release --offline --target-dir /t/avx2 \
    && cp /t/avx2/release/shopsess /out/v-avx2) || true
# fetched at build time, where the network is allowed
RUN ( apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends curl unzip ca-certificates \
    && curl -fsSL -o /tmp/g.zip https://www.joinbuilders.org/buildathon/tracks/shopping-sessions/files/generator.zip \
    && unzip -q /tmp/g.zip -d /tmp/g \
    && cd /tmp/g/generator \
    && cargo build --release \
    && cp target/release/generate /gen/generate ) || true

FROM debian:bookworm-slim
COPY --from=build /out/ /app/
COPY --from=build /gen /app/gen
USER 1000:1000
ENV DATA_DIR=/data OUTPUT_DIR=/output SCRATCH_DIR=/scratch
CMD ["/app/shopsess"]
