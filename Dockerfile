# Probe build, not a scoring build: the pipeline plus the track's own
# generator, so the probe can time a genuine practice-sized dataset.
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
ENV RUSTFLAGS="-C target-cpu=cascadelake -C strip=symbols"
RUN cargo build --release --offline
# fetched at build time, where the network is allowed; the probe falls back if this fails
RUN mkdir /gen && ( apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends curl unzip ca-certificates \
    && curl -fsSL -o /tmp/g.zip https://www.joinbuilders.org/buildathon/tracks/shopping-sessions/files/generator.zip \
    && unzip -q /tmp/g.zip -d /tmp/g \
    && cd /tmp/g/generator \
    && cargo build --release \
    && cp target/release/generate /gen/generate ) || true

FROM debian:bookworm-slim
COPY --from=build /src/target/release/shopsess /app/shopsess
COPY --from=build /gen /app/gen
USER 1000:1000
ENV DATA_DIR=/data OUTPUT_DIR=/output SCRATCH_DIR=/scratch
CMD ["/app/shopsess"]
