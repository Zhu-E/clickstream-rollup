# Shopping Sessions: one Rust binary, standard library only.
# Built for linux/amd64; the scorers are Cascade Lake or newer Intel Xeons.
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
ENV RUSTFLAGS="-C target-cpu=cascadelake"
RUN cargo build --release && strip target/release/shopsess

FROM debian:bookworm-slim
COPY --from=build /src/target/release/shopsess /app/shopsess
USER 1000:1000
ENV DATA_DIR=/data OUTPUT_DIR=/output SCRATCH_DIR=/scratch
CMD ["/app/shopsess"]
