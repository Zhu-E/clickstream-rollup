# Shopping Sessions: one Rust binary, standard library only, no network needed
# at build time beyond the base images and none at all at run time.
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# The scorers are Cascade Lake or newer Intel Xeons with AVX-512; target that
# baseline rather than the build host. Stripping is done by rustc so the image
# needs no extra tools.
ENV RUSTFLAGS="-C target-cpu=cascadelake -C strip=symbols"
RUN cargo build --release --offline

FROM debian:bookworm-slim
COPY --from=build /src/target/release/shopsess /app/shopsess
USER 1000:1000
ENV DATA_DIR=/data OUTPUT_DIR=/output SCRATCH_DIR=/scratch
CMD ["/app/shopsess"]
