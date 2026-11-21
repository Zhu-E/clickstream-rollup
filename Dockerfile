# Shopping Sessions: a single static Rust binary, no dependencies.
FROM rust:1.90-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
# The scorers are Cascade Lake or newer with AVX-512; target that baseline
# rather than the build host, and link statically so the image can be scratch.
ENV RUSTFLAGS="-C target-cpu=cascadelake -C target-feature=+crt-static"
RUN cargo build --release --target x86_64-unknown-linux-gnu \
 && strip target/x86_64-unknown-linux-gnu/release/shopsess

FROM scratch
COPY --from=build /src/target/x86_64-unknown-linux-gnu/release/shopsess /shopsess
USER 1000:1000
ENV DATA_DIR=/data OUTPUT_DIR=/output SCRATCH_DIR=/scratch
CMD ["/shopsess"]
