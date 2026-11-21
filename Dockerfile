# Shopping Sessions: one Rust binary, standard library only, no network needed
# at build time beyond the base images and none at all at run time.
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# The scorers are Cascade Lake or newer Intel Xeons with AVX-512; target that
# baseline rather than the build host. Stripping is done by rustc so the image
# needs no extra tools.
# glibc is linked statically, so the binary needs no loader and no files from
# the image and runs on an empty base. Static glibc rather than musl: musl's
# malloc and memcpy cost 60-75 ms on 20M events, more than start-up saves.
# Nothing here uses NSS or dlopen, which is what static glibc cannot do.
ENV RUSTFLAGS="-C target-cpu=cascadelake -C strip=symbols -C target-feature=+crt-static"
RUN cargo build --release --offline

# Nothing but the binary. No /tmp, /etc or users are needed: the scorer mounts
# /data, /output, /scratch and a tmpfs /tmp, and a numeric uid needs no passwd.
FROM scratch
COPY --from=build /src/target/release/shopsess /app/shopsess
USER 1000:1000
ENV DATA_DIR=/data OUTPUT_DIR=/output SCRATCH_DIR=/scratch
CMD ["/app/shopsess"]
