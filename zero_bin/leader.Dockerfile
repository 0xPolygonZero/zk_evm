FROM rustlang/rust:nightly-bullseye-slim as builder

# Install jemalloc
RUN apt-get update && apt-get install -y libjemalloc2 libjemalloc-dev make

RUN \
  mkdir -p ops/src     && touch ops/src/lib.rs && \
  mkdir -p common/src  && touch common/src/lib.rs && \
  mkdir -p rpc/src     && touch rpc/src/lib.rs && \
  mkdir -p leader/src  && echo "fn main() {println!(\"YO!\");}" > leader/src/main.rs

COPY Cargo.toml .
RUN sed -i "2s/.*/members = [\"ops\", \"leader\", \"common\", \"rpc\"]/" Cargo.toml
COPY Cargo.lock .

COPY ops/Cargo.toml ./ops/Cargo.toml
COPY common/Cargo.toml ./common/Cargo.toml
COPY rpc/Cargo.toml ./rpc/Cargo.toml
COPY leader/Cargo.toml ./leader/Cargo.toml

RUN cargo build --release --bin leader 

COPY ops ./ops
COPY common ./common
COPY rpc ./rpc
COPY leader ./leader
RUN \
  touch ops/src/lib.rs && \
  touch common/src/lib.rs && \
  touch rpc/src/lib.rs && \
  touch leader/src/main.rs

RUN cargo build --release --bin leader 

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y ca-certificates libjemalloc2
COPY --from=builder ./target/release/leader /usr/local/bin/leader
CMD ["leader"]
