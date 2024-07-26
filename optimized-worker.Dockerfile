FROM rustlang/rust:nightly-bullseye-slim as builder

# Install jemalloc
RUN apt-get update && apt-get install -y libjemalloc2 libjemalloc-dev make libssl-dev pkg-config

# Install llvm-tools-preview (requirement for cargo-pgo to compile an optimized binary)
RUN rustup component add llvm-tools-preview

# Install cargo-pgo, used for building an optimized binary from the gathered profiling data
RUN cargo install cargo-pgo

RUN mkdir -p zero_bin
COPY Cargo.toml .
# Cleanup all workspace members and add selected crates again
RUN sed -i '/members =/{:a;N;/]/!ba};//d' Cargo.toml
RUN sed -i 's#\[workspace\]#\[workspace\]\nmembers = \["zero_bin\/worker", "zero_bin\/common", "zero_bin\/ops"\, "evm_arithmetization", "mpt_trie", "proc_macro"\]#' Cargo.toml
COPY Cargo.lock .
COPY ./rust-toolchain.toml ./

COPY proof_gen proof_gen
COPY mpt_trie mpt_trie
COPY evm_arithmetization evm_arithmetization
COPY proc_macro proc_macro
COPY zero_bin/common zero_bin/common
COPY zero_bin/ops zero_bin/ops
COPY zero_bin/worker zero_bin/worker

RUN \
  touch zero_bin/common/src/lib.rs && \
  touch zero_bin/ops/src/lib.rs && \
  touch zero_bin/worker/src/main.rs && \
  touch evm_arithmetization/src/lib.rs && \
  touch mpt_trie/src/lib.rs && \
  touch proc_macro/src/lib.rs

ENV RUSTFLAGS='-C target-cpu=native -Zlinker-features=-lld'

COPY ./target/pgo-profiles/*.profraw ./target/pgo-profiles/

RUN cargo pgo optimize build -- --bin worker

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y ca-certificates libjemalloc2 make libssl-dev
COPY --from=builder ./target/x86_64-unknown-linux-gnu/release/worker /usr/local/bin/worker
CMD ["worker"]