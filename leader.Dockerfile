FROM rustlang/rust:nightly-bullseye-slim as builder

RUN apt-get update && apt-get install -y libjemalloc2 libjemalloc-dev make libssl-dev pkg-config

RUN mkdir -p zero_bin
COPY Cargo.toml .
# Cleanup all workspace members and add selected crates again
RUN sed -i '/members =/{:a;N;/]/!ba};//d' Cargo.toml
RUN sed -i 's#\[workspace\]#\[workspace\]\nmembers = \["zero_bin\/leader", "zero_bin\/prover", "zero_bin\/rpc", "zero_bin\/common", \
 "zero_bin\/ops"\, "evm_arithmetization", "trace_decoder", "mpt_trie", "proc_macro", "compat"\]#' Cargo.toml
COPY Cargo.lock .
COPY ./rust-toolchain.toml ./
RUN cat ./Cargo.toml
COPY ./.env ./.env

COPY proof_gen proof_gen
COPY mpt_trie mpt_trie
COPY proc_macro proc_macro
COPY compat compat
COPY trace_decoder trace_decoder
COPY evm_arithmetization evm_arithmetization
COPY zero_bin/common zero_bin/common
COPY zero_bin/ops zero_bin/ops
COPY zero_bin/rpc zero_bin/rpc
COPY zero_bin/prover zero_bin/prover
COPY zero_bin/leader zero_bin/leader


RUN \
  touch zero_bin/common/src/lib.rs && \
  touch zero_bin/ops/src/lib.rs && \
  touch zero_bin/leader/src/main.rs && \
  touch zero_bin/rpc/src/lib.rs && \
  touch zero_bin/prover/src/lib.rs && \
  touch evm_arithmetization/src/lib.rs && \
  touch trace_decoder/src/lib.rs && \
  touch mpt_trie/src/lib.rs && \
  touch proc_macro/src/lib.rs && \
  touch compat/src/lib.rs

# Disable the lld linker for now, as it's causing issues with the linkme package.
# https://github.com/rust-lang/rust/pull/124129
# https://github.com/dtolnay/linkme/pull/88
ENV RUSTFLAGS='-C target-cpu=native -Zlinker-features=-lld'

RUN cargo build --release --bin leader
RUN cargo build --release --bin rpc


FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y ca-certificates libjemalloc2
COPY --from=builder ./target/release/leader /usr/local/bin/leader
COPY --from=builder ./target/release/rpc /usr/local/bin/rpc
COPY --from=builder ./.env /.env

# Workaround for the issue with the Cargo.lock search path
# Related to issue https://github.com/0xPolygonZero/zk_evm/issues/311
RUN mkdir -p zero_bin/leader

ENTRYPOINT ["/usr/local/bin/leader"]
