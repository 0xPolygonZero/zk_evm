# NOTE: only a single worker needs to be deployed in k8s for this step.

# BONUS NOTE: recommended block=4825, checkpoint=4824
#   but this will need to be specified by the coordinator

FROM rustlang/rust:nightly-bullseye-slim as builder

RUN apt-get update && apt-get install -y libjemalloc2 libjemalloc-dev make libssl-dev pkg-config

# Install cargo-pgo, used for building a binary with profiling enabled
RUN cargo install cargo-pgo

RUN mkdir -p zero_bin
COPY Cargo.toml .
# Cleanup all workspace members and add selected crates again
RUN sed -i '/members =/{:a;N;/]/!ba};//d' Cargo.toml
RUN sed -i 's#\[workspace\]#\[workspace\]\nmembers = \["zero_bin\/worker", "zero_bin\/common", "zero_bin\/ops"\, "evm_arithmetization", "mpt_trie", "proc_macro"\]#' Cargo.toml
COPY Cargo.lock .
COPY ./rust-toolchain.toml ./

COPY pgo_worker_wrapper.py ./zero_bin/pgo_worker_wrapper.py

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

# Disable the lld linker for now, as it's causing issues with the linkme package.
# https://github.com/rust-lang/rust/pull/124129
# https://github.com/dtolnay/linkme/pull/88
ENV RUSTFLAGS='-C target-cpu=native -Zlinker-features=-lld'

RUN cargo pgo build -- --bin worker

# NOTE: cannot use a separate runtime environment, because the pgo-binary doesn't seem to be generating its profiling data (found during testing).
#FROM debian:bullseye-slim
#RUN apt-get update && apt-get install -y ca-certificates libjemalloc2
#COPY --from=builder ./target/x86_64-unknown-linux-gnu/release/worker /usr/local/bin/worker
#COPY pgo_worker_wrapper.py /usr/local/bin/pgo_worker_wrapper.py

# Install python3 and pip for the wrapper script
RUN apt-get install -y python3 python3-pip

# Install the google-cloud-storage dependency for the wrapper script
RUN pip3 install google-cloud-storage

# NOTE: the bucket name should be set WITHOUT the `gs://` prefix
#  BONUS NOTE: should we create a different bucket just for .profraw files?
ENV GCS_UPLOAD_BUCKET=zkevm-csv
ENV WORKER_PATH=./target/x86_64-unknown-linux-gnu/release/worker
ENV PROFILE_DIRECTORY=./target/pgo-profiles/
# run the python wrapper, which will:
#   1. execute the pgo-worker binary
#   2. wait to receive a signal (either SIGTERM or SIGKILL), then sends a SIGTERM to the pgo-worker binary
#   3. upload the created pgo .profraw file to GCS
CMD ["python3", "zero_bin/pgo_worker_wrapper.py"]
