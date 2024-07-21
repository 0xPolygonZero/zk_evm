# NOTE: only a single worker needs to be deployed in k8s for this step.

# BONUS NOTE: recommended block=4825, checkpoint=4824
#   but this will need to be specified by the coordinator

FROM rustlang/rust:nightly-bullseye-slim@sha256:2be4bacfc86e0ec62dfa287949ceb47f9b6d9055536769bdee87b7c1788077a9 as builder

# Install jemalloc
RUN apt-get update && apt-get install -y ca-certificates libjemalloc2 libjemalloc-dev make clang-16

# Install cargo-pgo, used for building a binary with profiling enabled
RUN cargo install cargo-pgo

RUN \
    mkdir -p common/src  && touch common/src/lib.rs && \
    mkdir -p ops/src     && touch ops/src/lib.rs && \
    mkdir -p worker/src  && echo "fn main() {println!(\"YO!\");}" > worker/src/main.rs

COPY Cargo.toml .
RUN sed -i "2s/.*/members = [\"common\", \"ops\", \"worker\"]/" Cargo.toml
COPY Cargo.lock .

COPY common/Cargo.toml ./common/Cargo.toml
COPY ops/Cargo.toml ./ops/Cargo.toml
COPY worker/Cargo.toml ./worker/Cargo.toml

COPY ./rust-toolchain.toml ./

# do not need to specify `--release`, it is added automatically by `cargo pgo`.
RUN cargo pgo build -- --bin worker

COPY common ./common
COPY ops ./ops
COPY worker ./worker
RUN \
    touch common/src/lib.rs && \
    touch ops/src/lib.rs && \
    touch worker/src/main.rs

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
CMD ["python3", "pgo_worker_wrapper.py"]
