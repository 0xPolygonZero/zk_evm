#!/bin/bash
# ------------------------------------------------------------------------------
set -exo pipefail

# Args:
# 1 --> Input witness json file

# We're going to set the parallelism in line with the total cpu count
if [[ "$OSTYPE" == "darwin"* ]]; then
	num_procs=$(sysctl -n hw.physicalcpu)
else
	num_procs=$(nproc)
fi

# Force the working directory to always be the `tools/` directory.
REPO_ROOT=$(git rev-parse --show-toplevel)
PROOF_OUTPUT_DIR="${REPO_ROOT}/proofs"

BLOCK_BATCH_SIZE="${BLOCK_BATCH_SIZE:-8}"
echo "Block batch size: $BLOCK_BATCH_SIZE"

OUTPUT_LOG="${REPO_ROOT}/output.log"
PROOFS_FILE_LIST="${PROOF_OUTPUT_DIR}/proof_files.json"

# Configured Rayon and Tokio with rough defaults
export RAYON_NUM_THREADS=$num_procs
export TOKIO_WORKER_THREADS=$num_procs

export RUST_MIN_STACK=33554432
export RUST_BACKTRACE=full
export RUST_LOG=info

INPUT_FILE=$1

if [[ $INPUT_FILE == "" ]]; then
	echo "Please provide witness json input file, e.g. artifacts/witness_b19240705.json"
	exit 1
fi

start_time=$(date +%s%N)
perf stat -e cycles "${REPO_ROOT}/target/release/leader" --runtime in-memory --load-strategy monolithic --block-batch-size "$BLOCK_BATCH_SIZE" \
	--proof-output-dir "$PROOF_OUTPUT_DIR" stdio < "$INPUT_FILE" &> "$OUTPUT_LOG"
end_time=$(date +%s%N)

set +o pipefail
grep "Successfully wrote to disk proof file" "$OUTPUT_LOG" | awk '{print $NF}' | tee "$PROOFS_FILE_LIST"
if [ ! -s "$PROOFS_FILE_LIST" ]; then
	# Some error occurred, display the logs and exit.
	cat "$OUTPUT_LOG"
	echo "Proof list not generated, some error happened. For more details check the log file $OUTPUT_LOG"
	exit 1
fi

duration_ns=$((end_time - start_time))
duration_sec=$(echo "$duration_ns / 1000000000" | bc -l)

echo "Success!"
echo "Proving duration: $duration_sec seconds"
echo "Note, this duration is inclusive of circuit handling and overall process initialization"
