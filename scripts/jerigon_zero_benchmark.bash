#!/usr/bin/env bash
set -euxo pipefail

# Get the number of processors for parallelism
if [[ "$OSTYPE" == "darwin"* ]]; then
    num_procs=$(sysctl -n hw.physicalcpu)
else
    num_procs=$(nproc)
fi

# Force the working directory to always be the repository root.
REPO_ROOT=$(git rev-parse --show-toplevel)
PROOF_OUTPUT_DIR="${REPO_ROOT}/proofs"
BLOCK_BATCH_SIZE="${BLOCK_BATCH_SIZE:-8}"

# Logging setup
OUTPUT_LOG="jerigon_zero_benchmark.log"
BLOCK_OUTPUT_LOG="jerigon_zero_block_output.log"
ERROR_LOG="jerigon_zero_error.log"
PROOFS_FILE_LIST="${PROOF_OUTPUT_DIR}/proof_files.json"

# Ensure necessary directories exist
mkdir -p "$PROOF_OUTPUT_DIR"

# Set environment variables for parallelism and logging
export RAYON_NUM_THREADS=$num_procs
export TOKIO_WORKER_THREADS=$num_procs
export RUST_MIN_STACK=33554432
export RUST_BACKTRACE=full
export RUST_LOG=info

# Log the current date and time
date +"%Y-%m-%d %H:%M:%S" &>> "$OUTPUT_LOG"
date +"%Y-%m-%d %H:%M:%S" &>> "$ERROR_LOG"

# Function to process each block
process_block() {
    local block start_time end_time duration_sec PERF_TIME PERF_USER_TIME PERF_SYS_TIME
    block=$1

    # Fetch block data
    if ! ./target/release/rpc --rpc-url "$ETH_RPC_URL" fetch --start-block "$block" --end-block "$block" > "witness_${block}.json"; then
        echo "Failed to fetch block data for block: $block" &>> "$ERROR_LOG"
        return
    fi

    start_time=$(date +%s%N)

    # Run performance stats
    if ! perf stat -e cycles ./target/release/leader --runtime in-memory --use-test-config --load-strategy on-demand --block-batch-size "$BLOCK_BATCH_SIZE" --proof-output-dir "$PROOF_OUTPUT_DIR" stdio < "witness_${block}.json" &> "$BLOCK_OUTPUT_LOG"; then
        echo "Performance command failed for block: $block" &>> "$OUTPUT_LOG"
        cat "$BLOCK_OUTPUT_LOG" &>> "$ERROR_LOG"
        return
    fi

    end_time=$(date +%s%N)

    set +o pipefail
    if ! grep "Successfully wrote to disk proof file " "$BLOCK_OUTPUT_LOG" | awk '{print $NF}' | tee "$PROOFS_FILE_LIST"; then
        echo "Proof list not generated for block: $block. Check the log for details." &>> "$OUTPUT_LOG"
        cat "$BLOCK_OUTPUT_LOG" &>> "$ERROR_LOG"
        return
    fi

    duration_sec=$(echo "scale=3; ($end_time - $start_time) / 1000000000" | bc -l)

    # Extract performance timings
    PERF_TIME=$(grep "seconds time elapsed" "$BLOCK_OUTPUT_LOG" | tail -1 | awk '{ print ($1)}')
    PERF_USER_TIME=$(grep "seconds user" "$BLOCK_OUTPUT_LOG" | tail -1 | awk '{ print ($1)}')
    PERF_SYS_TIME=$(grep "seconds sys" "$BLOCK_OUTPUT_LOG" | tail -1 | awk '{ print ($1)}')

    echo "Success for block: $block!"
    echo "Proving duration for block $block: $duration_sec seconds, performance time: $PERF_TIME, performance user time: $PERF_USER_TIME, performance system time: $PERF_SYS_TIME" &>> "$OUTPUT_LOG"
}

# Process each block
for i in $(seq 701 1000); do
    process_block "$i"
done

# Finalize logging
echo "Processing completed at: $(date +"%Y-%m-%d %H:%M:%S")" &>> "$OUTPUT_LOG"
echo "" &>> "$OUTPUT_LOG"

echo "Processing completed at: $(date +"%Y-%m-%d %H:%M:%S")" &>> "$ERROR_LOG"
echo "" &>> "$ERROR_LOG"