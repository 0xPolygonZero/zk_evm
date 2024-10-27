#!/bin/bash
# ------------------------------------------------------------------------------
set -exo pipefail

# Args:
# 1 --> Output file (Not used in the current script)

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
OUTPUT_LOG="jerigon_zero_output.log"
BLOCK_OUTPUT_LOG="jerigon_zero_block_output.log"
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
echo "$(date +"%Y-%m-%d %H:%M:%S")" &>> "$OUTPUT_LOG"

# Define the blocks to process
blocks=(100 200 300 400 500)

# Function to process each block
process_block() {
    local block=$1

    echo "Processing block: $block" &>> "$OUTPUT_LOG"

    # Fetch block data
    if ! ./target/release/rpc --rpc-url "$ETH_RPC_URL" fetch --start-block "$block" --end-block "$block" > "output_${block}.json"; then
        echo "Failed to fetch block data for block: $block" &>> "$OUTPUT_LOG"
        exit 1
    fi

    local start_time=$(date +%s%N)

    # Run performance stats
    if ! perf stat -e cycles ./target/release/leader --runtime in-memory --load-strategy monolithic --block-batch-size "$BLOCK_BATCH_SIZE" --proof-output-dir "$PROOF_OUTPUT_DIR" stdio < "output_${block}.json" &> "$BLOCK_OUTPUT_LOG"; then
        echo "Performance command failed for block: $block" &>> "$OUTPUT_LOG"
        cat "$BLOCK_OUTPUT_LOG" &>> "$OUTPUT_LOG"
        exit 1
    fi

    local end_time=$(date +%s%N)

    set +o pipefail
    if ! cat "$BLOCK_OUTPUT_LOG" | grep "Successfully wrote to disk proof file " | awk '{print $NF}' | tee "$PROOFS_FILE_LIST"; then
        echo "Proof list not generated for block: $block. Check the log for details." &>> "$OUTPUT_LOG"
        cat "$BLOCK_OUTPUT_LOG" &>> "$OUTPUT_LOG"
        exit 1
    fi

    local duration_sec=$(echo "scale=3; ($end_time - $start_time) / 1000000000" | bc -l)

    # Extract performance timings
    local PERF_TIME=$(grep "seconds time elapsed" "$BLOCK_OUTPUT_LOG" | tail -1 | awk '{ print ($1)}')
    local PERF_USER_TIME=$(grep "seconds user" "$BLOCK_OUTPUT_LOG" | tail -1 | awk '{ print ($1)}')
    local PERF_SYS_TIME=$(grep "seconds sys" "$BLOCK_OUTPUT_LOG" | tail -1 | awk '{ print ($1)}')

    echo "Success for block: $block!"
    echo "Proving duration for block $block: $duration_sec seconds, performance time: $PERF_TIME, performance user time: $PERF_USER_TIME, performance system time: $PERF_SYS_TIME" &>> "$OUTPUT_LOG"
}

# Process each block
for block in "${blocks[@]}"; do
    process_block "$block"
done

# Finalize logging
echo "Processing completed at: $(date +"%Y-%m-%d %H:%M:%S")" &>> "$OUTPUT_LOG"
echo "" &>> "$OUTPUT_LOG"
