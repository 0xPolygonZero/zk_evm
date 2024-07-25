#!/bin/bash
# ------------------------------------------------------------------------------
# Run prover with the parsed input from the standard terminal.
# To generate the json input file, use the `rpc` tool, for example:
# `cargo run --bin rpc -- fetch --rpc-url http://127.0.0.1:8546 --start-block 2 --end-block 5 > witness.json`

# Args:
# 1 --> Input witness json file
# 2 --> Test run only flag `test_only` (optional)

# We're going to set the parallelism in line with the total cpu count
num_procs=$(nproc)

# Force the working directory to always be the `tools/` directory. 
TOOLS_DIR=$(dirname $(realpath "$0"))

LEADER_OUT_PATH="${TOOLS_DIR}/leader.out"
PROOFS_JSON_PATH="${TOOLS_DIR}/proofs.json"
VERIFY_OUT_PATH="${TOOLS_DIR}/verify.out"
TEST_OUT_PATH="${TOOLS_DIR}/test.out"

# Set the environment variable to let the binary know that we're running in the project workspace.
export CARGO_WORKSPACE_DIR="${TOOLS_DIR}/../"

# Configured Rayon and Tokio with rough defaults
export RAYON_NUM_THREADS=$num_procs
export TOKIO_WORKER_THREADS=$num_procs

export RUST_MIN_STACK=33554432
export RUST_BACKTRACE=full
export RUST_LOG=info
# Script users are running locally, and might benefit from extra perf.
# See also .cargo/config.toml.
export RUSTFLAGS='-C target-cpu=native -Zlinker-features=-lld'

INPUT_FILE=$1
TEST_ONLY=$2

if [[ $INPUT_FILE == "" ]]; then
    echo "Please provide witness json input file, e.g. artifacts/witness_b19240705.json"
    exit 1
fi

if [[ $TEST_ONLY == "test_only" ]]; then
    # Circuit sizes don't matter in test_only mode, so we keep them minimal.
    export ARITHMETIC_CIRCUIT_SIZE="16..17"
    export BYTE_PACKING_CIRCUIT_SIZE="9..10"
    export CPU_CIRCUIT_SIZE="12..13"
    export KECCAK_CIRCUIT_SIZE="4..5"
    export KECCAK_SPONGE_CIRCUIT_SIZE="9..10"
    export LOGIC_CIRCUIT_SIZE="12..13"
    export MEMORY_CIRCUIT_SIZE="17..18"
    export MEMORY_BEFORE_CIRCUIT_SIZE="7..8"
    export MEMORY_AFTER_CIRCUIT_SIZE="7..8"
else
    if [[ $INPUT_FILE == *"witness_b19240705"* ]]; then
        # These sizes are configured specifically for block 19240705. Don't use this in other scenarios.
        echo "Using specific circuit sizes for witness_b19240705.json"
        export ARITHMETIC_CIRCUIT_SIZE="16..19"
        export BYTE_PACKING_CIRCUIT_SIZE="9..15"
        export CPU_CIRCUIT_SIZE="14..21"
        export KECCAK_CIRCUIT_SIZE="10..18"
        export KECCAK_SPONGE_CIRCUIT_SIZE="7..13"
        export LOGIC_CIRCUIT_SIZE="8..17"
        export MEMORY_CIRCUIT_SIZE="18..23"
        export MEMORY_BEFORE_CIRCUIT_SIZE="15..19"
        export MEMORY_AFTER_CIRCUIT_SIZE="7..19"
    elif [[ $INPUT_FILE == *"witness_b2_b7"* ]]; then
        # These sizes are configured specifically for custom small blocks. Don't use this in other scenarios.
        echo "Using specific circuit sizes for witness_b2_b7.json"
        export ARITHMETIC_CIRCUIT_SIZE="16..17"
        export BYTE_PACKING_CIRCUIT_SIZE="9..11"
        export CPU_CIRCUIT_SIZE="16..17"
        export KECCAK_CIRCUIT_SIZE="10..15"
        export KECCAK_SPONGE_CIRCUIT_SIZE="8..11"
        export LOGIC_CIRCUIT_SIZE="11..13"
        export MEMORY_CIRCUIT_SIZE="18..19"
        export MEMORY_BEFORE_CIRCUIT_SIZE="16..17"
        export MEMORY_AFTER_CIRCUIT_SIZE="7..8"
    else
        export ARITHMETIC_CIRCUIT_SIZE="16..23"
        export BYTE_PACKING_CIRCUIT_SIZE="8..23"
        export CPU_CIRCUIT_SIZE="8..25"
        export KECCAK_CIRCUIT_SIZE="4..20"
        export KECCAK_SPONGE_CIRCUIT_SIZE="8..15"
        export LOGIC_CIRCUIT_SIZE="8..18"
        export MEMORY_CIRCUIT_SIZE="17..28"
        export MEMORY_BEFORE_CIRCUIT_SIZE="7..27"
        export MEMORY_AFTER_CIRCUIT_SIZE="7..27"
    fi
fi


# Prover config. Override the defaults if needed by setting the env variables.
PROVER_BATCH_SIZE="${PROVER_BATCH_SIZE:-1}"
PROVER_SEGMENT_CHUNK_SIZE="${PROVER_SEGMENT_CHUNK_SIZE:-64}"
PROVER_MAX_CPU_LEN_LOG="${PROVER_MAX_CPU_LEN_LOG:-20}"
if [[ $PROVER_SAVE_INPUTS_ON_ERROR == "true" ]]; then
    PROVER_SAVE_INPUTS_ON_ERROR="--save-inputs-on-error"
else
    PROVER_SAVE_INPUTS_ON_ERROR=""
fi

if [ -n "$NUM_WORKERS" ]; then
    SET_NUM_WORKERS="--num-workers $NUM_WORKERS"
else
    SET_NUM_WORKERS=""
fi



# If we run ./prove_stdio.sh <witness file name> test_only, we'll generate a dummy
# proof. This is useful for quickly testing decoding and all of the
# other non-proving code.
if [[ $TEST_ONLY == "test_only" ]]; then
    cargo run --release --features test_only --bin leader -- --runtime in-memory --load-strategy on-demand stdio < $INPUT_FILE | tee $TEST_OUT_PATH
    if grep -q 'All proof witnesses have been generated successfully.' $TEST_OUT_PATH; then
        echo -e "\n\nSuccess - Note this was just a test, not a proof"
        exit
    else
         echo "Failed to create proof witnesses. See \"zk_evm/tools/test.out\" for more details."
        exit 1
    fi
fi

cargo build --release --jobs "$num_procs"

start_time=$(date +%s%N)
"${TOOLS_DIR}/../../target/release/leader" --runtime in-memory --load-strategy on-demand --batch-size $PROVER_BATCH_SIZE \
   --max-cpu-len-log $PROVER_MAX_CPU_LEN_LOG --segment-chunk-size $PROVER_SEGMENT_CHUNK_SIZE \
   $SET_NUM_WORKERS $PROVER_SAVE_INPUTS_ON_ERROR stdio < $INPUT_FILE | tee $LEADER_OUT_PATH
end_time=$(date +%s%N)

tail -n 1 $LEADER_OUT_PATH > $PROOFS_JSON_PATH

"${TOOLS_DIR}/../../target/release/verifier" -f $PROOFS_JSON_PATH | tee $VERIFY_OUT_PATH

if grep -q 'All proofs verified successfully!' $VERIFY_OUT_PATH; then
    duration_ns=$((end_time - start_time))
    duration_sec=$(echo "$duration_ns / 1000000000" | bc -l)
    echo "Success!"
    echo "Duration:" $duration_sec " seconds"
    echo "Note, this duration is inclusive of circuit handling and overall process initialization";
else
    echo "there was an issue with proof verification";
    exit 1
fi


