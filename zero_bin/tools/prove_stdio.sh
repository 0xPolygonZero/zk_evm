#!/bin/bash
# ------------------------------------------------------------------------------
set -exo pipefail

# Run prover with the parsed input from the standard terminal.
# To generate the json input file, use the `rpc` tool, for example:
# `cargo run --bin rpc -- fetch --rpc-url http://127.0.0.1:8546 --start-block 2 --end-block 5 > witness.json`

# Args:
# 1 --> Input witness json file
# 2 --> Test run only flag `test_only` (optional)

# We're going to set the parallelism in line with the total cpu count
if [[ "$OSTYPE" == "darwin"* ]]; then
    num_procs=$(sysctl -n hw.physicalcpu)
else
    num_procs=$(nproc)
fi

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
export RUSTFLAGS='-C target-cpu=native -Z linker-features=-lld'

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
    export KECCAK_CIRCUIT_SIZE="14..15"
    export KECCAK_SPONGE_CIRCUIT_SIZE="9..10"
    export LOGIC_CIRCUIT_SIZE="12..13"
    export MEMORY_CIRCUIT_SIZE="17..18"
else
    if [[ $INPUT_FILE == *"witness_b19807080"* ]]; then
      # These sizes are configured specifically for block 19807080. Don't use this in other scenarios
        echo "Using specific circuit sizes for witness_b19807080.json"
        export ARITHMETIC_CIRCUIT_SIZE="16..18"
        export BYTE_PACKING_CIRCUIT_SIZE="11..15"
        export CPU_CIRCUIT_SIZE="17..21"
        export KECCAK_CIRCUIT_SIZE="14..17"
        export KECCAK_SPONGE_CIRCUIT_SIZE="10..13"
        export LOGIC_CIRCUIT_SIZE="13..16"
        export MEMORY_CIRCUIT_SIZE="19..23"
    elif [[ $INPUT_FILE == *"witness_b3_b6"* ]]; then
      # These sizes are configured specifically for custom blocks 3 to 6. Don't use this in other scenarios
        echo "Using specific circuit sizes for witness_b3_b6.json"
        export ARITHMETIC_CIRCUIT_SIZE="16..17"
        export BYTE_PACKING_CIRCUIT_SIZE="8..14"
        export CPU_CIRCUIT_SIZE="14..19"
        export KECCAK_CIRCUIT_SIZE="14..15"
        export KECCAK_SPONGE_CIRCUIT_SIZE="10..11"
        export LOGIC_CIRCUIT_SIZE="12..13"
        export MEMORY_CIRCUIT_SIZE="17..21"
    else
        export ARITHMETIC_CIRCUIT_SIZE="16..23"
        export BYTE_PACKING_CIRCUIT_SIZE="8..21"
        export CPU_CIRCUIT_SIZE="12..25"
        export KECCAK_CIRCUIT_SIZE="14..20"
        export KECCAK_SPONGE_CIRCUIT_SIZE="9..15"
        export LOGIC_CIRCUIT_SIZE="12..18"
        export MEMORY_CIRCUIT_SIZE="17..28"
    fi
fi


# If we run ./prove_stdio.sh <witness file name> test_only, we'll generate a dummy
# proof. This is useful for quickly testing decoding and all of the
# other non-proving code.
if [[ $TEST_ONLY == "test_only" ]]; then
    echo $RUSTFLAGS
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
"${TOOLS_DIR}/../../target/release/leader" --runtime in-memory --load-strategy on-demand stdio < $INPUT_FILE | tee $LEADER_OUT_PATH
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


