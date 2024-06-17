#!/bin/bash
# ------------------------------------------------------------------------------
# Run prover with the parsed input from the standard terminal.
# To generate the json input file, use the `rpc` tool, for example:
# `cargo run --bin rpc -- fetch --rpc-url http://127.0.0.1:8546 --start-block 2 --end-block 5 > witness.json`

# Args:
# 1 --> Input witness json file
# 2 --> Test run only flag `test_only` (optional)

# We're going to set the paralellism in line with the total cpu count
num_procs=$(nproc)

# Configured Rayon and Tokio with rough defaults
export RAYON_NUM_THREADS=$num_procs
export TOKIO_WORKER_THREADS=$num_procs

export RUST_MIN_STACK=33554432
export RUST_BACKTRACE=full
export RUST_LOG=info
# Disable the lld linker for now, as it's causing issues with the linkme package.
# https://github.com/rust-lang/rust/pull/124129
# https://github.com/dtolnay/linkme/pull/88
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
    export KECCAK_CIRCUIT_SIZE="14..15"
    export KECCAK_SPONGE_CIRCUIT_SIZE="9..10"
    export LOGIC_CIRCUIT_SIZE="12..13"
    export MEMORY_CIRCUIT_SIZE="17..18"
else
    if [[ $INPUT_FILE == *"witness_b19240705"* ]]; then
      # These sizes are configured specifically for block 19240705. Don't use this in other scenarios
        echo "Using specific circuit sizes for witness_b19240705.json"
        export ARITHMETIC_CIRCUIT_SIZE="16..19"
        export BYTE_PACKING_CIRCUIT_SIZE="16..19"
        export CPU_CIRCUIT_SIZE="18..21"
        export KECCAK_CIRCUIT_SIZE="15..18"
        export KECCAK_SPONGE_CIRCUIT_SIZE="10..13"
        export LOGIC_CIRCUIT_SIZE="13..17"
        export MEMORY_CIRCUIT_SIZE="20..23"
    else
        export ARITHMETIC_CIRCUIT_SIZE="16..23"
        export BYTE_PACKING_CIRCUIT_SIZE="9..21"
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
    cargo run --release --features test_only --bin leader -- --runtime in-memory --load-strategy on-demand stdio < $INPUT_FILE | tee test.out
    if grep -q 'All proof witnesses have been generated successfully.' test.out; then
        echo -e "\n\nSuccess - Note this was just a test, not a proof"
        exit
    else
         echo "Failed to create proof witnesses. See test.out for more details."
        exit 1
    fi
fi

cargo build --release --jobs "$num_procs"

start_time=$(date +%s%N)
../target/release/leader --runtime in-memory --load-strategy on-demand stdio < $INPUT_FILE | tee leader.out
end_time=$(date +%s%N)

tail -n 1 leader.out > proofs.json

../target/release/verifier -f proofs.json | tee verify.out

if grep -q 'All proofs verified successfully!' verify.out; then
    duration_ns=$((end_time - start_time))
    duration_sec=$(echo "$duration_ns / 1000000000" | bc -l)
    echo "Success!"
    echo "Duration:" $duration_sec " seconds"
    echo "Note, this duration is inclusive of circuit handling and overall process initialization";
else
    echo "there was an issue with proof verification";
    exit 1
fi


