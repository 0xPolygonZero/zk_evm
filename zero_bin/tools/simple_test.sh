#!/bin/bash
# ------------------------------------------------------------------------------
# This is meant to be a somewhat self contained script for quickly
# proving an Ethereum mainnet block with the type 1 prover. The goal
# is to use this for benchmarking and CI. This is the block in
# question: https://etherscan.io/block/19240705

# We're going to set the paralellism in line with the total cpu count
num_procs=$(nproc)

2>&1 echo "Pulling sample witness"
witness_cid_hash="QmbwnLGuZ2qxZDqETAFb5DnyjZry8Sv3UFwYnsgKmsE3of"
curl -s -L "https://cf-ipfs.com/ipfs/$witness_cid_hash" > witness.json.bz2
bunzip2 -f witness.json.bz2

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

if [[ $1 == "test_only" ]]; then
    # Circuit sizes don't matter in test_only mode, so we keep them minimal.
    export ARITHMETIC_CIRCUIT_SIZE="16..17"
    export BYTE_PACKING_CIRCUIT_SIZE="9..10"
    export CPU_CIRCUIT_SIZE="12..13"
    export KECCAK_CIRCUIT_SIZE="14..15"
    export KECCAK_SPONGE_CIRCUIT_SIZE="9..10"
    export LOGIC_CIRCUIT_SIZE="12..13"
    export MEMORY_CIRCUIT_SIZE="17..18"
else
    # These sizes are configured specifically for this witness. Don't use this in other scenarios
    export ARITHMETIC_CIRCUIT_SIZE="16..19"
    export BYTE_PACKING_CIRCUIT_SIZE="16..19"
    export CPU_CIRCUIT_SIZE="18..21"
    export KECCAK_CIRCUIT_SIZE="15..18"
    export KECCAK_SPONGE_CIRCUIT_SIZE="10..13"
    export LOGIC_CIRCUIT_SIZE="13..17"
    export MEMORY_CIRCUIT_SIZE="20..23"
fi


# If we run ./simple_test test_only, we'll generate a dummy
# proof. This is useful for quickly testing decoding and all of the
# other non-proving code.
if [[ $1 == "test_only" ]]; then
    cargo run --release --features test_only --bin leader -- --runtime in-memory --load-strategy on-demand stdio < witness.json | tee test.out
    if grep 'Successfully generated witness for block' test.out; then
        echo "Success - Note this was just a test, not a proof"
        exit
    else
        echo "Failed to create a witness"
        exit 1
    fi
fi

cargo build --release --jobs "$num_procs"

start_time=$(date +%s%N)
../target/release/leader --runtime in-memory stdio < witness.json | tee leader.out
end_time=$(date +%s%N)

tail -n 1 leader.out > proof.json

../target/release/verifier -f proof.json | tee verify.out

if grep -q 'Proof verified successfully!' verify.out; then
    duration_ns=$((end_time - start_time))
    duration_sec=$(echo "$duration_ns / 1000000000" | bc -l)
    echo "Success!"
    printf "Duration: %.3f seconds\n" $duration_sec
    echo "Note, this duration is inclusive of circuit handling and overall process initialization";
else
    echo "there was an issue with proof verification";
    exit 1
fi


