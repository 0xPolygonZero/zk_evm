#!/bin/bash

# Args:
# 1 --> Block idx
# 2 --> Rpc endpoint:port (eg. http://35.246.1.96:8545)

export RUST_BACKTRACE=1
export RUST_MIN_STACK=8388608
export RUST_LOG=mpt_trie=info,trace_decoder=info,plonky2=info,evm_arithmetization=trace,leader=info
export RUSTFLAGS='-Ctarget-cpu=native'

# Speciying smallest ranges, as we won't need them anyway.
export ARITHMETIC_CIRCUIT_SIZE="16..17"
export BYTE_PACKING_CIRCUIT_SIZE="9..10"
export CPU_CIRCUIT_SIZE="12..13"
export KECCAK_CIRCUIT_SIZE="14..15"
export KECCAK_SPONGE_CIRCUIT_SIZE="9..10"
export LOGIC_CIRCUIT_SIZE="12..13"
export MEMORY_CIRCUIT_SIZE="17..18"

OUTPUT_DIR="debug"
OUT_DUMMY_PROOF_PATH="${OUTPUT_DIR}/b${1}.zkproof"
OUT_LOG_PATH="${OUTPUT_DIR}/b${1}.log"

echo "Testing block ${1}..."
mkdir -p $OUTPUT_DIR

cargo r --release --features test_only --bin leader -- -n 1 --runtime in-memory jerigon --rpc-url "$2" --block-number "$1" --checkpoint-block-number "$(($1-1))" --proof-output-path $OUT_DUMMY_PROOF_PATH > $OUT_LOG_PATH 2>&1
retVal=$?
if [ $retVal -ne 0 ]; then
    # Some error occured.
    echo "Witness generation for block ${1} errored. See ${OUT_LOG_PATH} for more details."
else
    echo "Witness generation for block ${1} succeeded."
    # Remove the log / dummy proof on success.
    rm $OUT_DUMMY_PROOF_PATH
    rm $OUT_LOG_PATH
fi

