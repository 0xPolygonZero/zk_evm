#!/bin/bash

# Args:
# 1 --> Start block idx
# 2 --> End block index (inclusive)
# 3 --> Rpc endpoint:port (eg. http://35.246.1.96:8545)
# 4 --> Ignore previous proofs (boolean)

export RUST_BACKTRACE=1
export RUST_LOG=mpt_trie=info,trace_decoder=info,plonky2=info,evm_arithmetization=trace,leader=info
export RUSTFLAGS='-Ctarget-cpu=native'

export ARITHMETIC_CIRCUIT_SIZE="16..23"
export BYTE_PACKING_CIRCUIT_SIZE="9..21"
export CPU_CIRCUIT_SIZE="12..25"
export KECCAK_CIRCUIT_SIZE="14..20"
export KECCAK_SPONGE_CIRCUIT_SIZE="9..15"
export LOGIC_CIRCUIT_SIZE="12..18"
export MEMORY_CIRCUIT_SIZE="17..28"

PROOF_OUTPUT_DIR="proofs"
ALWAYS_WRITE_LOGS=0 # Change this to `1` if you always want logs to be written.

TOT_BLOCKS=$(($2-$1+1))
IGNORE_PREVIOUS_PROOFS=$4

echo "Proving blocks ${1}..=${2}... (Total: ${TOT_BLOCKS})"
mkdir -p $PROOF_OUTPUT_DIR

for ((i=$1; i<=$2; i++))
do
    echo "Proving block ${i}..."

    OUT_PROOF_PATH="${PROOF_OUTPUT_DIR}/b${i}.zkproof"
    OUT_LOG_PATH="${PROOF_OUTPUT_DIR}/b${i}.log"

    if [ $IGNORE_PREVIOUS_PROOFS ]; then
        # Set checkpoint height to previous block number
        prev_proof_num=$((i-1))
        PREV_PROOF_EXTRA_ARG="--checkpoint-block-number ${prev_proof_num}"
    else
        if [ $i -gt 1 ]; then
            prev_proof_num=$((i-1))
            PREV_PROOF_EXTRA_ARG="-f ${PROOF_OUTPUT_DIR}/b${prev_proof_num}.zkproof"
        fi
    fi

    cargo r --release --bin leader -- --runtime in-memory jerigon --rpc-url "$3" --block-number $i --proof-output-path $OUT_PROOF_PATH $PREV_PROOF_EXTRA_ARG > $OUT_LOG_PATH 2>&1
    
    retVal=$?
    if [ $retVal -ne 0 ]; then
        # Some error occured.
        echo "Block ${i} errored. See ${OUT_LOG_PATH} for more details."
        exit $retVal
    else
        # Remove the log on success if we don't want to keep it.
        if [ $ALWAYS_WRITE_LOGS -ne 1 ]; then
            rm $OUT_LOG_PATH
        fi
    fi
done

echo "Successfully generated ${TOT_BLOCKS} proofs!"