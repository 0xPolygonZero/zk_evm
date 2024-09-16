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
PROOF_OUTPUT_DIR="${TOOLS_DIR}/proofs"

BLOCK_BATCH_SIZE="${BLOCK_BATCH_SIZE:-8}"
echo "Block batch size: $BLOCK_BATCH_SIZE"

OUTPUT_LOG="${TOOLS_DIR}/output.log"
PROOFS_FILE_LIST="${PROOF_OUTPUT_DIR}/proof_files.json"
TEST_OUT_PATH="${TOOLS_DIR}/test.out"

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

# Circuit sizes only matter in non test_only mode.
if ! [[ $TEST_ONLY == "test_only" ]]; then
    if [[ $INPUT_FILE == *"witness_b19807080"* ]]; then
      # These sizes are configured specifically for block 19807080. Don't use this in other scenarios
        echo "Using specific circuit sizes for witness_b19807080.json"
        export ARITHMETIC_CIRCUIT_SIZE="16..18"
        export BYTE_PACKING_CIRCUIT_SIZE="9..15"
        export CPU_CIRCUIT_SIZE="15..20"
        export KECCAK_CIRCUIT_SIZE="12..18"
        export KECCAK_SPONGE_CIRCUIT_SIZE="8..14"
        export LOGIC_CIRCUIT_SIZE="8..17"
        export MEMORY_CIRCUIT_SIZE="18..22"
        export MEMORY_BEFORE_CIRCUIT_SIZE="16..20"
        export MEMORY_AFTER_CIRCUIT_SIZE="7..20"
        # TODO(Robin): update Poseidon ranges here and below once Kernel ASM supports Poseidon ops
        export POSEIDON_CIRCUIT_SIZE="4..8"
    elif [[ $INPUT_FILE == *"witness_b3_b6"* ]]; then
      # These sizes are configured specifically for custom blocks 3 to 6. Don't use this in other scenarios
        echo "Using specific circuit sizes for witness_b3_b6.json"
        export ARITHMETIC_CIRCUIT_SIZE="16..18"
        export BYTE_PACKING_CIRCUIT_SIZE="8..15"
        export CPU_CIRCUIT_SIZE="10..20"
        export KECCAK_CIRCUIT_SIZE="4..13"
        export KECCAK_SPONGE_CIRCUIT_SIZE="8..9"
        export LOGIC_CIRCUIT_SIZE="4..14"
        export MEMORY_CIRCUIT_SIZE="17..22"
        export MEMORY_BEFORE_CIRCUIT_SIZE="17..18"
        export MEMORY_AFTER_CIRCUIT_SIZE="7..8"
        export POSEIDON_CIRCUIT_SIZE="4..8"
    else
        export ARITHMETIC_CIRCUIT_SIZE="16..21"
        export BYTE_PACKING_CIRCUIT_SIZE="8..21"
        export CPU_CIRCUIT_SIZE="8..21"
        export KECCAK_CIRCUIT_SIZE="4..20"
        export KECCAK_SPONGE_CIRCUIT_SIZE="8..17"
        export LOGIC_CIRCUIT_SIZE="4..21"
        export MEMORY_CIRCUIT_SIZE="17..24"
        export MEMORY_BEFORE_CIRCUIT_SIZE="16..23"
        export MEMORY_AFTER_CIRCUIT_SIZE="7..23"
        export POSEIDON_CIRCUIT_SIZE="4..8"
    fi
fi


# If we run ./prove_stdio.sh <witness file name> test_only, we'll generate a dummy
# proof. This is useful for quickly testing decoding and all of the
# other non-proving code.
if [[ $TEST_ONLY == "test_only" ]]; then
    cargo run --quiet --release --bin leader -- --test-only --runtime in-memory --load-strategy on-demand --block-batch-size $BLOCK_BATCH_SIZE --proof-output-dir $PROOF_OUTPUT_DIR stdio < $INPUT_FILE &> $TEST_OUT_PATH
    if grep -q 'All proof witnesses have been generated successfully.' $TEST_OUT_PATH; then
        echo -e "\n\nSuccess - Note this was just a test, not a proof"
        rm $TEST_OUT_PATH
        exit
    else
         echo "Failed to create proof witnesses. See \"zk_evm/tools/test.out\" for more details."
        exit 1
    fi
fi

cargo build --release --jobs "$num_procs"


start_time=$(date +%s%N)
"${TOOLS_DIR}/../../target/release/leader" --runtime in-memory --load-strategy on-demand --block-batch-size $BLOCK_BATCH_SIZE \
 --proof-output-dir $PROOF_OUTPUT_DIR stdio < $INPUT_FILE &> $OUTPUT_LOG
end_time=$(date +%s%N)

set +o pipefail
cat $OUTPUT_LOG | grep "Successfully wrote to disk proof file " | awk '{print $NF}' | tee $PROOFS_FILE_LIST
if [ ! -s "$PROOFS_FILE_LIST" ]; then
  echo "Proof list not generated, some error happened. For more details check the log file $OUTPUT_LOG"
  exit 1
fi

cat $PROOFS_FILE_LIST | while read proof_file;
do
  echo "Verifying proof file $proof_file"
  verify_file=$PROOF_OUTPUT_DIR/verify_$(basename $proof_file).out
  "${TOOLS_DIR}/../../target/release/verifier" -f $proof_file | tee $verify_file
  if grep -q 'All proofs verified successfully!' $verify_file; then
      echo "Proof verification for file $proof_file successful";
      rm $verify_file # we keep the generated proof for potential reuse
  else
      echo "there was an issue with proof verification";
      exit 1
  fi
done

duration_ns=$((end_time - start_time))
duration_sec=$(echo "$duration_ns / 1000000000" | bc -l)

echo "Success!"
echo "Proving duration:" $duration_sec " seconds"
echo "Note, this duration is inclusive of circuit handling and overall process initialization";

# Clean up in case of success
rm $OUTPUT_LOG





