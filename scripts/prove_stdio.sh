#!/bin/bash
# ------------------------------------------------------------------------------
set -x

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
REPO_ROOT=$(git rev-parse --show-toplevel)
PROOF_OUTPUT_DIR="${REPO_ROOT}/proofs"

BLOCK_BATCH_SIZE="${BLOCK_BATCH_SIZE:-1}"
echo "Block batch size: $BLOCK_BATCH_SIZE"

BATCH_SIZE=${BATCH_SIZE:-1}
echo "Batch size: $BATCH_SIZE"

OUTPUT_LOG="${REPO_ROOT}/output.log"
PROOFS_FILE_LIST="${PROOF_OUTPUT_DIR}/proof_files.json"
TEST_OUT_PATH="${REPO_ROOT}/$3.test.out"

# Configured Rayon and Tokio with rough defaults
export RAYON_NUM_THREADS=$num_procs
export TOKIO_WORKER_THREADS=$num_procs

#export RUST_MIN_STACK=33554432
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

if [[ ! -s $INPUT_FILE ]]; then
    echo "Input file $INPUT_FILE does not exist or has length 0."
    exit 6
fi

# Circuit sizes only matter in non test_only mode.
if ! [[ $TEST_ONLY == "test_only" ]]; then
    if [[ $INPUT_FILE == *"witness_b19807080"* ]]; then
      # These sizes are configured specifically for block 19807080. Don't use this in other scenarios
        echo "Using specific circuit sizes for witness_b19807080.json"
        export ARITHMETIC_CIRCUIT_SIZE="16..18"
        export BYTE_PACKING_CIRCUIT_SIZE="8..15"
        export CPU_CIRCUIT_SIZE="9..20"
        export KECCAK_CIRCUIT_SIZE="7..18"
        export KECCAK_SPONGE_CIRCUIT_SIZE="8..14"
        export LOGIC_CIRCUIT_SIZE="5..17"
        export MEMORY_CIRCUIT_SIZE="17..22"
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
        export MEMORY_BEFORE_CIRCUIT_SIZE="16..18"
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
    nice -19 cargo run --release --package zero --bin leader -- --test-only --runtime in-memory --load-strategy on-demand --block-batch-size $BLOCK_BATCH_SIZE --proof-output-dir $PROOF_OUTPUT_DIR --batch-size $BATCH_SIZE --save-inputs-on-error stdio < $INPUT_FILE |& tee &> $TEST_OUT_PATH
    if grep -q 'All proof witnesses have been generated successfully.' $TEST_OUT_PATH; then
        echo -e "\n\nSuccess - Note this was just a test, not a proof"
        #rm $TEST_OUT_PATH
        exit 0
    elif grep -q 'Attempted to collapse an extension node' $TEST_OUT_PATH; then
        echo "ERROR: Attempted to collapse an extension node. See $TEST_OUT_PATH for more details."
        rm $TEST_OUT_PATH
        exit 4
    elif grep -q 'SIMW == RPCW ? false' $TEST_OUT_PATH; then
        echo "ERROR: SIMW == RPCW ? false. See $TEST_OUT_PATH for more details."
        exit 5
    elif grep -q 'Proving task finished with error' $TEST_OUT_PATH; then
        # Some error occurred, display the logs and exit.
        echo "ERROR: Proving task finished with error. See $TEST_OUT_PATH for more details."
        exit 1
    else
        echo -e "\n\nUndecided.  Proving process has stopped but verdict is undecided. See $TEST_OUT_PATH for more details."
        exit 2
    fi
fi

cargo build --release --jobs "$num_procs"


start_time=$(date +%s%N)
nice -19 "${REPO_ROOT}/target/release/leader" --runtime in-memory --load-strategy on-demand -n 1 --block-batch-size $BLOCK_BATCH_SIZE \
 --proof-output-dir $PROOF_OUTPUT_DIR stdio < $INPUT_FILE |& tee $OUTPUT_LOG
end_time=$(date +%s%N)

cat $OUTPUT_LOG | grep "Successfully wrote to disk proof file " | awk '{print $NF}' | tee $PROOFS_FILE_LIST
if [ ! -s "$PROOFS_FILE_LIST" ]; then
  # Some error occurred, display the logs and exit.
  cat $OUTPUT_LOG
  echo "Proof list not generated, some error happened. For more details check the log file $OUTPUT_LOG"
  exit 1
fi

cat $PROOFS_FILE_LIST | while read proof_file;
do
  echo "Verifying proof file $proof_file"
  verify_file=$PROOF_OUTPUT_DIR/verify_$(basename $proof_file).out
  nice -19 "${REPO_ROOT}/target/release/verifier" -f $proof_file | tee $verify_file
  if grep -q 'All proofs verified successfully!' $verify_file; then
      echo "Proof verification for file $proof_file successful";
      rm $verify_file # we keep the generated proof for potential reuse
  else
      # Some error occurred with verification, display the logs and exit.
      cat $verify_file
      echo "There was an issue with proof verification. See $verify_file for more details.";
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





