#!/bin/bash

# Args:
# 1 --> Start block idx
# 2 --> End block index (inclusive)
# 3 --> Rpc endpoint:port (eg. http://35.246.1.96:8545)
# 4 --> Rpc type (eg. jerigon / native)
# 5 --> Ignore previous proofs (boolean)
# 6 --> Backoff in milliseconds (optional [default: 0])
# 7 --> Number of retries (optional [default: 0])
# 8 --> Test run only flag `test_only` (optional)

export RUST_MIN_STACK=33554432
export RUST_BACKTRACE=1
export RUST_LOG=info
# Script users are running locally, and might benefit from extra perf.
# See also .cargo/config.toml.
export RUSTFLAGS='-C target-cpu=native -Zlinker-features=-lld'

BLOCK_BATCH_SIZE="${BLOCK_BATCH_SIZE:-8}"
echo "Block batch size: $BLOCK_BATCH_SIZE"

REPO_ROOT=$(git rev-parse --show-toplevel)

PROOF_OUTPUT_DIR="${REPO_ROOT}/proofs"
OUT_LOG_PATH="${PROOF_OUTPUT_DIR}/b$1_$2.log"
ALWAYS_WRITE_LOGS=0 # Change this to `1` if you always want logs to be written.
TOT_BLOCKS=$(($2-$1+1))

START_BLOCK=$1
END_BLOCK=$2
NODE_RPC_URL=$3
NODE_RPC_TYPE=$4
IGNORE_PREVIOUS_PROOFS=$5
BACKOFF=${6:-0}
RETRIES=${7:-0}

# Sometimes we need to override file logging, e.g. in the CI run
OUTPUT_TO_TERMINAL="${OUTPUT_TO_TERMINAL:-false}"
# Only generate proof by default
RUN_VERIFICATION="${RUN_VERIFICATION:-false}"

# Recommended soft file handle limit. Will warn if it is set lower.
RECOMMENDED_FILE_HANDLE_LIMIT=8192

mkdir -p $PROOF_OUTPUT_DIR

if $IGNORE_PREVIOUS_PROOFS ; then
    # Set checkpoint height to previous block number for the first block in range
    prev_proof_num=$(($1-1))
    PREV_PROOF_EXTRA_ARG="--checkpoint-block-number ${prev_proof_num}"
else
    if [[ $1 -gt 1 ]]; then
        prev_proof_num=$(($1-1))
        PREV_PROOF_EXTRA_ARG="-f ${PROOF_OUTPUT_DIR}/b${prev_proof_num}.zkproof"
    fi
fi

# Convert hex to decimal parameters
if [[ $START_BLOCK == 0x* ]]; then
    START_BLOCK=$((16#${START_BLOCK#"0x"}))
fi
if [[ $END_BLOCK == 0x* ]]; then
    END_BLOCK=$((16#${END_BLOCK#"0x"}))
fi

# Define block interval
if [ $END_BLOCK == '-' ]; then
  # Follow from the start block to the end of the chain
  BLOCK_INTERVAL=$START_BLOCK..
elif [ $START_BLOCK == $END_BLOCK ]; then
  # Single block
  BLOCK_INTERVAL=$START_BLOCK
else
  # Block range
  BLOCK_INTERVAL=$START_BLOCK..=$END_BLOCK
fi

# Print out a warning if the we're using `native` and our file descriptor limit is too low. Don't bother if we can't find `ulimit`.
if [ $(command -v ulimit) ] && [ $NODE_RPC_TYPE == "native" ]
then
    file_desc_limit=$(ulimit -n)

    if [[ $file_desc_limit -lt $RECOMMENDED_FILE_HANDLE_LIMIT ]]
    then
        echo "WARNING: Maximum file descriptor limit may be too low to run native mode (current: $file_desc_limit, Recommended: ${RECOMMENDED_FILE_HANDLE_LIMIT}).
        Consider increasing it with:

        ulimit -n ${RECOMMENDED_FILE_HANDLE_LIMIT}"
    fi
fi

# If we set test_only flag, we'll generate a dummy
# proof. This is useful for quickly testing decoding and all of the
# other non-proving code.
if [[ $8 == "test_only" ]]; then
    # test only run
    echo "Proving blocks ${BLOCK_INTERVAL} in a test_only mode now... (Total: ${TOT_BLOCKS})"
    command='cargo r --release --package zero --bin leader -- --test-only --runtime in-memory --load-strategy on-demand --proof-output-dir $PROOF_OUTPUT_DIR --block-batch-size $BLOCK_BATCH_SIZE rpc --rpc-type "$NODE_RPC_TYPE" --rpc-url "$NODE_RPC_URL" --block-interval $BLOCK_INTERVAL  $PREV_PROOF_EXTRA_ARG --backoff "$BACKOFF" --max-retries "$RETRIES" '
    if [ "$OUTPUT_TO_TERMINAL" = true ]; then
        eval $command
        retVal=$?
        echo -e "Proof witness generation finished with result: $retVal"
        exit $retVal
    else
        eval $command > $OUT_LOG_PATH 2>&1
        if grep -q 'All proof witnesses have been generated successfully.' $OUT_LOG_PATH; then
            echo -e "Success - Note this was just a test, not a proof"
            # Remove the log on success if we don't want to keep it.
            if [ $ALWAYS_WRITE_LOGS -ne 1 ]; then
                rm $OUT_LOG_PATH
            fi
            exit
        else
            echo "Failed to create proof witnesses. See ${OUT_LOG_PATH} for more details."
            exit 1
        fi
    fi
else
    # normal run
    echo "Proving blocks ${BLOCK_INTERVAL} now... (Total: ${TOT_BLOCKS})"
    command='cargo r --release --package zero --bin leader -- --runtime in-memory --load-strategy on-demand --proof-output-dir $PROOF_OUTPUT_DIR --block-batch-size $BLOCK_BATCH_SIZE rpc --rpc-type "$NODE_RPC_TYPE" --rpc-url "$3" --block-interval $BLOCK_INTERVAL $PREV_PROOF_EXTRA_ARG --backoff "$BACKOFF" --max-retries "$RETRIES" '
    if [ "$OUTPUT_TO_TERMINAL" = true ]; then
        eval $command
        echo -e "Proof generation finished with result: $?"
    else
        eval $command > $OUT_LOG_PATH 2>&1
        retVal=$?
        if [ $retVal -ne 0 ]; then
            # Some error occurred, display the logs and exit.
            cat $OUT_LOG_PATH
            echo "Block ${i} errored. See ${OUT_LOG_PATH} for more details."
            exit $retVal
        else
            # Remove the log on success if we don't want to keep it.
            if [ $ALWAYS_WRITE_LOGS -ne 1 ]; then
                rm $OUT_LOG_PATH
            fi
        fi
        echo "Successfully generated ${TOT_BLOCKS} proofs!"
    fi
fi


# If we're running the verification, we'll do it here.
if [ "$RUN_VERIFICATION" = true ]; then
  echo "Running the verification for the last proof..."

  proof_file_name=$PROOF_OUTPUT_DIR/b$END_BLOCK.zkproof
  echo "Verifying the proof of the latest block in the interval:" $proof_file_name
  cargo r --release --package zero --bin verifier -- -f $proof_file_name > $PROOF_OUTPUT_DIR/verify.out 2>&1

  if grep -q 'All proofs verified successfully!' $PROOF_OUTPUT_DIR/verify.out; then
      echo "$proof_file_name verified successfully!";
      rm  $PROOF_OUTPUT_DIR/verify.out
  else
      # Some error occurred with verification, display the logs and exit.
      cat $PROOF_OUTPUT_DIR/verify.out
      echo "There was an issue with proof verification. See $PROOF_OUTPUT_DIR/verify.out for more details.";
      exit 1
  fi
else
  echo "Skipping verification..."
fi
