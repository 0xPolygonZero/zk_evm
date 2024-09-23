#!/usr/bin/env bash

set -uxo pipefail

export RPC=
if [ -z $RPC ]; then
  # You must set an RPC endpoint
  exit 1
fi
mkdir -p witnesses

# Must match the values in prove_stdio.sh or build is dirty.
export RAYON_NUM_THREADS=1
export TOKIO_WORKER_THREADS=1
export RUST_BACKTRACE=full
#export RUST_LOG=info
#export RUSTFLAGS='-C target-cpu=native -Zlinker-features=-lld'
#export RUST_MIN_STACK=33554432



CANCUNBLOCKS="
20548415
20240058
19665756
20634472
19807080
20634403
"

PRECANCUN="
19096840
19240700
"

CANCUN=19426587
TIP=`cast block-number --rpc-url $RPC`
STATICTIP=20721266
NUMRANDOMBLOCKS=100
RANDOMBLOCKS=`shuf --input-range=$CANCUN-$TIP -n $NUMRANDOMBLOCKS | sort`

GITHASH=`git rev-parse --short HEAD`
echo "Testing against mainnet, current revision: $GITHASH."

BLOCKS="$CANCUNBLOCKS $RANDOMBLOCKS"
#BLOCKS="$CANCUNBLOCKS"
echo "Testing blocks: $BLOCKS"

echo "Downloading witnesses.."
echo "------------------------"| tee -a witnesses/native_results.txt

for BLOCK in $BLOCKS; do
  WITNESS="witnesses/$BLOCK.native.$GITHASH.witness.json"
  until [ -f $WITNESS -a -s $WITNESS ]; do
    echo "Fetching block $BLOCK"
    cargo run --release --verbose --bin rpc -- --backoff 3000 --max-retries 100 --rpc-url $RPC --rpc-type native fetch --start-block $BLOCK --end-block $BLOCK 1> $WITNESS
    EXITCODE=$?

    if [ $EXITCODE -eq 0 -a -f $WITNESS -a -s $WITNESS ]
    then
      printf "%10i %s witness saved: %s.\n" $BLOCK $GITHASH success | tee -a witnesses/native_results.txt
      break
    else
      printf "%10i %s witness saved: %s.\n" $BLOCK $GITHASH failure | tee -a witnesses/native_results.txt
    fi
  done

  echo "Witness for block $BLOCK ($WITNESS) prepared."

  echo "Testing $WITNESS"
  ./prove_stdio.sh $WITNESS test_only
  EXITCODE=$?
  if [ $EXITCODE -eq 0 ]
  then
    RESULT="success"
  else
    RESULT="failure"
  fi
  printf "%10i %s witness tested: %s.\n" $BLOCK $GITHASH $RESULT | tee -a witnesses/native_results.txt
done

#echo "Finished downloading witnesses."
#echo "Testing prepared witnesses.."
#
#for WITNESS in witnesses/*.native.$GITHASH.witness.json; do
#  echo "Testing $WITNESS"
#  ./prove_stdio.sh $WITNESS test_only
#  EXITCODE=$?
#  if [ $EXITCODE -eq 0 ]
#  then
#    RESULT="success"
#  else
#    RESULT="failure"
#  fi
#  printf "%10i %s witness tested: %s.\n" $BLOCK $GITHASH $RESULT | tee -a witnesses/native_results.txt
#done
#
#echo "Finished testing witnesses."
