#!/usr/bin/env bash

set -uo pipefail

export RPC=
if [ -z $RPC ]; then
  # You must set an RPC endpoint
  exit 1
fi
mkdir -p witnesses

# Must match the values in prove_stdio.sh or build is dirty.
#export RAYON_NUM_THREADS=1
#export TOKIO_WORKER_THREADS=1
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

#It's visible with block 20727641 
ROUND1=`echo {20727640..20727650}`



CANCUN=19426587
TIP=`cast block-number --rpc-url $RPC`
STATICTIP=20721266
NUMRANDOMBLOCKS=100
RANDOMBLOCKS=`shuf --input-range=$CANCUN-$TIP -n $NUMRANDOMBLOCKS | sort`

GITHASH=`git rev-parse --short HEAD`
echo "Testing against mainnet, current revision: $GITHASH."

#BLOCKS="$CANCUNBLOCKS $RANDOMBLOCKS"
BLOCKS="$ROUND1"
#BLOCKS="$CANCUNBLOCKS"
echo "Testing blocks: $BLOCKS"

echo "Testing:  $BLOCKS"
printf "githash       block verdict duration\n" | tee -a witnesses/native_results.txt
echo   "------------------------------------"   | tee -a witnesses/native_results.txt

for BLOCK in $BLOCKS; do
  GITHASH=`git rev-parse --short HEAD`
  WITNESS="witnesses/$BLOCK.native.$GITHASH.witness.json"
  echo "Fetching block $BLOCK"
  export RUST_LOG=rpc=trace
  cargo run --quiet --release --bin rpc -- --backoff 3000 --max-retries 100 --rpc-url $RPC --rpc-type native fetch --start-block $BLOCK --end-block $BLOCK 1> $WITNESS
  echo "Testing blocks: $BLOCKS."
  echo "Now testing block $BLOCK .."
  export RUST_LOG=info
  SECONDS=0
  timeout 30m ./prove_stdio.sh $WITNESS test_only
  EXITCODE=$?
  DURATION=`date -u -d @"$SECONDS" +'%-Hh%-Mm%-Ss'`
  echo $DURATION
  if [ $EXITCODE -eq 0 ]
  then
    VERDICT="success"
  else
    VERDICT="failure"
  fi
  printf "%s %10i %s %s\n" $GITHASH $BLOCK $VERDICT $DURATION | tee -a witnesses/native_results.txt
done
