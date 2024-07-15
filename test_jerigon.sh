#!/usr/bin/env bash

set -euxo pipefail

#export CARGO_LOG=cargo::core::compiler::fingerprint=debug
export RPC=
if [ -z $RPC ]; then
  # You must set an RPC endpoint
  exit 1
fi
mkdir -p witnesses

export RAYON_NUM_THREADS=4
export TOKIO_WORKER_THREADS=4
export RUST_BACKTRACE=full
export RUST_LOG=info
export 'RUSTFLAGS=-C target-cpu=native -Zlinker-features=-lld'
export RUST_MIN_STACK=33554432

GITHASH=`git rev-parse --short HEAD`
echo "Testing against jergion, current revision: $GITHASH."

TESTNETBLOCKS="
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
"


KNOWNFAILED="
28
444
"



# 470..663 from Robin
for i in {470..663}
do
  ROBIN+=" $i"
done

# Pick random blocks
for i in {1..10}
do
  RANDOMBLOCKS+=" $((1 + $RANDOM % 688))"
done

# TESTNETBLOCKS="$KNOWNFAILED $ROBIN $RANDOMBLOCKS $TESTNETBLOCKS"
TESTNETBLOCKS="$ROBIN $RANDOMBLOCKS $TESTNETBLOCKS"

TESTNETBLOCKS=`echo $TESTNETBLOCKS | sed 's/\s/\n/g'`
SHUF=`shuf -e $TESTNETBLOCKS` 
echo $SHUF



for BLOCK in $TESTNETBLOCKS; do
  GITHASH=`git rev-parse --short HEAD`
  WITNESS="$witnesses/$BLOCK.jerigon.$GITHASH.witness.json"
  echo "Fetching block $BLOCK"
  cargo run --release --bin rpc -- --backoff 3000 --max-retries 100 --rpc-url $RPC --rpc-type jerigon fetch --start-block $BLOCK --end-block $BLOCK 1> $WITNESS
  echo "Checking block $BLOCK"
  zero_bin/tools/prove_stdio.sh $WITNESS test_only
  EXITCODE=$?
  if [ -n $EXITCODE ]
  then
    RESULT="success"
  else
    RESULT="failure"
  fi
  printf "%10i %s %s\n" $BLOCK $GITHASH $RESULT | tee -a result.txt
done

exit 0
